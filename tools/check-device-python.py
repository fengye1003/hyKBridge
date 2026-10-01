#!/usr/bin/env python3
"""Sanity-check the device-side scripts before they are copied to a Kindle.

Why this exists: this package's pulse loop is the one file that runs unattended on a
device we cannot easily debug, and the failure modes are silent -- on 2026-10-01 a
function was renamed and a stale call site survived, so the loop died with
`NameError: name 'maybe_suspend' is not defined` only *after* it had been deployed.
`ast.parse` alone would not catch that: it is not a syntax error.

So: parse it, then flag every call to a name that is never defined anywhere in the
module (and is not a builtin) -- the exact shape of a stale rename.

Usage:  python tools/check-device-python.py [file-or-dir ...]
        (no arguments = scan ../device next to this script)
Exit:   0 clean, 1 problems found
"""
import ast
import builtins
import os
import sys

ASCII_MARK = {'ok': '[OK]', 'ng': '[NG]'}


def check(path):
    with open(path, 'rb') as fh:
        raw = fh.read()
    problems = []

    # 1) a no-BOM UTF-8 file is what the device expects; a BOM breaks shebangs
    if raw.startswith(b'\xef\xbb\xbf'):
        problems.append('file starts with a UTF-8 BOM')
    # 2) CRLF in a shell script breaks on the device; for .py it is ugly but legal,
    #    so only warn for shell scripts
    if path.endswith('.sh') and b'\r\n' in raw:
        problems.append('shell script has CRLF line endings')
    # 3) non-ASCII in a shell script that runs in a do-not-care locale
    if path.endswith('.sh'):
        bad = [(i + 1, l) for i, l in enumerate(raw.split(b'\n')) if any(b > 127 for b in l)]
        for lineno, line in bad[:3]:
            problems.append('line %d is non-ASCII: %r' % (lineno, line[:60]))

    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        problems.append('not valid UTF-8: %s' % exc)
        return problems

    if not path.endswith('.py'):
        return problems  # shell scripts: the byte-level checks above are the whole story

    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        problems.append('SyntaxError line %s: %s' % (exc.lineno, exc.msg))
        return problems

    defined = set(dir(builtins))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defined.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            defined.add(node.id)
        elif isinstance(node, ast.arg):
            defined.add(node.arg)
        elif isinstance(node, ast.alias):
            defined.add((node.asname or node.name).split('.')[0])
        elif isinstance(node, ast.ExceptHandler) and node.name:
            defined.add(node.name)
        elif isinstance(node, ast.Global):
            defined.update(node.names)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id not in defined:
                problems.append('line %d: call to undefined name %r (stale rename?)'
                                % (node.lineno, node.func.id))
    return problems


def main(argv):
    # Default: scan the device tree next to this script's repo (works from any cwd).
    here = os.path.dirname(os.path.abspath(__file__))
    targets = argv or [os.path.join(os.path.dirname(here), 'device')]

    files = []
    for t in targets:
        if os.path.isdir(t):
            for root, dirs, names in os.walk(t):
                dirs[:] = [d for d in dirs if d not in ('state', '__pycache__')]
                files += [os.path.join(root, n) for n in sorted(names)
                          if n.endswith(('.py', '.sh'))]
        else:
            files.append(t)

    if not files:
        print('[NG] nothing to check (looked at: %s)' % ', '.join(targets))
        return 1

    rc = 0
    for path in files:
        problems = check(path)
        if problems:
            rc = 1
            print('%s %s' % (ASCII_MARK['ng'], path))
            for p in problems:
                print('     - %s' % p)
        else:
            print('%s %s' % (ASCII_MARK['ok'], path))
    print('[i] %d file(s) checked, %s' % (len(files), 'clean' if rc == 0 else 'PROBLEMS FOUND'))
    return rc


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
