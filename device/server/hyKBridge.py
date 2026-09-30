#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
hyKBridge.py -- Kindle hyKBridge 服务端（纯标准库，Python 3.9 可用）

做什么：在 Kindle 上起一个局域网 HTTP 服务，让电脑/手机能远程
        ① 执行命令  ② 管理 KUAL 插件  ③ 浏览书目文件  ④ 看设备状态

设计红线（对应需求里的「不得直接修改系统和任何敏感文件」）：
  * 所有文件操作**限定在 /mnt/us 之内**（realpath 前缀校验，挡穿越与软链逃逸）；
  * 命令执行**默认带系统路径写操作拦网**（mntroot/mount/reboot/写 /etc /var/local… 一律拒），
    要放开必须显式把 state/config.json 的 allow_system 改成 true —— 默认 false；
  * 全站强制 Token 鉴权（除 /__ping 静态探针），失败 5 次锁 10 分钟；
  * 日志**只记请求行与返回码**，绝不记录 Token、不记录命令输出内容。

启动：python3 hyKBridge.py            （读同目录上一级的 state/config.json）
      --port 8090 --bind 0.0.0.0 --root /mnt/us --state /mnt/us/extensions/hyKBridge/state
"""
from __future__ import print_function

import argparse
import errno
import hashlib
import hmac
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
import zipfile

try:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlparse, parse_qs, unquote
except ImportError:                                   # pragma: no cover
    from BaseHTTPServer import BaseHTTPRequestHandler
    from SocketServer import ThreadingHTTPServer
    from urlparse import urlparse, parse_qs
    from urllib import unquote

VERSION = '0.1.0'
COPYRIGHT = ('== HyKBridge by HYrecovery & HoshinoSumi from teko.IO SisTemS! ==\n'
             '== Under MIT Open Source License ==')
APPNAME = 'hyKBridge'

# 允许工作的根目录。默认写死 /mnt/us。
# 只有「启动这个进程的人」（Kindle 上就是 KUAL 的 root）能通过环境变量改，
# 刻意不做成命令行参数 —— 少一个被误传/被滥用的入口。
# 本地自测时设 KWS_ROOT 到一个假树即可，逻辑完全同一条代码路径。
ALLOWED_ROOT = os.environ.get('KWS_ROOT') or '/mnt/us'

# 默认端口：避开 80（filebrowser）
DEFAULT_PORT = 8090

# 命令拦网：这些"动词"一旦出现就直接拒绝（大小写不敏感，按词边界匹配）
DENY_VERBS = [
    'mntroot', 'mount', 'umount', 'reboot', 'halt', 'poweroff', 'shutdown',
    'insmod', 'rmmod', 'modprobe', 'mkfs', 'fdisk', 'mke2fs', 'fsck',
    'chroot', 'pivot_root', 'sysctl', 'iptables', 'ip6tables', 'init',
]
# 受保护路径：只要命令里同时出现「受保护路径」和「写动作」，就拒绝
PROTECTED_PATHS = ['/etc', '/var/local', '/var', '/opt', '/usr', '/bin', '/sbin',
                   '/lib', '/dev', '/proc', '/sys', '/mnt/us/../..']
# 写动作的判据（踩了三轮才收敛，别改回去）：
#  ① 重定向符 `>` —— 子串找即可
#  ② 写动词 —— **必须是"某个命令段的第一个词"**，不能全串搜。
#     真机上误伤过三次，全是"写动词出现在别处"：
#       a) `.../bookfere-tools/bin/fix-cover/x.py` 被 `/bin` 子串命中（路径边界已修）
#       b) `cat .../rtc0/wakealarm` 被 "wakeal**arm **" 里的 `rm ` 命中
#       c) `ps aux | grep "[a]rm-and-watch"` 被 `]rm-` 的词边界命中
#     ⇒ 按 `; & |` 切成命令段，只认"段首是写动词"。这样
#       `rm -rf /bin`（段首 rm）拦得住，而 `grep "[a]rm-and-watch"` 放行。
WRITE_VERBS = ['rm', 'mv', 'cp', 'dd', 'tee', 'mkdir', 'touch', 'chmod', 'chown',
               'truncate', 'install', 'rmdir', 'link', 'ln']
# 这些"设备"不算受保护路径的写操作（黑洞/标准流）
DEV_SAFE = ['/dev/null', '/dev/zero', '/dev/stdout', '/dev/stderr']


def _segments(cmd):
    return [s.strip() for s in re.split(r'[;&|]+', cmd) if s.strip()]


def has_write_action(text):
    """这段命令里有没有'真正写文件'的动作（重定向，或段首写动词）。"""
    if '>' in text:
        return True
    for seg in _segments(text):
        first = seg.split()[0] if seg.split() else ''
        if first in WRITE_VERBS:
            return True
        # `sed -i ...` / `ln -s ...` 这类"动词 + 选项"也算
        if first in ('sed',) and re.search(r'(^|\s)-i(\s|$)', seg):
            return True
    return False


MAX_EXEC_OUT = 40000          # 单次命令输出上限（字符）
AUTH_FAIL_LIMIT = 5
AUTH_LOCK_SECONDS = 600

STATE = {'lock': threading.Lock(), 'fails': {}, 'started': time.time(),
         'requests': 0, 'execs': 0}


# ────────────────────────────────────────────────────────────────
# 小工具
# ────────────────────────────────────────────────────────────────
def sha12(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()[:12]


def within_root(path):
    """chroot 语义的路径归一化：API 里的 "/" 就等于 ALLOWED_ROOT。

      '/documents'        -> <root>/documents     （友好写法）
      '<root>/documents'  -> 原样                  （完整写法）
      '/../../etc/passwd' -> 归一化后落在 root 外 -> 拒绝
    """
    if not path:
        return False, None
    root = os.path.realpath(ALLOWED_ROOT)
    p = path
    if not (os.path.isabs(p) and (p == root or p.startswith(root.rstrip('/') + os.sep))):
        # 不是"已经落在 root 下的绝对路径" -> 一律当成 root 内的相对路径
        p = os.path.join(root, p.lstrip('/'))
    p = os.path.normpath(p)
    rp = os.path.realpath(p)
    if rp == root or rp.startswith(root + os.sep):
        return True, rp
    return False, rp


def human(n):
    for unit in ('B', 'K', 'M', 'G'):
        if n < 1024 or unit == 'G':
            return ('%d%s' % (n, unit)) if unit == 'B' else ('%.1f%s' % (n, unit))
        n /= 1024.0


def local_ips():
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return sorted(i for i in ips if not i.startswith('127.'))


def eips(row, text):
    """往 Kindle 屏幕上打一行状态（e-ink 没有终端可看）。失败就算了。"""
    try:
        subprocess.call(['eips', '2', str(row), text])
    except Exception:
        pass


# ────────────────────────────────────────────────────────────────
# 配对（bootstrap）
# ────────────────────────────────────────────────────────────────
DEVICE_NAME = os.environ.get('HYKBRIDGE_DEVICE_NAME') or 'kindle'
PAIR_MAX_ATTEMPTS = 5
PAIR_TTL_SECONDS = 300


def _sf(name):
    base = STATE_DIR or os.path.join(ALLOWED_ROOT, 'extensions', 'hyKBridge', 'state')
    return os.path.join(base, name)


def pair_window():
    try:
        with open(_sf('pair.json'), 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def clear_pair_window():
    try:
        os.remove(_sf('pair.json'))
    except OSError:
        pass


def load_paired():
    try:
        with open(_sf('paired.json'), 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def save_paired(p):
    tmp = _sf('paired.json.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(p, f, indent=1, ensure_ascii=True)
    if os.path.exists(_sf('paired.json')):
        os.remove(_sf('paired.json'))
    os.rename(tmp, _sf('paired.json'))


POWERD_PROP = 'com.lab126.powerd'
POWERD_NAME = 'preventScreenSaver'


def keep_awake_flag():
    return os.path.join(STATE_DIR or '.', 'keep-awake')


def keep_awake_state():
    """读 preventScreenSaver 的当前值（只读调用，不改任何东西）。"""
    try:
        out = subprocess.check_output(['lipc-get-prop', POWERD_PROP, POWERD_NAME],
                                      stderr=subprocess.STDOUT, timeout=10)
        val = out.decode('utf-8', 'replace').strip()
    except Exception as e:
        val = 'error: %s' % e
    return {'flag': os.path.exists(keep_awake_flag()), 'powerd': val}


def keep_awake_set(on):
    """打开/关闭"不休眠"。这是运行时 lipc 属性：不写系统分区文件、重启即失效。"""
    flag = keep_awake_flag()
    try:
        if on:
            with open(flag, 'w') as f:
                f.write('1\n')
        elif os.path.exists(flag):
            os.remove(flag)
        subprocess.call(['lipc-set-prop', POWERD_PROP, POWERD_NAME, '1' if on else '0'])
    except Exception as e:
        return False, 'failed: %s' % e
    st = keep_awake_state()
    if str(st['powerd']).strip() != ('1' if on else '0'):
        return False, 'lipc-set-prop did not take effect (powerd=%s)' % st['powerd']
    return True, 'keep-awake %s' % ('ON' if on else 'OFF')


# ────────────────────────────────────────────────────────────────
# 鉴权
# ────────────────────────────────────────────────────────────────
class Auth(object):
    def __init__(self, token):
        self.token = token or ''
        self.fp = sha12(self.token) if self.token else 'none'
        self.fails = {}
        self.lock = threading.Lock()

    def locked(self, ip):
        with self.lock:
            rec = self.fails.get(ip)
            if not rec:
                return 0
            cnt, last = rec
            if cnt >= AUTH_FAIL_LIMIT:
                left = AUTH_LOCK_SECONDS - (time.time() - last)
                if left > 0:
                    return int(left)
                del self.fails[ip]
            return 0

    def fail(self, ip):
        with self.lock:
            cnt, _ = self.fails.get(ip, (0, 0))
            self.fails[ip] = (cnt + 1, time.time())

    def ok(self, presented):
        if not self.token or not presented:
            return False
        return hmac.compare_digest(str(presented), self.token)


# ────────────────────────────────────────────────────────────────
# 命令拦网
# ────────────────────────────────────────────────────────────────
def command_guard(cmd, allow_system):
    """返回 None 表示放行，否则返回拒绝原因。这是"防手滑"的拦网，不是安全沙箱。"""
    if allow_system:
        return None
    low = ' ' + cmd.lower() + ' '
    for verb in DENY_VERBS:
        if re.search(r'(^|[\s;|&(])%s(\s|$)' % re.escape(verb), low):
            return 'blocked verb: %s (system operation; set allow_system=true to lift)' % verb
    # ★ 顺序很讲究：**先**抹掉"不是写文件"的重定向噪声，**再**按 `; & |` 切段。
    #   反过来的话 `2>&1` 里的 `&` 会把命令切成两段、留下一个裸的 `2>` ⇒ 误判成写动作。
    #   `2>&1` / `>&2` -> 真机误报过 `ls -la /usr/bin/x 2>&1`
    #   `>/dev/null`   -> 最常见的黑洞重定向
    cleaned = re.sub(r'\d?>>?\s*&\s*\d', ' ', cmd)
    cleaned = re.sub(r'\d?>>?\s*/dev/(null|zero|stdout|stderr)', ' ', cleaned)
    # ★ 再逐"命令段"判定，而不是整条串里"同时出现"就算 —— `rm -f /mnt/us/x; cat /etc/hosts`
    #   曾被判成"写 /etc"（真机踩过）。同一段里既有受保护路径、又有写动作，才拒。
    for seg in _segments(cleaned):
        scrubbed = seg
        for safe in DEV_SAFE:
            scrubbed = scrubbed.replace(safe, ' ')
        if not has_write_action(scrubbed):
            continue
        for p in PROTECTED_PATHS:
            # ★ 必须在"路径边界"上匹配，不能子串匹配 —— 真机上误伤过一次：
            #   `.../bookfere-tools/bin/fix-cover/x.py` 里的 `.../bin/...` 被命中。
            # 边界 = 前面是行首/空白/引号/括号/等号/冒号，后面是 / 或分隔符或结尾。
            pat = r"(?:^|[\s'\"=(:])%s(?:/|[\s'\"),;|&]|$)" % re.escape(p)
            if re.search(pat, scrubbed):
                return 'blocked write to protected path: %s' % p
    if re.search(r'\brm\s+(-[a-zA-Z]*\s+)*/(\s|$)', cmd):
        return 'blocked: rm on /'
    return None


def run_cmd(cmd, cwd, timeout, allow_system):
    reason = command_guard(cmd, allow_system)
    if reason:
        return {'rc': 126, 'stdout': '', 'stderr': reason + '\n', 'blocked': True}
    if not cwd:
        cwd = ALLOWED_ROOT
    ok, real = within_root(cwd)
    if not ok or not os.path.isdir(real):
        return {'rc': 126, 'stdout': '', 'stderr': 'cwd outside /mnt/us\n', 'blocked': True}
    try:
        p = subprocess.Popen(cmd, shell=True, cwd=real,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            out, err = p.communicate()
            return {'rc': 124, 'stdout': _dec(out), 'stderr': _dec(err) + '\n[timeout after %ss]' % timeout}
        return {'rc': p.returncode, 'stdout': _dec(out), 'stderr': _dec(err)}
    except Exception as e:
        return {'rc': 125, 'stdout': '', 'stderr': 'exec failed: %s\n' % e}


def _dec(b):
    if b is None:
        return ''
    if isinstance(b, str):
        s = b
    else:
        s = b.decode('utf-8', 'replace')
    if len(s) > MAX_EXEC_OUT:
        s = s[:MAX_EXEC_OUT] + '\n...[truncated at %d chars]' % MAX_EXEC_OUT
    return s


# ────────────────────────────────────────────────────────────────
# 插件（KUAL extension）管理
# ────────────────────────────────────────────────────────────────
EXT_DIR = os.path.join(ALLOWED_ROOT, 'extensions')
DISABLED_SUFFIX = '.disabled'


def ext_path(name):
    """插件目录必须是 extensions/ 下的直接子目录，名字不含 / 与 .."""
    if not name or '/' in name or '\\' in name or name in ('.', '..'):
        return None
    p = os.path.join(EXT_DIR, name)
    return p if os.path.isdir(p) else None


def ext_list():
    out = []
    if not os.path.isdir(EXT_DIR):
        return out
    for name in sorted(os.listdir(EXT_DIR)):
        p = os.path.join(EXT_DIR, name)
        if not os.path.isdir(p):
            continue
        cfg = os.path.join(p, 'config.xml')
        cfg_off = cfg + DISABLED_SUFFIX
        menu = os.path.join(p, 'menu.json')
        try:
            mtime = time.strftime('%Y-%m-%d %H:%M', time.localtime(os.path.getmtime(p)))
        except OSError:
            mtime = '?'
        size = 0
        for root, _d, files in os.walk(p):
            for fn in files:
                try:
                    size += os.path.getsize(os.path.join(root, fn))
                except OSError:
                    pass
        info = {'name': name, 'enabled': os.path.exists(cfg),
                'disabled_marker': os.path.exists(cfg_off),
                'has_menu': os.path.exists(menu), 'mtime': mtime, 'bytes': size}
        try:
            with open(menu, 'r', encoding='utf-8', errors='replace') as f:
                data = json.load(f)
            items = data.get('items', [])
            info['menu_items'] = len(items)
        except Exception:
            info['menu_items'] = None
        if os.path.exists(cfg):
            try:
                with open(cfg, 'r', encoding='utf-8', errors='replace') as f:
                    head = f.read(1200)
                m = re.search(r'<name>(.*?)</name>', head, re.S)
                v = re.search(r'<version>(.*?)</version>', head, re.S)
                info['title'] = m.group(1).strip() if m else None
                info['version'] = v.group(1).strip() if v else None
            except Exception:
                pass
        out.append(info)
    return out


def ext_toggle(name, enable):
    """启用/禁用：KUAL 靠 config.xml 发现插件，所以把它改名即可（完全可逆）。"""
    p = ext_path(name)
    if not p:
        return False, 'no such extension'
    cfg = os.path.join(p, 'config.xml')
    off = cfg + DISABLED_SUFFIX
    if enable:
        if os.path.exists(cfg):
            return True, 'already enabled'
        if not os.path.exists(off):
            return False, 'no config.xml or config.xml.disabled found'
        os.rename(off, cfg)
        return True, 'enabled'
    else:
        if os.path.exists(off) and not os.path.exists(cfg):
            return True, 'already disabled'
        if not os.path.exists(cfg):
            return False, 'no config.xml'
        os.rename(cfg, off)
        return True, 'disabled'


def ext_backup(name, backups_dir):
    p = ext_path(name)
    if not p:
        return False, 'no such extension', None
    if not os.path.isdir(backups_dir):
        os.makedirs(backups_dir)
    stamp = time.strftime('%Y%m%d-%H%M%S')
    dest = os.path.join(backups_dir, '%s-%s.zip' % (name, stamp))
    with zipfile.ZipFile(dest, 'w', zipfile.ZIP_DEFLATED) as z:
        for root, _d, files in os.walk(p):
            for fn in files:
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, p)
                z.write(full, os.path.join(name, rel))
    return True, 'backed up', dest


def ext_install_from_zip(zip_path, target_name):
    """安全解压：拒绝绝对路径与 .. 逃逸（zip-slip），且必须落在 extensions/<name> 下。"""
    dest = os.path.join(EXT_DIR, target_name)
    if not within_root(dest)[0]:
        return False, 'bad target'
    if not os.path.isdir(dest):
        os.makedirs(dest)
    dest_real = os.path.realpath(dest)
    n = 0
    with zipfile.ZipFile(zip_path) as z:
        for member in z.namelist():
            if member.endswith('/'):
                continue
            rel = member.lstrip('/')
            parts = [p for p in rel.split('/') if p not in ('', '.', '..')]
            if not parts:
                continue
            # 若压缩包自带顶层同名目录，去掉一层
            if parts[0] == target_name and len(parts) > 1:
                parts = parts[1:]
            out = os.path.join(dest_real, *parts)
            if not os.path.realpath(out).startswith(dest_real + os.sep):
                return False, 'zip-slip blocked: %s' % member
            d = os.path.dirname(out)
            if not os.path.isdir(d):
                os.makedirs(d)
            with z.open(member) as src, open(out, 'wb') as dst:
                shutil.copyfileobj(src, dst)
            n += 1
    return True, 'installed %d files' % n


# ────────────────────────────────────────────────────────────────
# 书目
# ────────────────────────────────────────────────────────────────
BOOK_EXT = ('.mobi', '.azw', '.azw3', '.azw4', '.prc', '.pobi', '.epub',
            '.kfx', '.pdf', '.txt', '.kfx-zip')
THUMB_DIR = os.path.join(ALLOWED_ROOT, 'system', 'thumbnails')
DAMAGED_SIZE = 2000


def books_summary(limit=400):
    docs = os.path.join(ALLOWED_ROOT, 'documents')
    out = {'dir': docs, 'files': 0, 'bytes': 0, 'sdr': 0, 'dir_folders': 0,
           'by_ext': {}, 'thumbs': 0, 'thumbs_damaged': 0, 'items': []}
    if os.path.isdir(docs):
        for name in sorted(os.listdir(docs)):
            full = os.path.join(docs, name)
            if os.path.isdir(full):
                if name.endswith('.sdr'):
                    out['sdr'] += 1
                elif name.endswith('.dir'):
                    out['dir_folders'] += 1
                continue
            try:
                sz = os.path.getsize(full)
            except OSError:
                continue
            ext = os.path.splitext(name)[1].lower()
            if ext in BOOK_EXT:
                out['files'] += 1
                out['bytes'] += sz
                out['by_ext'][ext] = out['by_ext'].get(ext, 0) + 1
                if len(out['items']) < limit:
                    out['items'].append({'name': name, 'bytes': sz,
                                         'mtime': time.strftime('%Y-%m-%d %H:%M',
                                                                time.localtime(os.path.getmtime(full)))})
    if os.path.isdir(THUMB_DIR):
        for name in os.listdir(THUMB_DIR):
            if not name.lower().endswith('.jpg'):
                continue
            out['thumbs'] += 1
            try:
                if os.path.getsize(os.path.join(THUMB_DIR, name)) < DAMAGED_SIZE:
                    out['thumbs_damaged'] += 1
            except OSError:
                pass
    return out


# ────────────────────────────────────────────────────────────────
# HTTP
# ────────────────────────────────────────────────────────────────
CONFIG = {}
AUTH = None
LOG_PATH = None
STATE_DIR = None


def log_line(text):
    try:
        with open(LOG_PATH, 'a', encoding='utf-8') as f:
            f.write('%s %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), text))
    except Exception:
        pass


PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kindle hyKBridge</title>
<style>
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:14px;background:#111;color:#eee}
h1{font-size:17px;margin:0 0 10px} .c{background:#1c1c1c;border:1px solid #333;border-radius:8px;padding:10px;margin-bottom:10px}
input,button,textarea{font:inherit;background:#222;color:#eee;border:1px solid #444;border-radius:6px;padding:7px}
input{width:100%;box-sizing:border-box} button{cursor:pointer}
pre{white-space:pre-wrap;word-break:break-all;background:#0a0a0a;border:1px solid #333;border-radius:6px;padding:8px;max-height:44vh;overflow:auto;font-size:12px}
.k{color:#8bd} .w{color:#fc6} .g{color:#7d7} .r{color:#f77}
.row{display:flex;gap:8px;margin-top:8px} .row button{flex:1}
</style></head><body>
<h1>Kindle hyKBridge <span class="k" id="v"></span></h1>
<div class="c"><b>Token</b> <input id="tk" type="password" placeholder="粘贴 state/token.txt 里的口令">
<div class="row"><button onclick="save()">保存并连接</button><button onclick="st()">设备状态</button></div>
<div id="auth" class="w"></div></div>
<div class="c"><b>执行命令</b> <input id="cmd" value="ls -la /mnt/us/extensions">
<div class="row"><button onclick="ex()">运行</button><button onclick="ex('df -h /mnt/us')">磁盘</button></div></div>
<div class="c"><b>插件</b> <div class="row"><button onclick="ext()">列出</button></div><div id="exts"></div></div>
<div class="c"><b>书目</b> <div class="row"><button onclick="bk()">统计</button></div></div>
<pre id="o">就绪。先粘贴 Token 再点「保存并连接」。</pre>
<script>
const $=s=>document.querySelector(s); let TK=localStorage.getItem('kws')||'';
$('#tk').value=TK;
function save(){TK=$('#tk').value.trim();localStorage.setItem('kws',TK);$('#auth').textContent='已保存，正在自检…';st();}
function hdr(){return {'X-Auth':TK,'Content-Type':'application/json'};}
function out(t,cls){$('#o').innerHTML=(cls?'<span class="'+cls+'">':'')+t+(cls?'</span>':'');}
async function api(p,body){const r=await fetch(p,{method:body?'POST':'GET',headers:hdr(),body:body?JSON.stringify(body):undefined});
 const j=await r.json().catch(()=>({error:'bad json'}));if(r.status===401){out('鉴权失败：Token 不对（或该 IP 已被临时锁定）','r');throw 0;}return j;}
async function st(){try{const j=await api('/api/status');out(JSON.stringify(j,null,1));$('#v').textContent='v'+j.version;$('#auth').innerHTML='<span class="g">已连接 '+j.ips.join(', ')+'</span>';}catch(e){}}
async function ex(c){try{const j=await api('/api/exec',{cmd:c||$('#cmd').value});out('rc='+j.rc+'\n'+j.stdout+(j.stderr?'\n[stderr]\n'+j.stderr:''));}catch(e){}}
async function ext(){try{const j=await api('/api/ext');let h='<pre>';for(const e of j.items){h+=(e.enabled?'<span class="g">[on] </span>':'<span class="r">[off]</span>')+' '+e.name.padEnd(16)+' '+e.mtime+'  '+(e.menu_items===null?'?':e.menu_items+' 项')+'\n';}h+='</pre>';$('#exts').innerHTML=h;out('共 '+j.items.length+' 个插件');}catch(e){}}
async function bk(){try{const j=await api('/api/books');out('书目 '+j.files+' 个 / '+j.bytes+' 字节\n缩略图 '+j.thumbs+' 张，其中损坏 '+j.thumbs_damaged+' 张\n.sdr '+j.sdr+' 个\n'+JSON.stringify(j.by_ext,null,1));}catch(e){}}
<div style="text-align:center;color:#666;font-size:11px;margin-top:14px;line-height:1.5">== HyKBridge by HYrecovery &amp; HoshinoSumi from teko.IO SisTemS! ==<br>== Under MIT Open Source License ==</div>
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = 'hyKBridge/' + VERSION
    protocol_version = 'HTTP/1.1'
    timeout = 60

    # 安静：自己写访问日志（标准日志会打到 stderr，KUAL 里看不到）
    def log_message(self, fmt, *args):
        pass

    # ── 响应助手 ──────────────────────────────────────────────
    def _send(self, code, body, ctype='application/json; charset=utf-8', extra=None):
        if isinstance(body, str):
            body = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False, indent=1))

    def _err(self, code, msg):
        # 走错误路径时请求体可能没被读完（例如鉴权失败、只读拒绝都发生在读 body 之前）。
        # HTTP/1.1 keep-alive 下残留字节会污染下一个请求，所以出错一律关连接。
        self.close_connection = True
        self._json({'ok': False, 'error': msg}, code)

    def _client(self):
        return self.client_address[0]

    def _token_from(self, q):
        t = self.headers.get('X-Auth')
        if t:
            return t
        if q.get('k'):
            return q['k'][0]
        ck = self.headers.get('Cookie') or ''
        m = re.search(r'kws=([^;]+)', ck)
        return m.group(1) if m else ''

    def _need_auth(self, q):
        ip = self._client()
        left = AUTH.locked(ip)
        if left:
            self._err(429, 'too many failures, locked for %ds' % left)
            log_line('LOCKED %s' % ip)
            return False
        if not AUTH.ok(self._token_from(q)):
            AUTH.fail(ip)
            self._err(401, 'unauthorized')
            log_line('401 %s %s' % (ip, self.path.split('?')[0]))
            return False
        return True

    def _body(self):
        # 兼容 chunked：Node 的 http.request 在没有 Content-Length 时默认走 chunked，
        # 只认 Content-Length 的服务器会把请求体读成空（实测过一次：400 empty cmd）。
        te = (self.headers.get('Transfer-Encoding') or '').lower()
        if 'chunked' in te:
            return self._read_chunked()
        try:
            n = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            n = 0
        if n <= 0:
            return b''
        return self.rfile.read(n)

    def _read_chunked(self, cap=64 * 1024 * 1024):
        out = bytearray()
        while True:
            line = self.rfile.readline(128)
            if not line:
                break
            try:
                size = int(line.strip().split(b';')[0] or b'0', 16)
            except ValueError:
                break
            if size == 0:
                self.rfile.readline(128)          # 收尾 CRLF
                break
            if len(out) + size > cap:
                break
            out += self.rfile.read(size)
            self.rfile.readline(128)              # chunk 末尾 CRLF
        return bytes(out)

    def _body_json(self):
        raw = self._body()
        if not raw:
            return {}
        try:
            return json.loads(raw.decode('utf-8'))
        except Exception:
            return {}

    # ── GET ──────────────────────────────────────────────────
    def do_GET(self):
        STATE['requests'] += 1
        u = urlparse(self.path)
        q = parse_qs(u.query)
        path = unquote(u.path)

        if path == '/__ping':
            return self._json({'ok': True, 'app': APPNAME, 'v': VERSION})
        if path in ('/', '/index.html'):
            return self._send(200, PAGE, 'text/html; charset=utf-8')

        if not self._need_auth(q):
            return
        try:
            if path == '/api/status':
                return self._json(self.api_status())
            if path == '/api/keepawake':
                return self._json(dict({'ok': True}, **keep_awake_state()))
            if path == '/api/ext':
                return self._json({'ok': True, 'items': ext_list()})
            if path == '/api/books':
                return self._json(dict({'ok': True}, **books_summary()))
            if path == '/api/ls':
                return self.api_ls(q)
            if path == '/api/get':
                return self.api_get(q)
            if path == '/api/read':
                return self.api_read(q)
            return self._err(404, 'no such endpoint')
        except Exception as e:
            log_line('ERR %s %s: %s' % (self._client(), path, e))
            return self._err(500, 'internal error: %s' % e)

    # ── POST ─────────────────────────────────────────────────
    def do_POST(self):
        STATE['requests'] += 1
        u = urlparse(self.path)
        q = parse_qs(u.query)
        path = unquote(u.path)

        # /api/pair is the BOOTSTRAP: it must run BEFORE token auth, because the
        # whole point is that the host does not have a token yet. What protects it:
        #   * the 6-digit code, which only exists while the user is looking at the
        #     device screen (KUAL -> "Show Pairing Code"),
        #   * single use + short TTL + max 5 attempts + constant-time compare,
        #   * it only works from the LAN.
        # On success we also record the CALLER'S IP: that is how the device later
        # knows where its host lives (the host never has to be configured by hand).
        if path == '/api/pair':
            return self.api_pair()

        if not self._need_auth(q):
            return
        try:
            if path == '/api/exec':
                return self.api_exec()
            if path == '/api/keepawake':
                return self.api_keepawake()
            if path == '/api/sleep':
                return self.api_sleep()
            if path == '/api/put':
                return self.api_put(q)
            if path == '/api/mkdir':
                return self.api_mkdir()
            if path == '/api/mv':
                return self.api_mv()
            if path == '/api/rm':
                return self.api_rm()
            if path == '/api/ext/toggle':
                return self.api_ext_toggle()
            if path == '/api/ext/backup':
                return self.api_ext_backup()
            if path == '/api/ext/install':
                return self.api_ext_install(q)
            if path == '/api/backups':
                return self.api_backups()
            return self._err(404, 'no such endpoint')
        except Exception as e:
            log_line('ERR %s %s: %s' % (self._client(), path, e))
            return self._err(500, 'internal error: %s' % e)

    # ── 各 API ───────────────────────────────────────────────
    def api_status(self):
        # shutil.disk_usage 跨平台；os.statvfs 是 Unix 专有（本地一跑就 500）
        try:
            total, used, free = shutil.disk_usage(ALLOWED_ROOT)
        except Exception:
            total = used = free = 0
        return {
            'ok': True, 'app': APPNAME, 'version': VERSION,
            'python': sys.version.split()[0],
            'platform': sys.platform,
            'root': ALLOWED_ROOT, 'cwd': os.getcwd(),
            'pid': os.getpid(),
            'uptime_s': int(time.time() - STATE['started']),
            'ips': local_ips(),
            'port': CONFIG.get('port', DEFAULT_PORT),
            'allow_system': bool(CONFIG.get('allow_system')),
            'read_only': bool(CONFIG.get('read_only')),
            'token_fp': AUTH.fp,
            'disk': {'total': human(total), 'free': human(free),
                     'used_pct': int(100 * (total - free) / total) if total else 0},
            'requests': STATE['requests'], 'execs': STATE['execs'],
            'keep_awake': keep_awake_state(),
            'home_dir': os.path.expanduser('~'),
        }

    def api_ls(self, q):
        p = q.get('path', ['/documents'])[0]
        ok, real = within_root(p)
        if not ok:
            return self._err(403, 'path outside /mnt/us')
        if not os.path.isdir(real):
            return self._err(404, 'not a directory: %s' % real)
        items = []
        try:
            names = sorted(os.listdir(real))
        except OSError as e:
            return self._err(500, str(e))
        for name in names:
            full = os.path.join(real, name)
            try:
                sb = os.lstat(full)
                items.append({'name': name, 'dir': stat.S_ISDIR(sb.st_mode),
                              'bytes': sb.st_size,
                              'mtime': time.strftime('%Y-%m-%d %H:%M', time.localtime(sb.st_mtime))})
            except OSError:
                continue
        return self._json({'ok': True, 'path': real, 'count': len(items), 'items': items})

    def api_read(self, q):
        p = q.get('path', [''])[0]
        ok, real = within_root(p)
        if not ok:
            return self._err(403, 'path outside /mnt/us')
        if not os.path.isfile(real):
            return self._err(404, 'no such file: %s' % real)
        cap = int(q.get('max', ['20000'])[0])
        try:
            with open(real, 'r', encoding='utf-8', errors='replace') as f:
                data = f.read(cap)
        except Exception as e:
            return self._err(500, str(e))
        return self._json({'ok': True, 'path': real, 'bytes': os.path.getsize(real),
                           'truncated': os.path.getsize(real) > cap, 'text': data})

    def api_get(self, q):
        p = q.get('path', [''])[0]
        ok, real = within_root(p)
        if not ok:
            return self._err(403, 'path outside /mnt/us')
        if not os.path.isfile(real):
            return self._err(404, 'no such file: %s' % real)
        try:
            with open(real, 'rb') as f:
                data = f.read()
        except Exception as e:
            return self._err(500, str(e))
        fn = os.path.basename(real).replace('"', '')
        return self._send(200, data, 'application/octet-stream',
                          {'Content-Disposition': 'attachment; filename="%s"' % fn})

    def _write_guard(self):
        if CONFIG.get('read_only'):
            self._err(403, 'server is in read_only mode')
            return False
        return True

    def api_put(self, q):
        if not self._write_guard():
            return
        p = q.get('path', [''])[0]
        ok, real = within_root(p)
        if not ok:
            return self._err(403, 'path outside /mnt/us')
        data = self._body()
        d = os.path.dirname(real)
        if d and not os.path.isdir(d):
            os.makedirs(d)
        tmp = real + '.kws-tmp'
        with open(tmp, 'wb') as f:
            f.write(data)
        if os.path.exists(real):
            os.remove(real)
        os.rename(tmp, real)
        log_line('PUT %s %d bytes' % (real, len(data)))
        return self._json({'ok': True, 'path': real, 'bytes': len(data)})

    def api_mkdir(self):
        if not self._write_guard():
            return
        b = self._body_json()
        ok, real = within_root(b.get('path', ''))
        if not ok:
            return self._err(403, 'path outside /mnt/us')
        if not os.path.isdir(real):
            os.makedirs(real)
        return self._json({'ok': True, 'path': real})

    def api_mv(self):
        if not self._write_guard():
            return
        b = self._body_json()
        ok1, src = within_root(b.get('src', ''))
        ok2, dst = within_root(b.get('dst', ''))
        if not (ok1 and ok2):
            return self._err(403, 'path outside /mnt/us')
        if not os.path.exists(src):
            return self._err(404, 'no such src')
        shutil.move(src, dst)
        log_line('MV %s -> %s' % (src, dst))
        return self._json({'ok': True, 'src': src, 'dst': dst})

    def api_rm(self):
        if not self._write_guard():
            return
        b = self._body_json()
        if not b.get('confirm'):
            return self._err(400, 'need "confirm": true')
        ok, real = within_root(b.get('path', ''))
        if not ok:
            return self._err(403, 'path outside /mnt/us')
        if real.rstrip('/') in (os.path.realpath(ALLOWED_ROOT), EXT_DIR,
                                os.path.join(ALLOWED_ROOT, 'documents')):
            return self._err(403, 'refuse to remove a top-level directory')
        if os.path.isdir(real) and not os.path.islink(real):
            shutil.rmtree(real)
        elif os.path.exists(real):
            os.remove(real)
        else:
            return self._err(404, 'no such path')
        log_line('RM %s' % real)
        return self._json({'ok': True, 'removed': real})

    def api_exec(self):
        if not self._write_guard():
            return
        b = self._body_json()
        cmd = (b.get('cmd') or '').strip()
        if not cmd:
            return self._err(400, 'empty cmd')
        timeout = int(b.get('timeout') or 30)
        timeout = max(1, min(timeout, 300))
        STATE['execs'] += 1
        log_line('EXEC %s | %s' % (self._client(), cmd[:200]))
        r = run_cmd(cmd, b.get('cwd') or ALLOWED_ROOT, timeout, bool(CONFIG.get('allow_system')))
        r['ok'] = True
        r['cmd'] = cmd
        return self._json(r)

    # ── pairing ──────────────────────────────────────────────
    def api_pair(self):
        """6 位单次码换长期令牌。只用局域网可达 + 码在设备屏幕上 + 单次/短 TTL/限次。"""
        b = self._body_json()
        code = str(b.get('code') or '').strip()
        secret = str(b.get('secret') or '')
        name = str(b.get('name') or 'host')[:64]
        ports = b.get('ports') or [8091, 8092]
        caller = self._client()

        if not re.match(r'^\d{6}$', code) or len(secret) < 32:
            return self._err(400, 'code must be 6 digits; secret >= 32 chars')

        st = pair_window()
        if not st:
            return self._err(403, 'no pairing window open -- on the device tap KUAL > hyKBridge > Show Pairing Code')
        if st.get('used'):
            return self._err(403, 'that code was already used')
        if time.time() > st.get('expires', 0):
            clear_pair_window()
            return self._err(403, 'pairing code expired -- tap it again on the device')
        if st.get('attempts', 0) >= PAIR_MAX_ATTEMPTS:
            clear_pair_window()
            return self._err(429, 'too many wrong attempts -- tap Show Pairing Code again')

        want = hashlib.sha256((str(st.get('salt', '')) + code).encode('utf-8')).hexdigest()
        if not hmac.compare_digest(want, str(st.get('hash', ''))):
            st['attempts'] = int(st.get('attempts', 0)) + 1
            with open(_sf('pair.json'), 'w', encoding='utf-8') as f:
                json.dump(st, f)
            log_line('PAIR reject from %s (attempt %d)' % (caller, st['attempts']))
            return self._err(403, 'wrong code')

        device_id = 'kb' + os.urandom(6).hex()
        paired = load_paired()
        paired[device_id] = {'name': name, 'secret': secret, 'host_ip': caller,
                             'ports': ports, 'paired_at': int(time.time())}
        save_paired(paired)
        clear_pair_window()
        log_line('PAIR ok device=%s host=%s name=%s' % (device_id, caller, name))
        eips(3, 'hyKBridge paired with')
        eips(4, caller)
        return self._json({'ok': True, 'device_id': device_id, 'device_name': DEVICE_NAME,
                           'host_ip_seen': caller})

    def api_keepawake(self):
        if not self._write_guard():
            return
        b = self._body_json()
        ok, msg = keep_awake_set(bool(b.get('on')))
        log_line('KEEPAWAKE %s -> %s' % (b.get('on'), msg))
        return self._json(dict({'ok': ok, 'result': msg}, **keep_awake_state()),
                          200 if ok else 400)

    def api_sleep(self):
        """一次性挂起测试：设 RTC 闹钟 -> 验证 -> 挂起 N 秒 -> 自醒。

        先回响应，再由一个 detached 的 sleep-once.sh 去挂起 —— 否则这个 HTTP
        响应永远发不出去（设备已经睡了）。
        """
        if not self._write_guard():
            return
        b = self._body_json()
        try:
            secs = int(b.get('seconds') or 30)
        except (TypeError, ValueError):
            secs = 30
        secs = max(5, min(secs, 3600))
        script = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                              '..', 'bin', 'sleep-once.sh'))
        if not os.path.exists(script):
            return self._err(500, 'sleep-once.sh not found')
        try:
            subprocess.Popen(['sh', script, str(secs)],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
        except Exception as e:
            return self._err(500, 'spawn failed: %s' % e)
        log_line('SLEEP %ss scheduled' % secs)
        return self._json({'ok': True, 'scheduled_sleep_s': secs,
                           'note': 'device suspends in ~2s; reconnect after it wakes'})

    def api_ext_toggle(self):
        if not self._write_guard():
            return
        b = self._body_json()
        name = b.get('name', '')
        ok, msg = ext_toggle(name, bool(b.get('enabled')))
        log_line('EXT %s -> %s (%s)' % (name, b.get('enabled'), msg))
        return self._json({'ok': ok, 'result': msg}, 200 if ok else 400)

    def api_ext_backup(self):
        if not self._write_guard():
            return
        b = self._body_json()
        ok, msg, dest = ext_backup(b.get('name', ''), os.path.join(STATE_DIR, 'backups'))
        log_line('BACKUP %s -> %s' % (b.get('name'), dest))
        return self._json({'ok': ok, 'result': msg, 'file': dest}, 200 if ok else 400)

    def api_ext_install(self, q):
        if not self._write_guard():
            return
        name = q.get('name', [''])[0]
        if not name or not re.match(r'^[A-Za-z0-9._-]+$', name):
            return self._err(400, 'bad extension name')
        data = self._body()
        if not data:
            return self._err(400, 'empty body (send the zip bytes)')
        tmp = os.path.join(STATE_DIR, '_upload.zip')
        with open(tmp, 'wb') as f:
            f.write(data)
        try:
            ok, msg = ext_install_from_zip(tmp, name)
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass
        log_line('INSTALL %s: %s' % (name, msg))
        return self._json({'ok': ok, 'result': msg}, 200 if ok else 400)

    def api_backups(self):
        d = os.path.join(STATE_DIR, 'backups')
        items = []
        if os.path.isdir(d):
            for fn in sorted(os.listdir(d)):
                items.append({'name': fn, 'bytes': os.path.getsize(os.path.join(d, fn))})
        return self._json({'ok': True, 'dir': d, 'items': items})


# ────────────────────────────────────────────────────────────────
# 启动
# ────────────────────────────────────────────────────────────────
def load_config(state_dir, args):
    cfg_path = os.path.join(state_dir, 'config.json')
    cfg = {'port': DEFAULT_PORT, 'bind': '0.0.0.0', 'allow_system': False, 'read_only': False}
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, 'r', encoding='utf-8') as f:
                cfg.update(json.load(f))
        except Exception as e:
            print('[warn] config unreadable (%s), using defaults' % e)
    if args.port:
        cfg['port'] = args.port
    if args.bind:
        cfg['bind'] = args.bind
    return cfg


def load_token(state_dir):
    p = os.path.join(state_dir, 'token.txt')
    if os.path.exists(p):
        with open(p, 'r', encoding='utf-8') as f:
            return f.read().strip()
    tok = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
    with open(p, 'w', encoding='utf-8') as f:
        f.write(tok + '\n')
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return tok


def main():
    global CONFIG, AUTH, LOG_PATH, STATE_DIR
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, default=0)
    ap.add_argument('--bind', default='')
    ap.add_argument('--state', default='/mnt/us/extensions/hyKBridge/state')
    args = ap.parse_args()

    STATE_DIR = args.state
    if not os.path.isdir(STATE_DIR):
        os.makedirs(STATE_DIR)
    LOG_PATH = os.path.join(STATE_DIR, 'access.log')

    CONFIG = load_config(STATE_DIR, args)
    AUTH = Auth(load_token(STATE_DIR))

    ips = local_ips()
    port = int(CONFIG['port'])
    bind = CONFIG['bind'] or '0.0.0.0'

    eips(3, 'hyKBridge starting...')
    eips(4, 'port %d  token-fp %s' % (port, AUTH.fp))

    # 端口自检：别人的服务已经占了就明确报错，不要静默"起来但打不开"
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind(('127.0.0.1', port))
    except OSError as e:
        msg = 'port %d already in use (%s)' % (port, errno.errorcode.get(e.errno, e.errno))
        print('[NG] ' + msg)
        eips(4, 'FAILED: ' + msg)
        return 2
    finally:
        probe.close()

    httpd = ThreadingHTTPServer((bind, port), Handler)
    httpd.daemon_threads = True

    with open(os.path.join(STATE_DIR, 'pid'), 'w') as f:
        f.write(str(os.getpid()))
    status = {'pid': os.getpid(), 'port': port, 'bind': bind, 'ips': ips,
              'token_fp': AUTH.fp, 'version': VERSION,
              'python': sys.version.split()[0], 'started': time.strftime('%Y-%m-%d %H:%M:%S'),
              'allow_system': bool(CONFIG.get('allow_system'))}
    with open(os.path.join(STATE_DIR, 'status.json'), 'w', encoding='utf-8') as f:
        json.dump(status, f, ensure_ascii=False, indent=1)
    log_line('== HyKBridge by HYrecovery & HoshinoSumi from teko.IO SisTemS! == / Under MIT Open Source License')
    log_line('START bind=%s port=%d ips=%s fp=%s' % (bind, port, ','.join(ips), AUTH.fp))

    # 屏幕提示：Kindle 上没有终端，eips 就是 stdout
    url = 'http://%s:%d/' % (ips[0] if ips else '?', port)
    eips(3, 'hyKBridge READY')
    eips(4, url)
    eips(5, 'token-fp ' + AUTH.fp + '  (>=3s)')

    print(COPYRIGHT)
    print('[OK] %s v%s listening on %s:%d' % (APPNAME, VERSION, bind, port))
    print('[i]  urls: %s' % ', '.join('http://%s:%d/' % (i, port) for i in ips))
    print('[i]  token fingerprint: %s' % AUTH.fp)
    print('[i]  state dir: %s' % STATE_DIR)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            os.remove(os.path.join(STATE_DIR, 'pid'))
        except OSError:
            pass
        log_line('STOP')
    return 0


if __name__ == '__main__':
    # 再脏也不能带崩整个服务：把致命错误写进日志文件，KUAL 里看不到 stderr
    try:
        sys.exit(main())
    except Exception as exc:                            # pragma: no cover
        import traceback
        try:
            d = os.path.dirname(os.path.abspath(__file__))
            with open(os.path.join(d, '..', 'state', 'crash.log'), 'a',
                      encoding='utf-8') as f:
                f.write('%s\n%s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), traceback.format_exc()))
        except Exception:
            pass
        print('[NG] fatal: %s' % exc)
        sys.exit(1)
