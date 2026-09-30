#!/bin/sh
# hyKBridge -- start the HTTP server on the Kindle (KUAL action)
# LF line endings only. ASCII only.
#
# rev2 2026-09-30: this Kindle has an inbound firewall. The File Browser plugin
# that works on this exact device opens its port in the first line of start.sh:
#     iptables -I INPUT -p tcp --dport 80 -j ACCEPT
# Without such a rule the symptom is: local listener fine, LAN unreachable
# (plain TCP timeout). So we do the same for 8090. It is a RUNTIME rule --
# it writes no file and disappears on reboot.

DIR=/mnt/us/extensions/hyKBridge
STATE=$DIR/state
LOG=$STATE/server.log
# primary port; override by writing a number into state/port (used to bring the new
# build up on a spare port while an older one still holds 8090)
PORT=$(cat $STATE/port 2>/dev/null)
[ -n "$PORT" ] || PORT=8090

mkdir -p $STATE

# keep-awake is opt-in (state/keep-awake flag): an idle Kindle drops WiFi when it
# sleeps, which silently kills this remote channel. Re-apply it on every start.
if [ -f $STATE/keep-awake ]; then
    lipc-set-prop com.lab126.powerd preventScreenSaver 1 2>/dev/null
fi

. $DIR/bin/banner.sh    # copyright banner

# ---- firewall: open the port (same recipe as the working filebrowser plugin) ----
iptables -S INPUT > $STATE/iptables-before.txt 2>&1
if iptables -C INPUT -p tcp --dport $PORT -j ACCEPT 2>/dev/null; then
    echo "iptables: rule for $PORT already present"
else
    iptables -I INPUT -p tcp --dport $PORT -j ACCEPT 2>> $STATE/iptables-before.txt
    echo "iptables: inserted ACCEPT for tcp/$PORT"
fi
iptables -S INPUT > $STATE/iptables-after.txt 2>&1

# re-open the port even when the server is already up (rules vanish on reboot)
if [ -f $STATE/pid ]; then
    PID=$(cat $STATE/pid 2>/dev/null)
    if [ -n "$PID" ] && kill -0 $PID 2>/dev/null; then
        IP=$(sed -n 's/.*"ips": \["\([^"]*\)".*/\1/p' $STATE/status.json 2>/dev/null)
        eips 2 3 "hyKBridge already running (pid $PID)"
        eips 2 4 "http://$IP:$PORT/"
        eips 2 5 "firewall rule re-checked"
        exit 0
    fi
fi

# locate python3
PY=""
for c in /mnt/us/python3/bin/python3.9 /mnt/us/python3/bin/python3.8 /usr/bin/python3 /usr/bin/python; do
    if [ -x "$c" ]; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then
    eips 2 3 "hyKBridge: no python found"
    exit 1
fi

eips 2 3 "hyKBridge: starting..."

# On-device self check: really compile it and really import the deps.
# (The dev machine runs 3.13/3.14; the Kindle runs 3.9 -- never assume.)
"$PY" -V > $STATE/python-version.txt 2>&1
"$PY" -m py_compile $DIR/server/hyKBridge.py 2> $STATE/compile.log
if [ $? -ne 0 ]; then
    eips 2 3 "hyKBridge: SYNTAX ERROR"
    eips 2 4 "see state/compile.log"
    exit 1
fi
"$PY" -c "import http.server, urllib.parse, hmac, hashlib, json, subprocess, zipfile, shutil, sqlite3, socket, threading; print('imports ok')" > $STATE/imports.log 2>&1
if [ $? -ne 0 ]; then
    eips 2 3 "hyKBridge: IMPORT FAILED"
    eips 2 4 "see state/imports.log"
    exit 1
fi

cd $DIR/server || exit 1
# -u: unbuffered -- otherwise a hard kill throws away every print/traceback
#     still sitting in the stdout buffer (we lost exactly that evidence once).
if command -v setsid >/dev/null 2>&1; then
    setsid "$PY" -u $DIR/server/hyKBridge.py --state $STATE --port $PORT >> $LOG 2>&1 < /dev/null &
else
    nohup "$PY" -u $DIR/server/hyKBridge.py --state $STATE --port $PORT >> $LOG 2>&1 < /dev/null &
fi

sleep 4

PID=$(cat $STATE/pid 2>/dev/null)
if [ -n "$PID" ] && kill -0 $PID 2>/dev/null; then
    IP=$(sed -n 's/.*"ips": \["\([^"]*\)".*/\1/p' $STATE/status.json 2>/dev/null)
    # local self-connect: proves the listener really answers, which separates
    # "process is dead" from "firewall is blocking the LAN".
    "$PY" -c "import urllib.request,sys; sys.stdout.write(urllib.request.urlopen('http://127.0.0.1:$PORT/__ping',timeout=6).read().decode())" > $STATE/selftest-local.txt 2>&1
    eips 2 3 "hyKBridge READY  pid $PID"
    eips 2 4 "http://$IP:$PORT/"
    eips 2 5 "local selftest: $(cat $STATE/selftest-local.txt | cut -c1-30)"
else
    eips 2 3 "hyKBridge FAILED"
    eips 2 4 "$(tail -n 1 $LOG 2>/dev/null | cut -c1-44)"
    eips 2 5 "see state/server.log"
fi
