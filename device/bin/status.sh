#!/bin/sh
# hyKBridge -- show status on the Kindle screen (e-ink has no terminal)
# LF line endings only. ASCII only.

DIR=/mnt/us/extensions/hyKBridge
STATE=$DIR/state
PORT=$(cat $STATE/port 2>/dev/null)
[ -n "$PORT" ] || PORT=8090

. $DIR/bin/banner.sh    # copyright banner

if [ ! -f $STATE/status.json ]; then
    eips 2 3 "hyKBridge: never started"
    eips 2 4 "state/status.json is missing"
    exit 0
fi

PID=$(cat $STATE/pid 2>/dev/null)
RUN="stopped"
if [ -n "$PID" ] && kill -0 $PID 2>/dev/null; then RUN="running"; fi

IP=$(sed -n 's/.*"ips": \["\([^"]*\)".*/\1/p' $STATE/status.json 2>/dev/null)
FP=$(sed -n 's/.*"token_fp": "\([^"]*\)".*/\1/p' $STATE/status.json 2>/dev/null)
PY=$(sed -n 's/.*"python": "\([^"]*\)".*/\1/p' $STATE/status.json 2>/dev/null)

eips 2 2 "hyKBridge: $RUN"
eips 2 3 "http://$IP:$PORT/"
eips 2 4 "pid $PID  python $PY"
eips 2 5 "token-fp $FP  (token in state/token.txt)"
