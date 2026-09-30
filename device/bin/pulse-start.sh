#!/bin/sh
# pulse-start.sh -- turn pulse mode on and launch the client detached.
# LF line endings only. ASCII only.

DIR=/mnt/us/extensions/hyKBridge
STATE=$DIR/state
LOG=$STATE/pulse.log
PY=/mnt/us/python3/bin/python3.9
[ -x "$PY" ] || PY=/usr/bin/python3
[ -x "$PY" ] || PY=/usr/bin/python

mkdir -p $STATE
touch $STATE/pulse-on

. $DIR/bin/banner.sh    # copyright banner

if [ -f $STATE/pulse.pid ]; then
    PID=$(cat $STATE/pulse.pid 2>/dev/null)
    if [ -n "$PID" ] && kill -0 $PID 2>/dev/null; then
        eips 2 3 "hyKBridge pulse already running (pid $PID)"
        exit 0
    fi
fi

if [ ! -f $STATE/paired.json ]; then
    eips 2 3 "Not paired yet."
    eips 2 4 "Run 'Show Pairing Code' first."
    rm -f $STATE/pulse-on
    exit 0
fi

# detached: never hang this loop off the caller's pipes (see restart.sh gotcha)
setsid "$PY" -u $DIR/bin/hyKBridge-pulse.py < /dev/null >> $LOG 2>&1 &
sleep 2

PID=$(ps aux | grep '[h]yKBridge-pulse.py' | awk '{print $2}' | head -n 1)
if [ -n "$PID" ]; then
    echo $PID > $STATE/pulse.pid
    eips 2 3 "hyKBridge pulse ON (pid $PID)"
else
    eips 2 3 "hyKBridge pulse FAILED"
    eips 2 4 "see state/pulse.log"
fi
