#!/bin/sh
# hyKBridge -- stop the HTTP server
# LF line endings only. ASCII only.

DIR=/mnt/us/extensions/hyKBridge
STATE=$DIR/state

# let the device sleep again (the flag file state/keep-awake is kept, so a later
# Start will re-apply it -- we only drop the runtime property here)
. $DIR/bin/banner.sh    # copyright banner

lipc-set-prop com.lab126.powerd preventScreenSaver 0 2>/dev/null

if [ ! -f $STATE/pid ]; then
    eips 2 3 "hyKBridge: not running (no pid file)"
    exit 0
fi

PID=$(cat $STATE/pid 2>/dev/null)
if [ -n "$PID" ] && kill -0 $PID 2>/dev/null; then
    kill $PID 2>/dev/null
    sleep 1
    if kill -0 $PID 2>/dev/null; then
        kill -9 $PID 2>/dev/null
        sleep 1
    fi
    eips 2 3 "hyKBridge stopped (pid $PID)"
else
    eips 2 3 "hyKBridge: stale pid, cleaned"
fi
rm -f $STATE/pid
