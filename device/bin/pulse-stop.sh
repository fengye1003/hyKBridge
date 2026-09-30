#!/bin/sh
# pulse-stop.sh -- turn pulse mode off (the loop exits after its current cycle).
# LF line endings only. ASCII only.

DIR=/mnt/us/extensions/hyKBridge
STATE=$DIR/state

rm -f $STATE/pulse-on

. $DIR/bin/banner.sh    # copyright banner

PID=$(cat $STATE/pulse.pid 2>/dev/null)
if [ -n "$PID" ] && kill -0 $PID 2>/dev/null; then
    kill $PID 2>/dev/null
    sleep 1
    kill -9 $PID 2>/dev/null
fi
rm -f $STATE/pulse.pid

# clear any pending alarm so the device is not woken for nothing
echo 0 > /sys/class/rtc/rtc0/wakealarm 2>/dev/null

eips 2 3 "hyKBridge pulse OFF"
echo "pulse stopped"
