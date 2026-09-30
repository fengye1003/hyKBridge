#!/bin/sh
# sleep-once.sh [SECONDS] [dry] -- SUSPEND test: arm the RTC alarm, verify it,
# then suspend. `dry` only arms + verifies + clears, WITHOUT suspending.
#
# Safety: if the alarm cannot be read back, it does NOT suspend (a device that
# sleeps with no alarm is a device you have to walk over and press the button).
#
# LF line endings only. ASCII only.

N=$1
[ -n "$N" ] || N=30
MODE=$2
RTC=/sys/class/rtc/rtc0/wakealarm
LOG=/mnt/us/extensions/hyKBridge/state/sleep.log

. $DIR/bin/banner.sh    # copyright banner

echo 0 > $RTC 2>/dev/null
echo +$N > $RTC 2>/dev/null
ALARM=$(cat $RTC 2>/dev/null)
NOW=$(date +%s 2>/dev/null)

if [ -z "$ALARM" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') ABORT: wakealarm empty after writing +$N" >> $LOG
    echo "ABORT: wakealarm empty"
    exit 1
fi

if [ "$MODE" = "dry" ]; then
    echo "dry-run: alarm=$ALARM now=$NOW delta=$((ALARM - NOW))s"
    echo "$(date '+%Y-%m-%d %H:%M:%S') dry-run OK alarm=$ALARM now=$NOW" >> $LOG
    echo 0 > $RTC 2>/dev/null
    exit 0
fi

echo "$(date '+%Y-%m-%d %H:%M:%S') suspending for ${N}s (alarm=$ALARM)" >> $LOG
echo mem > /sys/power/state
echo "$(date '+%Y-%m-%d %H:%M:%S') resumed (alarm now: $(cat $RTC 2>/dev/null))" >> $LOG
echo "resumed"
