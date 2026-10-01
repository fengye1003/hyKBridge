#!/bin/sh
# waketest.sh -- controlled RTC wake test (one shot).
# Sets an alarm 60s out, suspends, and records whether we actually come back.
# WHY: the pulse loop armed /sys/class/rtc/rtc0/wakealarm and the value read back
# correctly, yet the device slept 4.4 hours without waking -- so either the alarm is
# cleared on suspend or it never fires. rtcwake is the tool built for exactly this.
# LF line endings only. ASCII only.

LOG=/mnt/us/tmp/waketest.log

echo "START $(date +%H:%M:%S) epoch=$(date +%s)" > $LOG
echo "wakealarm_before=$(cat /sys/class/rtc/rtc0/wakealarm 2>&1)" >> $LOG
echo "wakeup_flag=$(cat /sys/class/rtc/rtc0/device/power/wakeup 2>&1)" >> $LOG

# -m mem = suspend to RAM, -s 60 = 60 seconds from now
/usr/sbin/rtcwake -d /dev/rtc0 -m mem -s 60 >> $LOG 2>&1
RC=$?

echo "WOKE $(date +%H:%M:%S) epoch=$(date +%s) rtcwake_rc=$RC" >> $LOG
echo "wakealarm_after=$(cat /sys/class/rtc/rtc0/wakealarm 2>&1)" >> $LOG
