#!/bin/sh
# hyKBridge -- show the last lines of the access log on screen
# LF line endings only. ASCII only.

DIR=/mnt/us/extensions/hyKBridge
LOG=$DIR/state/access.log

. $DIR/bin/banner.sh    # copyright banner

if [ ! -f $LOG ]; then
    eips 2 3 "no access.log yet"
    exit 0
fi

i=1
tail -n 5 $LOG | while read line; do
    eips 2 $((i + 1)) "$(echo $line | cut -c1-44)"
    i=$((i + 1))
done
echo "--- last 5 lines ---"
tail -n 5 $LOG
