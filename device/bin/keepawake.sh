#!/bin/sh
# hyKBridge -- keep the device awake while the shell is in use
#   keepawake.sh on | off | status
#
# Why: an idle Kindle drops WiFi when it sleeps, and then the remote shell is
# simply gone. preventScreenSaver is a RUNTIME lipc property -- it writes no
# file on the system partition and resets on reboot. Cost: more battery drain,
# so it is opt-in (flag file state/keep-awake decides whether start.sh applies it).
#
# LF line endings only. ASCII only.

DIR=/mnt/us/extensions/hyKBridge
STATE=$DIR/state
FLAG=$STATE/keep-awake
PROP=com.lab126.powerd
NAME=preventScreenSaver

mkdir -p $STATE

. $DIR/bin/banner.sh    # copyright banner

case "$1" in
    on)
        touch $FLAG
        lipc-set-prop $PROP $NAME 1
        eips 2 3 "Keep awake: ON"
        eips 2 4 "screen will not sleep (battery drains faster)"
        echo "keep-awake ON (powerd=$(lipc-get-prop $PROP $NAME 2>&1))"
        ;;
    off)
        rm -f $FLAG
        lipc-set-prop $PROP $NAME 0
        eips 2 3 "Keep awake: OFF"
        eips 2 4 "device may sleep again (WiFi will drop)"
        echo "keep-awake OFF (powerd=$(lipc-get-prop $PROP $NAME 2>&1))"
        ;;
    *)
        V=$(lipc-get-prop $PROP $NAME 2>&1)
        if [ -f $FLAG ]; then F=on; else F=off; fi
        eips 2 3 "keep-awake flag: $F"
        eips 2 4 "powerd $NAME = $V"
        echo "flag=$F powerd=$V"
        ;;
esac
