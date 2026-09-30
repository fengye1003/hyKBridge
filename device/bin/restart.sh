#!/bin/sh
# hyKBridge -- restart
# LF line endings only. ASCII only.
#
# GOTCHA 2026-09-30: the first version was just "stop.sh; start.sh". When that
# command is issued through this server's own /api/exec, the script inherits the
# SERVER's stdout/stderr PIPES. Kill the server and the pipes break -- the next
# write from this script takes SIGPIPE and dies too. Net effect: "service stopped,
# never came back", i.e. the remote channel was gone and only a human tapping
# Start Shell in KUAL could recover it.
#
# Correct pattern: detach the real work completely first (setsid + stdin/stdout/
# stderr redirected to a file or /dev/null), return immediately, and let the
# detached process do the delayed stop/start.

DIR=/mnt/us/extensions/hyKBridge
STATE=$DIR/state

mkdir -p $STATE

. $DIR/bin/banner.sh    # copyright banner

setsid sh -c "sleep 2; sh $DIR/bin/stop.sh >> $STATE/restart.log 2>&1; sleep 1; sh $DIR/bin/start.sh >> $STATE/restart.log 2>&1" < /dev/null >> $STATE/restart.log 2>&1 &

echo "restart scheduled (detached); watch state/restart.log and state/status.json"
