#!/bin/sh
# pair-code.sh -- open a ONE-TIME pairing window and show the code on screen.
#
# The code is what bootstraps trust: the host proves it is in the room by typing
# the 6 digits the device is displaying. Stored as sha256(salt + code) so the file
# on disk is not a usable credential by itself.
#
#   single use  |  5 minute TTL  |  max 5 wrong attempts  |  LAN only
#
# LF line endings only. ASCII only.

DIR=/mnt/us/extensions/hyKBridge
STATE=$DIR/state
PY=/mnt/us/python3/bin/python3.9
[ -x "$PY" ] || PY=/usr/bin/python3
[ -x "$PY" ] || PY=/usr/bin/python

mkdir -p $STATE

CODE=$("$PY" -c "import random;print('%06d'%random.randrange(1000000))" 2>/dev/null)
[ -n "$CODE" ] || CODE=000000
SALT=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
HASH=$(printf '%s%s' "$SALT" "$CODE" | sha256sum | cut -d' ' -f1)
NOW=$(date +%s)
EXP=$((NOW + 300))

cat > $STATE/pair.json <<EOF
{"salt":"$SALT","hash":"$HASH","expires":$EXP,"attempts":0,"used":false}
EOF

IP=$(ifconfig wlan0 2>/dev/null | grep 'inet addr' | awk -F '[ :]' '{print $13}')
[ -n "$IP" ] || IP=$(ifconfig wlan0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)

PORT=$(cat $STATE/port 2>/dev/null)
[ -n "$PORT" ] || PORT=8090

. $DIR/bin/banner.sh    # copyright banner

eips 2 2 "=== hyKBridge pairing ==="
eips 2 3 "CODE:  $CODE"
eips 2 4 "valid 5 min, one use"
eips 2 5 "$IP  port $PORT"

echo "pairing code: $CODE   (device $IP, expires in 5 min, single use)"
echo "on the host run:  node hyKBridge.mjs pair --kindle $IP --code $CODE"
