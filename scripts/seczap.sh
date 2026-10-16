#!/bin/bash
# usage: seczap.sh <repo> <phase> <label> baseline|api <target> [extra zap args...]
R=$1; P=$2; L=$3; MODE=$4; T=$5; shift 5
OUT=${WORK:-$HOME/sec}/_results/$R/$P
mkdir -p "$OUT"
W=$(mktemp -d /tmp/secr6zap.XXXX); chmod 777 "$W"
if [ "$MODE" = baseline ]; then
  docker run --rm --name "secr6-zap-$$" --network host -v "$W":/zap/wrk:rw ghcr.io/zaproxy/zaproxy:stable \
    zap-baseline.py -t "$T" -J zap-$L.json -r zap-$L.html -I "$@" > "$W/zap-$L.log" 2>&1
else
  docker run --rm --name "secr6-zap-$$" --network host -v "$W":/zap/wrk:rw ghcr.io/zaproxy/zaproxy:stable \
    zap-api-scan.py -t "$T" -f openapi -J zap-$L.json -r zap-$L.html -I "$@" > "$W/zap-$L.log" 2>&1
fi
echo "zap $MODE exit $?"
cp "$W"/zap-$L.* "$OUT"/ ; rm -rf "$W"
grep -E 'FAIL-NEW|WARN-NEW' "$OUT/zap-$L.log" | head -40
