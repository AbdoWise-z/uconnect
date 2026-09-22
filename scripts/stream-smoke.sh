#!/usr/bin/env bash
# End-to-end test of the reliable stream layer, over both paths a peer can take.
#
#   punched : the normal case -- peers reach each other directly
#   relayed : the fallback for symmetric NAT, forced here so the path is
#             exercised even from a network where punching happens to work
#
# Each leg transfers a megabyte of a known pattern and verifies every byte, in
# order. That is the whole claim of the layer: the session underneath loses and
# reorders, and the application must not be able to tell.
set -uo pipefail
cd "$(dirname "$0")/.."
source scripts/env.sh

SERVER="./build/server/uconnect-rendezvous$EXE"
STREAM="./build/examples/uconn-stream$EXE"
DEMO="./build/examples/uconn-demo$EXE"
BYTES=${BYTES:-1048576}
FAIL=0

leg() {
    local label="$1" port="$2" extra="$3"

    "$SERVER" --port "$port" --quiet > "/tmp/ss-$label-server.log" 2>&1 &
    local SRV=$!
    sleep 1
    if ! kill -0 "$SRV" 2>/dev/null; then
        echo "FAIL [$label]: server did not start"; FAIL=1; return
    fi

    # Build the topic locally so no helper process registers a ghost record.
    local TID KEY TOPIC
    TID=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
    KEY=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    TOPIC="uconn://${TID}#${KEY}"

    "$STREAM" --server "127.0.0.1:$port" --topic "$TOPIC" --recv $extra --seconds 150 \
        > "/tmp/ss-$label-recv.log" 2>&1 &
    local R=$!
    sleep 2
    "$STREAM" --server "127.0.0.1:$port" --topic "$TOPIC" --send "$BYTES" $extra --seconds 150 \
        > "/tmp/ss-$label-send.log" 2>&1 &
    local S=$!

    wait $S; local RS=$?
    wait $R; local RR=$?
    local stats
    stats="$("$DEMO" --server "127.0.0.1:$port" --stats 2>/dev/null || true)"
    kill "$SRV" 2>/dev/null

    local got
    got="$(grep -o '\[recv\] [0-9]* bytes' "/tmp/ss-$label-recv.log" | grep -o '[0-9]*' | head -1)"

    echo "--- $label ---"
    grep -E '^\[(send|recv)\]' "/tmp/ss-$label-send.log" "/tmp/ss-$label-recv.log" \
        | sed "s|/tmp/ss-$label-[a-z]*\.log:||"

    [ "$RS" -eq 0 ] || { echo "FAIL [$label]: sender exit $RS"; FAIL=1; }
    [ "$RR" -eq 0 ] || { echo "FAIL [$label]: receiver exit $RR"; FAIL=1; }
    [ "${got:-0}" = "$BYTES" ] || { echo "FAIL [$label]: got ${got:-0} of $BYTES bytes"; FAIL=1; }
    grep -q "verified=yes" "/tmp/ss-$label-recv.log" || {
        echo "FAIL [$label]: payload did not verify"; FAIL=1; }
    grep -q "fin=yes" "/tmp/ss-$label-recv.log" || {
        echo "FAIL [$label]: stream never finished"; FAIL=1; }

    # A lease mismatch shows up here and nowhere else on the punched path.
    echo "$stats" | grep -q "auth=0" || {
        echo "FAIL [$label]: authentication rejections"; FAIL=1; }
    echo "  server: $(echo "$stats" | grep -o 'registers=[0-9]*') $(echo "$stats" | grep -o 'relays=[0-9]*')"
}

leg punched 19500 ""
leg relayed 19600 "--relay"

echo
if [ "$FAIL" -eq 0 ]; then echo "STREAM SMOKE PASSED"; else echo "STREAM SMOKE FAILED"; fi
exit $FAIL
