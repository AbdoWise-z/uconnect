#!/usr/bin/env bash
# End-to-end transfer over both paths a peer connection can take.
#
#   punched : the normal case -- peers reach each other directly, over TCP for
#             messages and punched UDP for datagrams
#   relayed : the fallback when punching fails, forced here so the path is
#             exercised even from a network where punching happens to work --
#             the TCP relay for messages, the UDP relay for datagrams
#
# Each leg moves a megabyte of a known pattern as messages and verifies every
# byte, in order, and the receiver acknowledges the end. Then it sends a burst
# of datagrams and requires most of them to arrive -- they are unreliable, so
# "all" would test the network rather than the library.
set -uo pipefail
cd "$(dirname "$0")/.."
source scripts/env.sh

SERVER="./build/server/uconnect-rendezvous$EXE"
XFER="./build/examples/uconn-transfer$EXE"
DEMO="./build/examples/uconn-demo$EXE"
BYTES=${BYTES:-1048576}
DGRAMS=${DGRAMS:-500}
FAIL=0

leg() {
    local label="$1" port="$2" extra="$3" want_path="$4" want_dpath="$5"

    "$SERVER" --port "$port" --quiet > "/tmp/xs-$label-server.log" 2>&1 &
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

    "$XFER" --server "127.0.0.1:$port" --topic "$TOPIC" --recv $extra --seconds 60 \
        > "/tmp/xs-$label-recv.log" 2>&1 &
    local R=$!
    sleep 1
    "$XFER" --server "127.0.0.1:$port" --topic "$TOPIC" --send "$BYTES" --dgrams "$DGRAMS" \
        $extra --seconds 60 > "/tmp/xs-$label-send.log" 2>&1 &
    local S=$!

    wait $S; local RS=$?
    wait $R; local RR=$?
    local stats
    stats="$("$DEMO" --server "127.0.0.1:$port" --stats 2>/dev/null || true)"
    kill "$SRV" 2>/dev/null

    local got dgot
    got="$(grep -o '\[recv\] [0-9]* bytes' "/tmp/xs-$label-recv.log" | grep -o '[0-9]*' | head -1)"
    dgot="$(grep -o 'received=[0-9-]*' "/tmp/xs-$label-send.log" | cut -d= -f2)"

    echo "--- $label ---"
    grep -E '^\[(send|recv|link)\]' "/tmp/xs-$label-send.log" "/tmp/xs-$label-recv.log" \
        | sed "s|/tmp/xs-$label-[a-z]*\.log:||"

    [ "$RS" -eq 0 ] || { echo "FAIL [$label]: sender exit $RS"; FAIL=1; }
    [ "$RR" -eq 0 ] || { echo "FAIL [$label]: receiver exit $RR"; FAIL=1; }
    [ "${got:-0}" = "$BYTES" ] || { echo "FAIL [$label]: got ${got:-0} of $BYTES bytes"; FAIL=1; }
    grep -q "verified=yes" "/tmp/xs-$label-recv.log" || {
        echo "FAIL [$label]: payload did not verify"; FAIL=1; }
    grep -q "acked=yes" "/tmp/xs-$label-send.log" || {
        echo "FAIL [$label]: the receiver never acknowledged"; FAIL=1; }
    grep -q "^\[link\] $want_path" "/tmp/xs-$label-send.log" || {
        echo "FAIL [$label]: expected a $want_path connection"; FAIL=1; }
    grep -q "path=$want_dpath " "/tmp/xs-$label-send.log" || {
        echo "FAIL [$label]: expected datagrams over $want_dpath"; FAIL=1; }
    # Loopback loses nothing in practice; 90% leaves room for a busy machine.
    if [ "${dgot:--1}" -lt $((DGRAMS * 9 / 10)) ]; then
        echo "FAIL [$label]: only ${dgot:-none} of $DGRAMS datagrams arrived"; FAIL=1
    fi

    echo "  server: $(echo "$stats" | grep -o 'registers=[0-9]*') $(echo "$stats" | grep -o 'relays=[0-9]*')"
}

leg punched 19500 ""                              direct  direct
leg relayed 19600 "--relay --dgram-fallback relay" relayed relayed

echo
if [ "$FAIL" -eq 0 ]; then echo "TRANSFER SMOKE PASSED"; else echo "TRANSFER SMOKE FAILED"; fi
exit $FAIL
