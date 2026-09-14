#!/usr/bin/env bash
# End-to-end smoke test: rendezvous server + two peers that must punch, run the
# Noise handshake, and exchange messages. Fails loudly if any step does not
# happen.
set -u
cd "$(dirname "$0")/.."
source scripts/env.sh

SERVER="./build/server/uconnect-rendezvous$EXE"
DEMO="./build/examples/uconn-demo$EXE"
UC_PORT=${UC_PORT:-14433}

cleanup() { [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null; }
trap cleanup EXIT

rm -f /tmp/uc-*.log
"$SERVER" --port "$UC_PORT" > /tmp/uc-server.log 2>&1 &
SRV_PID=$!
sleep 1

if ! kill -0 "$SRV_PID" 2>/dev/null; then
    echo "FAIL: server did not start"; cat /tmp/uc-server.log; exit 1
fi
echo "server up on $UC_PORT (pid $SRV_PID)"

TOPIC=$("$DEMO" --server "127.0.0.1:$UC_PORT" --create --seconds 0 2>/dev/null \
        | grep -o 'uconn://[0-9a-f]*#[0-9a-f]*' | head -1)
if [ -z "$TOPIC" ]; then echo "FAIL: could not create a topic"; exit 1; fi
echo "topic: ${TOPIC:0:40}..."

"$DEMO" --server "127.0.0.1:$UC_PORT" --topic "$TOPIC" --name alice --seconds 14 \
    > /tmp/uc-alice.log 2>&1 &
A=$!
sleep 2
"$DEMO" --server "127.0.0.1:$UC_PORT" --topic "$TOPIC" --name bob --seconds 12 \
    > /tmp/uc-bob.log 2>&1 &
B=$!

wait $A; RA=$?
wait $B; RB=$?

echo
echo "=== alice ==="; cat /tmp/uc-alice.log
echo "=== bob ==="; cat /tmp/uc-bob.log
echo "=== server ==="; cat /tmp/uc-server.log

FAIL=0
grep -q "> connected" /tmp/uc-alice.log || { echo "FAIL: alice never connected"; FAIL=1; }
grep -q "> connected" /tmp/uc-bob.log   || { echo "FAIL: bob never connected"; FAIL=1; }
grep -q "<- .*hello from bob"   /tmp/uc-alice.log || { echo "FAIL: alice got no message from bob"; FAIL=1; }
grep -q "<- .*hello from alice" /tmp/uc-bob.log   || { echo "FAIL: bob got no message from alice"; FAIL=1; }
[ "$RA" -eq 0 ] || { echo "FAIL: alice exit $RA"; FAIL=1; }
[ "$RB" -eq 0 ] || { echo "FAIL: bob exit $RB"; FAIL=1; }

if [ "$FAIL" -eq 0 ]; then echo; echo "SMOKE TEST PASSED"; else echo; echo "SMOKE TEST FAILED"; fi
exit $FAIL
