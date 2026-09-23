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

# Bob exits well before alice on purpose: his shutdown sends a wire-level close
# and alice has to still be running to observe it. Without that message she
# would not notice until the 90s idle timeout, long after this test is over.
"$DEMO" --server "127.0.0.1:$UC_PORT" --topic "$TOPIC" --name alice --seconds 18 \
    > /tmp/uc-alice.log 2>&1 &
A=$!
sleep 2
"$DEMO" --server "127.0.0.1:$UC_PORT" --topic "$TOPIC" --name bob --seconds 8 \
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

# Bob's shutdown tells alice on the wire. She outlives him by ~8s, and the idle
# timeout is 90s, so seeing "closed" at all proves the message arrived rather
# than a timer having expired.
grep -q "> closed" /tmp/uc-alice.log || {
    echo "FAIL: alice never saw bob close -- the shutdown notice did not arrive"
    FAIL=1
}
[ "$RA" -eq 0 ] || { echo "FAIL: alice exit $RA"; FAIL=1; }
[ "$RB" -eq 0 ] || { echo "FAIL: bob exit $RB"; FAIL=1; }

# Two peers publishing once each should produce exactly two registrations, and
# no authentication rejections at all.
#
# Both checks exist because of one bug that hid behind a passing smoke test: a
# spurious retransmission registered every client twice, the server rotated the
# lease token on the second registration, and every authenticated message
# afterwards failed. Punching does not depend on those MACs, so peers still
# connected and still exchanged messages -- nothing looked wrong until the
# relay, which does depend on them, refused to work at all.
STATS="$("$DEMO" --server "127.0.0.1:$UC_PORT" --stats 2>/dev/null || true)"
echo "=== server stats ==="; echo "$STATS"

REGS="$(echo "$STATS" | grep -o 'registers=[0-9]*' | cut -d= -f2)"
AUTH="$(echo "$STATS" | grep -o 'auth=[0-9]*' | cut -d= -f2)"

[ "${AUTH:-0}" = "0" ] || { echo "FAIL: $AUTH authentication rejection(s) -- lease drift"; FAIL=1; }
# 3 = alice + bob + the helper that created the topic.
if [ -n "$REGS" ] && [ "$REGS" -gt 3 ]; then
    echo "FAIL: $REGS registrations for 3 publishers -- requests are being duplicated"
    FAIL=1
fi

if [ "$FAIL" -eq 0 ]; then echo; echo "SMOKE TEST PASSED"; else echo; echo "SMOKE TEST FAILED"; fi
exit $FAIL
