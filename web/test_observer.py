"""Tests for the dashboard's data layer.

Runs without Flask and without a network: the subprocess boundary is the seam,
so a fake binary stands in for uconn-observe. What is being tested is the
caching, the stale-on-failure behaviour and the summarising -- the parts that
decide whether a dashboard misleads someone when the server misbehaves.

    python3 web/test_observer.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from observer import Observer, ObserverError, summarise  # noqa: E402

FAILED = 0


def check(cond, what):
    global FAILED
    if cond:
        print(f"  ok   {what}")
    else:
        FAILED += 1
        print(f"  FAIL {what}")


def fake_binary(body: str, exit_code: int = 0) -> str:
    """A stand-in for uconn-observe that prints `body` and exits."""
    fd, path = tempfile.mkstemp(suffix=".py")
    os.write(fd, f"import sys\nsys.stdout.write({body!r})\nsys.exit({exit_code})\n".encode())
    os.close(fd)

    fd2, sh = tempfile.mkstemp(suffix=".sh")
    os.write(fd2, f"#!/bin/sh\nexec {sys.executable} {path} \"$@\"\n".encode())
    os.close(fd2)
    os.chmod(sh, 0o755)
    return sh


SAMPLE = json.dumps(
    {
        "ok": True,
        "server": "127.0.0.1:4433",
        "stats": {"topics_total": 2, "topics_listed": 1, "entries_fresh": 3},
        "topics": [
            {
                "id": "a" * 32,
                "mode": "keyed",
                "peers": 2,
                "fresh_peers": 2,
                "members": [
                    {"dev_id": "b" * 32, "age_s": 3, "stale": False, "meta_text": "alice"},
                    {"dev_id": "c" * 32, "age_s": 9, "stale": True},
                ],
            },
            {"id": "d" * 32, "mode": "open", "peers": 50, "fresh_peers": 40, "members": []},
        ],
    }
)


def test_parses_and_summarises():
    print("parses and summarises")
    o = Observer("x:1", binary=fake_binary(SAMPLE))
    data, stale, err = o.overview()
    check(not stale and err is None, "fresh result is not marked stale")

    v = summarise(data)
    check(v["topic_count"] == 2, "counts topics")
    check(v["peer_count"] == 52, "sums peers across topics")
    check(v["topics"][0]["peers"] == 50, "sorts by peer count, busiest first")
    check(v["topics"][1]["keyed"] is True, "flags keyed topics")


def test_reports_sampling():
    # A 50-peer topic that returned 0 members must not look like an empty topic,
    # and a 2-peer topic that returned both must not claim it was sampled.
    print("distinguishes a sample from the whole swarm")
    o = Observer("x:1", binary=fake_binary(SAMPLE))
    data, _, _ = o.overview()
    v = summarise(data)
    big = next(t for t in v["topics"] if t["peers"] == 50)
    small = next(t for t in v["topics"] if t["peers"] == 2)
    check(big["sampled"] is True, "50 peers with 0 returned is marked sampled")
    check(small["sampled"] is False, "2 peers with 2 returned is not")


def test_cache_prevents_hammering():
    # Caching is what keeps an open dashboard from tripping the server's own
    # per-IP rate limiter, so it is load-bearing rather than an optimisation.
    print("caches within the TTL")
    counter = tempfile.mktemp()
    fd, path = tempfile.mkstemp(suffix=".py")
    os.write(
        fd,
        (
            f"import sys\n"
            f"open({counter!r}, 'a').write('x')\n"
            f"sys.stdout.write({SAMPLE!r})\n"
        ).encode(),
    )
    os.close(fd)
    fd2, sh = tempfile.mkstemp(suffix=".sh")
    os.write(fd2, f"#!/bin/sh\nexec {sys.executable} {path} \"$@\"\n".encode())
    os.close(fd2)
    os.chmod(sh, 0o755)

    o = Observer("x:1", binary=sh, ttl=10.0)
    for _ in range(5):
        o.overview()
    runs = len(open(counter).read()) if os.path.exists(counter) else 0
    check(runs == 1, f"five requests ran the binary once (ran {runs})")


def test_serves_stale_on_failure():
    # A server restart, or one lookup hitting the rate limiter, should not blank
    # a dashboard that was correct a moment ago -- but it must be visibly old.
    print("serves stale data when a refresh fails")
    good = fake_binary(SAMPLE)
    o = Observer("x:1", binary=good, ttl=0.0)
    o.overview()

    o.binary = fake_binary(json.dumps({"ok": False, "error": "server unreachable"}))
    data, stale, err = o.overview()
    check(stale is True, "result is flagged stale")
    check("unreachable" in (err or ""), "the underlying error is reported, not swallowed")
    check(len(data["topics"]) == 2, "last good data is still served")


def test_first_failure_raises():
    print("raises when there is no good data to fall back on")
    o = Observer("x:1", binary=fake_binary(json.dumps({"ok": False, "error": "nope"})))
    try:
        o.overview()
        check(False, "should have raised")
    except ObserverError as exc:
        check("nope" in str(exc), "propagates the error")


def test_rejects_bad_topic_ids():
    # This string reaches a subprocess argument list, so it is validated before
    # it gets there rather than trusted.
    print("validates topic ids")
    o = Observer("x:1", binary=fake_binary(SAMPLE))
    for bad in ("", "xyz", "g" * 32, "a" * 31, "a" * 33, "../../etc/passwd", "a" * 32 + ";id"):
        try:
            o.topic(bad)
            check(False, f"accepted bad id {bad!r}")
        except ObserverError:
            check(True, f"rejected {bad[:18]!r}")


def test_missing_binary_is_explained():
    print("explains a missing binary")
    o = Observer("x:1", binary="/nonexistent/uconn-observe")
    try:
        o.overview()
        check(False, "should have raised")
    except ObserverError as exc:
        check("not found" in str(exc).lower(), "says the binary is missing, not 'invalid JSON'")


def test_garbage_output_is_explained():
    print("explains unparseable output")
    o = Observer("x:1", binary=fake_binary("this is not json"))
    try:
        o.overview()
        check(False, "should have raised")
    except ObserverError as exc:
        check("JSON" in str(exc), "names the real problem")



# ---------------------------------------------------------------------------
# Sessions and limits
# ---------------------------------------------------------------------------
from sessions import LimitError, SessionRegistry, client_ip  # noqa: E402
from events import EventHub  # noqa: E402


def test_session_cap_per_ip():
    print("caps sessions per IP")
    r = SessionRegistry(max_per_ip=3)
    sids = [r.touch(None, "1.2.3.4").sid for _ in range(3)]
    check(len(set(sids)) == 3, "issues distinct session ids")
    try:
        r.touch(None, "1.2.3.4")
        check(False, "should have refused the 4th")
    except LimitError as e:
        check("too many" in str(e), "refuses past the cap with a usable message")
    check(r.touch(None, "5.6.7.8") is not None, "a different address is unaffected")
    check(r.touch(sids[0], "1.2.3.4").sid == sids[0], "an existing session still works")


def test_idle_sessions_expire():
    # Without reaping, the cap becomes permanent: ten visits from an office NAT
    # would lock out everyone behind it forever.
    print("expires idle sessions so the cap is not permanent")
    r = SessionRegistry(max_per_ip=2, idle_timeout=0.0)
    r.touch(None, "1.1.1.1")
    r.touch(None, "1.1.1.1")
    try:
        r.touch(None, "1.1.1.1")
        check(True, "idle sessions were reaped, so a new one is allowed")
    except LimitError:
        check(False, "should have reaped idle sessions")


def test_stream_limits():
    print("caps live streams globally and per session")
    r = SessionRegistry(max_per_ip=10, max_total_streams=2, max_streams_per_session=1)
    a = r.touch(None, "1.1.1.1").sid
    b = r.touch(None, "2.2.2.2").sid
    c = r.touch(None, "3.3.3.3").sid
    r.open_stream(a); r.open_stream(b)
    try:
        r.open_stream(c); check(False, "should have hit the global cap")
    except LimitError as e:
        check("capacity" in str(e), "global cap refuses with a clear message")
    try:
        r.open_stream(a); check(False, "should have hit the per-session cap")
    except LimitError:
        check(True, "per-session cap holds")
    r.close_stream(a)
    r.open_stream(c)
    check(True, "closing a stream frees the slot")


def test_stream_slot_is_not_leaked_by_a_reaped_session():
    # A session reaped mid-stream must still return its slot, or the feed
    # slowly closes itself to everyone.
    print("does not leak a stream slot when the session is gone")
    r = SessionRegistry(max_total_streams=1, idle_timeout=0.0)
    s = r.touch(None, "1.1.1.1").sid
    r.open_stream(s)
    r._sessions.clear()          # simulate the reaper taking it mid-stream
    r.close_stream(s)
    check(r._live_streams == 0, "global counter returned to zero")


def test_topic_cap_per_session():
    print("caps topics recorded per session")
    r = SessionRegistry(max_topics_per_session=2)
    s = r.touch(None, "1.1.1.1").sid
    r.record_topic(s, "a" * 32)
    r.record_topic(s, "b" * 32)
    try:
        r.record_topic(s, "c" * 32)
        check(False, "should have refused")
    except LimitError:
        check(True, "refuses past the cap")
    r.record_topic(s, "a" * 32)
    check(len(r._sessions[s].topics) == 2, "re-recording an existing id is a no-op")


def test_forwarded_for_is_not_trusted_by_default():
    # It is a header; anyone can send one. Trusting it by default would turn
    # the per-IP limit into a suggestion.
    print("ignores X-Forwarded-For unless told to trust it")
    hdrs = {"X-Forwarded-For": "9.9.9.9"}
    check(client_ip(hdrs, "1.2.3.4", trust_proxy=False) == "1.2.3.4", "uses the peer address")
    check(client_ip(hdrs, "1.2.3.4", trust_proxy=True) == "9.9.9.9", "honours it when enabled")


# ---------------------------------------------------------------------------
# Event diffing
# ---------------------------------------------------------------------------
def _snap(topics):
    return {"ok": True, "topics": topics, "stats": {"registers": 0, "lookups": 0}}


def _topic(tid, peers, members):
    return {"id": tid, "mode": "keyed", "peers": peers, "fresh_peers": peers,
            "members": [{"dev_id": d, "meta_text": n} for d, n in members]}


def test_first_snapshot_is_a_baseline():
    print("does not replay the world as new events on first poll")
    hub = EventHub.__new__(EventHub)
    hub._lock = __import__("threading").Lock()
    hub._subscribers = set(); hub._recent = []; hub._seq = 0; hub._prev = None
    hub._diff(_snap([_topic("a" * 32, 2, [("d1", "alice"), ("d2", "bob")])]))
    kinds = [e["kind"] for e in hub._recent]
    check(kinds == ["ready"], f"only a baseline event, got {kinds}")


def test_diff_reports_joins_leaves_and_topics():
    print("reports joins, leaves and topic lifecycle")
    hub = EventHub.__new__(EventHub)
    hub._lock = __import__("threading").Lock()
    hub._subscribers = set(); hub._recent = []; hub._seq = 0; hub._prev = None

    hub._diff(_snap([_topic("a" * 32, 1, [("d1", "alice")])]))
    hub._recent.clear()
    hub._diff(_snap([_topic("a" * 32, 2, [("d1", "alice"), ("d2", "bob")]),
                     _topic("b" * 32, 1, [("d3", "carol")])]))
    kinds = {e["kind"] for e in hub._recent}
    check("peer_join" in kinds, "reports a join")
    check("topic_new" in kinds, "reports a new topic")
    joined = [e for e in hub._recent if e["kind"] == "peer_join"]
    check(any(e.get("name") == "bob" for e in joined), "carries the metadata name")

    hub._recent.clear()
    hub._diff(_snap([_topic("a" * 32, 1, [("d1", "alice")])]))
    kinds = {e["kind"] for e in hub._recent}
    check("peer_leave" in kinds, "reports a leave")
    check("topic_gone" in kinds, "reports a topic disappearing")


def test_sampled_topics_do_not_produce_phantom_events():
    # LOOKUP samples. On a big topic a peer drops out of one sample and back
    # into the next without having gone anywhere; reporting that as join/leave
    # would be pure noise.
    print("suppresses join/leave on sampled topics")
    hub = EventHub.__new__(EventHub)
    hub._lock = __import__("threading").Lock()
    hub._subscribers = set(); hub._recent = []; hub._seq = 0; hub._prev = None

    hub._diff(_snap([_topic("a" * 32, 500, [("d1", "x"), ("d2", "y")])]))
    hub._recent.clear()
    hub._diff(_snap([_topic("a" * 32, 500, [("d3", "z"), ("d4", "w")])]))
    kinds = {e["kind"] for e in hub._recent}
    check("peer_join" not in kinds and "peer_leave" not in kinds,
          f"no membership events for a sampled topic, got {kinds}")


def test_slow_subscriber_does_not_grow_memory():
    print("drops events for a subscriber that stopped reading")
    import queue as _q
    hub = EventHub.__new__(EventHub)
    hub._lock = __import__("threading").Lock()
    hub._subscribers = set(); hub._recent = []; hub._seq = 0; hub._prev = None
    q = _q.Queue(maxsize=2)
    hub._subscribers.add(q)
    for i in range(50):
        hub._publish("activity", deltas={"lookups": i})
    check(q.qsize() == 2, "queue stayed bounded")
    check(len(hub._recent) <= 100, "history stayed bounded")




# ---------------------------------------------------------------------------
# Chat bridge management
# ---------------------------------------------------------------------------
from chat import BridgeManager, ChatError  # noqa: E402


def fake_bridge(script: str) -> str:
    """A stand-in for uconn-bridge: reads the URI line, then commands."""
    fd, path = tempfile.mkstemp(suffix=".py")
    os.write(fd, script.encode())
    os.close(fd)
    fd2, sh = tempfile.mkstemp(suffix=".sh")
    os.write(fd2, f"#!/bin/sh\nexec {sys.executable} -u {path} \"$@\"\n".encode())
    os.close(fd2)
    os.chmod(sh, 0o755)
    return sh


ECHO_BRIDGE = r'''
import sys, json
uri = sys.stdin.readline().strip()
tid = uri.replace("uconn://", "").split("#")[0]
print(json.dumps({"t": "ready", "dev": "d" * 32, "topic": tid, "keyed": "#" in uri}))
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    m = json.loads(line)
    if m.get("cmd") == "bye":
        break
    if m.get("cmd") == "say":
        print(json.dumps({"t": "msg", "dev": "d" * 32, "text": m["text"], "self": True}))
'''


def test_chat_rejects_malformed_topics():
    # The URI is written to the child's stdin as one line, so a newline in it
    # would be read as a command rather than as part of the URI.
    print("validates topic URIs before spawning anything")
    m = BridgeManager("x:1", binary=fake_bridge(ECHO_BRIDGE))
    for bad in ("", "http://x", "uconn://short",
                "uconn://" + "a" * 32 + "\n{\"cmd\":\"say\"}",
                "uconn://" + "g" * 32, "uconn://" + "a" * 31):
        try:
            m.start("s1", bad, "nick")
            check(False, f"accepted {bad[:24]!r}")
        except ChatError:
            check(True, f"rejected {bad[:24]!r}")


def test_chat_round_trip():
    print("relays a message through the bridge")
    m = BridgeManager("x:1", binary=fake_bridge(ECHO_BRIDGE))
    b = m.start("s1", "uconn://" + "a" * 32 + "#" + "b" * 64, "alice")
    q = b.subscribe()
    deadline = time.time() + 5
    ready = None
    while time.time() < deadline and ready is None:
        try:
            ev = q.get(timeout=1)
            if ev.get("t") == "ready":
                ready = ev
        except Exception:
            break
    check(ready is not None, "got a ready event")
    check(ready and ready["topic"] == "a" * 32, "carries the topic id")

    b.say("hello there")
    got = None
    deadline = time.time() + 5
    while time.time() < deadline and got is None:
        try:
            ev = q.get(timeout=1)
            if ev.get("t") == "msg":
                got = ev
        except Exception:
            break
    check(got is not None and got["text"] == "hello there", "message echoed back")
    m.stop("s1")


def test_chat_caps_total_sessions():
    # Each bridge is a real UDP node -- far more expensive than a page view --
    # so the cap is what stops a handful of tabs pinning the host.
    print("caps concurrent chat sessions")
    m = BridgeManager("x:1", binary=fake_bridge(ECHO_BRIDGE), max_total=2)
    m.start("s1", "uconn://" + "a" * 32, "a")
    m.start("s2", "uconn://" + "b" * 32, "b")
    try:
        m.start("s3", "uconn://" + "c" * 32, "c")
        check(False, "should have refused a third")
    except ChatError as e:
        check("full" in str(e), "refuses with a message that suggests a native client")
    # Rejoining an existing session replaces rather than counts again.
    m.start("s1", "uconn://" + "a" * 32, "a")
    check(True, "an existing session can rejoin at the cap")
    m.stop("s1"); m.stop("s2")


def test_chat_replays_history_to_a_second_tab():
    print("replays history to a late subscriber")
    m = BridgeManager("x:1", binary=fake_bridge(ECHO_BRIDGE))
    b = m.start("s1", "uconn://" + "a" * 32, "a")
    time.sleep(0.6)
    b.say("first")
    time.sleep(0.6)
    q = b.subscribe()
    seen = []
    while True:
        try:
            seen.append(q.get_nowait())
        except Exception:
            break
    check(any(e.get("t") == "ready" for e in seen), "second tab sees the ready event")
    check(any(e.get("text") == "first" for e in seen), "and the message it missed")
    m.stop("s1")


def test_chat_missing_binary_is_explained():
    print("explains a missing bridge binary")
    m = BridgeManager("x:1", binary="/nonexistent/uconn-bridge")
    try:
        m.start("s1", "uconn://" + "a" * 32, "a")
        check(False, "should have raised")
    except ChatError as e:
        check("not found" in str(e).lower(), "names the real problem")


if __name__ == "__main__":
    for fn in [
        test_parses_and_summarises,
        test_reports_sampling,
        test_cache_prevents_hammering,
        test_serves_stale_on_failure,
        test_first_failure_raises,
        test_rejects_bad_topic_ids,
        test_missing_binary_is_explained,
        test_garbage_output_is_explained,
        test_session_cap_per_ip,
        test_idle_sessions_expire,
        test_stream_limits,
        test_stream_slot_is_not_leaked_by_a_reaped_session,
        test_topic_cap_per_session,
        test_forwarded_for_is_not_trusted_by_default,
        test_first_snapshot_is_a_baseline,
        test_diff_reports_joins_leaves_and_topics,
        test_sampled_topics_do_not_produce_phantom_events,
        test_slow_subscriber_does_not_grow_memory,
        test_chat_rejects_malformed_topics,
        test_chat_round_trip,
        test_chat_caps_total_sessions,
        test_chat_replays_history_to_a_second_tab,
        test_chat_missing_binary_is_explained,
    ]:
        fn()
    print()
    print("FAILED" if FAILED else "all web tests passed")
    sys.exit(1 if FAILED else 0)
