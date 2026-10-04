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


def executable_for(script: str) -> str:
    """An executable that runs the Python file `script` with this interpreter.

    A shell script with a shebang on Unix. Windows cannot execute one of those
    at all, so there it is a .cmd file, which CreateProcess runs through cmd.
    """
    if os.name == "nt":
        fd, path = tempfile.mkstemp(suffix=".cmd")
        os.write(fd, f'@"{sys.executable}" "{script}" %*\r\n'.encode())
    else:
        fd, path = tempfile.mkstemp(suffix=".sh")
        os.write(fd, f"#!/bin/sh\nexec \"{sys.executable}\" \"{script}\" \"$@\"\n".encode())
    os.close(fd)
    os.chmod(path, 0o755)
    return path


def fake_binary(body: str, exit_code: int = 0) -> str:
    """A stand-in for uconn-observe that prints `body` and exits."""
    fd, path = tempfile.mkstemp(suffix=".py")
    os.write(fd, f"import sys\nsys.stdout.write({body!r})\nsys.exit({exit_code})\n".encode())
    os.close(fd)
    return executable_for(path)


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

    o = Observer("x:1", binary=executable_for(path), ttl=10.0)
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


def test_topic_cache_is_bounded():
    # #34. Any 32-hex id is a valid request, so arbitrary ids must not grow
    # the cache without bound.
    print("bounds the per-topic cache")
    o = Observer("x:1", binary="unused", ttl=60.0)
    o._run = lambda args: json.loads(SAMPLE)
    o.overview()
    cap = getattr(Observer, "TOPIC_CACHE", 256)
    for i in range(cap + 300):
        o.topic(f"{i:032x}")
    topics = [k for k in o._cache if k.startswith("topic:")]
    check(len(topics) <= cap, f"{len(topics)} topic entries kept, at most {cap}")
    check(f"topic:{cap + 299:032x}" in o._cache, "the newest is kept")
    check(f"topic:{0:032x}" not in o._cache, "the oldest went first")
    check("overview:True" in o._cache, "the overview is never evicted for topics")


def test_concurrent_misses_run_once():
    # #34. Simultaneous requests for one uncached key each ran the binary.
    print("runs one lookup for simultaneous misses on one key")
    import threading
    o = Observer("x:1", binary="unused", ttl=60.0)
    runs = []

    def slow_run(args):
        runs.append(args)
        time.sleep(0.3)
        return json.loads(SAMPLE)

    o._run = slow_run
    results = []
    threads = [threading.Thread(target=lambda: results.append(o.topic("e" * 32))) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check(len(runs) == 1, f"eight requests ran the binary once (ran {len(runs)})")
    check(len(results) == 8 and all(not stale for _, stale, _ in results), "all eight got the answer")

    # A failure reaches every waiter too, rather than leaving them hanging.
    def failing_run(args):
        runs.append(args)
        time.sleep(0.3)
        raise ObserverError("boom")

    o._run = failing_run
    errors = []

    def ask():
        try:
            o.topic("f" * 32)
        except ObserverError as exc:
            errors.append(str(exc))

    threads = [threading.Thread(target=ask) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check(len(errors) == 4 and all("boom" in e for e in errors), "all four waiters saw the failure")


def test_missing_binary_is_explained():
    print("explains a missing binary")
    o = Observer("x:1", binary="/nonexistent/uconn-observe")
    try:
        o.overview()
        check(False, "should have raised")
    except ObserverError as exc:
        check("not found" in str(exc).lower(), "says the binary is missing, not 'invalid JSON'")


def test_unrunnable_binary_is_explained():
    # #52. A binary that exists but cannot be executed -- no execute bit on
    # Linux, not a valid executable on Windows -- raised a bare OSError, which
    # the dashboard's routes do not catch: a 500 instead of an explanation.
    print("explains a binary that cannot be run")
    fd, path = tempfile.mkstemp(suffix=".bin")
    os.write(fd, b"this is not a program\n")
    os.close(fd)
    os.chmod(path, 0o644)
    o = Observer("x:1", binary=path)
    try:
        o.overview()
        check(False, "should have raised")
    except ObserverError as exc:
        check(os.path.basename(path) in str(exc), "names the binary that could not be run")
    except OSError as exc:
        check(False, f"leaked a raw {type(exc).__name__}: {exc}")


def test_garbage_output_is_explained():
    print("explains unparseable output")
    o = Observer("x:1", binary=fake_binary("this is not json"))
    try:
        o.overview()
        check(False, "should have raised")
    except ObserverError as exc:
        check("JSON" in str(exc), "names the real problem")


def test_derived_stats():
    # Numbers a reader wants that the raw counters do not state outright.
    print("derives the numbers the raw counters do not state")
    from observer import derived_stats
    d = derived_stats(json.loads(SAMPLE))
    check(d["keyed_topics"] == 1 and d["open_topics"] == 1, "splits keyed from open")
    check(d["largest_topic"] == 50, "finds the largest topic")
    check(d["listed_peers"] == 52, "sums peers")


def test_deployment_info():
    # The watcher writes the sha only after tests passed and the service came
    # up, so this names the commit actually serving.
    print("reads the deployed commit")
    from observer import deployment_info
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "deployed.sha"), "w") as fh:
        fh.write("abc123def4567890\n")
    with open(os.path.join(d, "deployed.subject"), "w") as fh:
        fh.write("a commit subject\n")
    i = deployment_info(os.path.join(d, "deployed.sha"))
    check(i["short"] == "abc123d", "shortens the sha")
    check(i["subject"] == "a commit subject", "reads the subject without running git")
    check(i["attempt"] is None, "no deploy.status: no attempt to report")
    check(deployment_info("/nonexistent/x")["short"] is None,
          "a missing file is not an error")


def test_deploy_attempt():
    # A commit the watcher refused is never retried, so the deployed sha just
    # stays put: without the watcher's deploy.status, a failed deploy looked
    # exactly like no new commit.
    print("reports the newest deploy attempt")
    from observer import deployment_info
    d = tempfile.mkdtemp()
    sha_file = os.path.join(d, "deployed.sha")
    status = os.path.join(d, "deploy.status")
    with open(sha_file, "w") as fh:
        fh.write("abc123def4567890\n")

    with open(status, "w") as fh:
        json.dump({"sha": "fedcba9876543210", "state": "failed", "detail": "tests failed",
                   "time": time.time() - 90}, fh)
    a = deployment_info(sha_file)["attempt"]
    check(a["short"] == "fedcba9" and a["state"] == "failed", "reads a refused commit")
    check(a["detail"] == "tests failed", "and why it was refused")
    check(85 <= a["age_s"] <= 95, f"and how long ago ({a['age_s']}s)")

    with open(status, "w") as fh:
        json.dump({"sha": "fedcba9876543210", "state": "testing",
                   "detail": "running the test suite", "time": time.time()}, fh)
    check(deployment_info(sha_file)["attempt"]["state"] == "testing", "reads one in progress")

    for broken in ("not json", "[1, 2]", '{"state": "failed", "time": "soon"}'):
        with open(status, "w") as fh:
            fh.write(broken)
        try:
            info = deployment_info(sha_file)
            check(info["attempt"] is None and info["short"] == "abc123d",
                  f"ignores a broken status file {broken[:14]!r}")
        except Exception as exc:  # noqa: BLE001 -- any exception is the failure
            check(False, f"a broken status file raised {type(exc).__name__}")

    # A first deploy that failed: there is no deployed.sha yet, but there is
    # an attempt to report.
    d2 = tempfile.mkdtemp()
    with open(os.path.join(d2, "deploy.status"), "w") as fh:
        json.dump({"sha": "0123456789abcdef", "state": "failed", "detail": "build failed",
                   "time": time.time()}, fh)
    i = deployment_info(os.path.join(d2, "deployed.sha"))
    check(i["short"] is None and i["attempt"]["state"] == "failed",
          "reports a failed first deploy, with nothing deployed")


def test_reports_when_data_was_fetched():
    # A quiet server and a dashboard that has stopped updating look the same
    # unless the page says how old its numbers are.
    print("says when the data was fetched")
    o = Observer("x:1", binary=fake_binary(SAMPLE), ttl=10.0)
    before = time.time()
    data, _, _ = o.overview()
    check(before - 1 <= data.get("fetched_at", 0) <= time.time() + 1, "stamps a fresh answer")
    again, _, _ = o.overview()
    check(again["fetched_at"] == data["fetched_at"], "a cached answer keeps its original time")

    o.ttl = 0.0
    o.binary = fake_binary(json.dumps({"ok": False, "error": "server unreachable"}))
    stale, is_stale, _ = o.overview()
    check(is_stale and stale["fetched_at"] == data["fetched_at"],
          "stale data keeps the time it was really fetched")


def test_node_connections_exclude_the_observer():
    print("does not count its own connection as a node")
    from observer import derived_stats
    d = derived_stats({"stats": {"connections": 3}, "topics": []})
    check(d["node_connections"] == 2, "three connections, one of them ours: two nodes")
    check(derived_stats({"stats": {"connections": 1}, "topics": []})["node_connections"] == 0,
          "an idle server has no node connections")
    check(derived_stats({"topics": []})["node_connections"] == 0, "no stats: zero, not -1")


def test_ago():
    print("words an age")
    from observer import ago
    check(ago(0) == "just now" and ago(None) == "?", "edges")
    check(ago(42) == "42s ago" and ago(600) == "10 min ago" and ago(10800) == "3 h ago",
          "seconds, minutes, hours")


if __name__ == "__main__":
    for fn in [
        test_parses_and_summarises,
        test_reports_sampling,
        test_cache_prevents_hammering,
        test_serves_stale_on_failure,
        test_first_failure_raises,
        test_rejects_bad_topic_ids,
        test_topic_cache_is_bounded,
        test_concurrent_misses_run_once,
        test_missing_binary_is_explained,
        test_unrunnable_binary_is_explained,
        test_garbage_output_is_explained,
        test_derived_stats,
        test_deployment_info,
        test_deploy_attempt,
        test_reports_when_data_was_fetched,
        test_node_connections_exclude_the_observer,
        test_ago,
    ]:
        fn()
    print()
    print("FAILED" if FAILED else "all web tests passed")
    sys.exit(1 if FAILED else 0)
