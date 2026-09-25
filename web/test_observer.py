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
    check(deployment_info("/nonexistent/x")["short"] is None,
          "a missing file is not an error")


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
        test_derived_stats,
        test_deployment_info,
    ]:
        fn()
    print()
    print("FAILED" if FAILED else "all web tests passed")
    sys.exit(1 if FAILED else 0)
