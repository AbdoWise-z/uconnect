"""Data layer for the uConnect dashboard.

Deliberately free of Flask imports so it can be exercised without a web server,
and so the part that talks to the rendezvous server stays testable on its own.

The dashboard never speaks the uConnect wire protocol. It shells out to
`uconn-observe`, which links the real library and prints JSON. A second
implementation of the framing in Python would drift from the C++ one the first
time a field moved, and the symptom would be a quietly wrong dashboard rather
than a build error.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
from collections import OrderedDict
from typing import Any

__all__ = [
    "Observer",
    "ObserverError",
    "summarise",
    "derived_stats",
    "deployment_info",
    "ago",
]


def ago(seconds: float | None) -> str:
    """'just now', '42s ago', '7 min ago', '3 h ago'."""
    if seconds is None:
        return "?"
    s = max(0, int(seconds))
    if s < 2:
        return "just now"
    if s < 120:
        return f"{s}s ago"
    if s < 7200:
        return f"{s // 60} min ago"
    return f"{s // 3600} h ago"


class ObserverError(RuntimeError):
    pass


class _Flight:
    """One lookup in progress, and what it came to, for those waiting on it."""

    def __init__(self) -> None:
        self.done = threading.Event()
        self.result: tuple[dict, bool, str | None] | None = None
        self.error: ObserverError | None = None


def _default_binary() -> str:
    """Find uconn-observe: $UCONNECT_OBSERVE, then PATH, then the build tree."""
    env = os.environ.get("UCONNECT_OBSERVE")
    if env:
        return env

    found = shutil.which("uconn-observe")
    if found:
        return found

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for candidate in (
        os.path.join(root, "build", "tools", "uconn-observe"),
        os.path.join(root, "build", "tools", "uconn-observe.exe"),
    ):
        if os.path.exists(candidate):
            return candidate
    return "uconn-observe"


class Observer:
    """Runs uconn-observe and caches the result.

    Caching is not an optimisation, it is a requirement. The rendezvous server
    rate-limits per source IP measured in bytes returned, and a LOOKUP for every
    topic is the most expensive thing it serves. A dashboard left open on a
    short auto-refresh would otherwise get itself throttled and report an
    outage it caused.
    """

    # Per-topic answers held at most, least recently asked going first.
    TOPIC_CACHE = 256

    def __init__(
        self,
        server: str,
        binary: str | None = None,
        ttl: float = 5.0,
        timeout: float = 15.0,
        limit: int = 30,
    ) -> None:
        self.server = server
        self.binary = binary or _default_binary()
        self.ttl = ttl
        self.timeout = timeout
        self.limit = limit

        self._lock = threading.Lock()
        # key -> (monotonic time, wall time, data) of the last good answer,
        # least recently used first
        self._cache: OrderedDict[str, tuple[float, float, Any]] = OrderedDict()
        # key -> the one lookup in progress for it, which later askers join
        self._inflight: dict[str, _Flight] = {}

    # --- process plumbing --------------------------------------------------
    def _run(self, args: list[str]) -> dict:
        cmd = [self.binary, "--server", self.server, "--limit", str(self.limit)] + args
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except FileNotFoundError as exc:
            raise ObserverError(
                f"uconn-observe not found at {self.binary!r}. Build it, or set "
                f"UCONNECT_OBSERVE to its path."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise ObserverError(
                f"uconn-observe timed out after {self.timeout}s -- is {self.server} reachable?"
            ) from exc
        except OSError as exc:
            # Present but not runnable: no execute bit, or not an executable
            # for this platform. Raised as ObserverError like every other
            # failure, so the dashboard explains it or serves stale data
            # rather than answering with a 500.
            raise ObserverError(f"could not run uconn-observe at {self.binary!r}: {exc}") from exc

        # The tool reports failure as JSON on stdout precisely so a dashboard can
        # tell "the server says there is nothing" from "we could not reach it".
        # An empty body with a non-zero exit cannot carry that distinction, so
        # only treat it as fatal when there is genuinely nothing to parse.
        if not proc.stdout.strip():
            detail = proc.stderr.strip() or f"exit {proc.returncode}"
            raise ObserverError(f"uconn-observe produced no output ({detail})")

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise ObserverError(f"uconn-observe emitted invalid JSON: {exc}") from exc

        if not data.get("ok", False):
            raise ObserverError(data.get("error", "unknown error"))
        return data

    def _cached(self, key: str, args: list[str]) -> tuple[dict, bool, str | None]:
        """Return (data, is_stale, error).

        On failure the last good value is served with is_stale set, rather than
        blanking the page. A rendezvous server restarting, or one lookup hitting
        the rate limiter, should not wipe a dashboard that was correct a moment
        ago -- but it must be visibly old rather than quietly wrong.

        The data carries `fetched_at`, the wall-clock time the server answered,
        so a page can say how old it is: a quiet server and a dashboard that
        has stopped updating otherwise look exactly alike.
        """
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(key)
            if hit:
                self._cache.move_to_end(key)
            if hit and now - hit[0] < self.ttl:
                return {**hit[2], "fetched_at": hit[1]}, False, None
            # One lookup per key at a time: simultaneous misses wait for the
            # one already running instead of each starting uconn-observe (#34).
            flight = self._inflight.get(key)
            leader = flight is None
            if leader:
                flight = self._inflight[key] = _Flight()

        if not leader:
            flight.done.wait()
            if flight.error is not None:
                raise flight.error
            return flight.result

        try:
            flight.result = self._fetch(key, args, now)
            return flight.result
        except ObserverError as exc:
            flight.error = exc
            raise
        finally:
            with self._lock:
                del self._inflight[key]
            flight.done.set()

    def _fetch(self, key: str, args: list[str], now: float) -> tuple[dict, bool, str | None]:
        try:
            data = self._run(args)
        except ObserverError as exc:
            with self._lock:
                hit = self._cache.get(key)
            if hit:
                return {**hit[2], "fetched_at": hit[1]}, True, str(exc)
            raise

        wall = time.time()
        with self._lock:
            self._cache[key] = (now, wall, data)
            self._cache.move_to_end(key)
            # Any 32-hex id is a valid request, so per-topic answers are held
            # only for the most recently asked: unbounded, random ids grew the
            # cache until the service ran out of memory (#34). The overviews
            # are two keys at most, and never pushed out by topics.
            topics = [k for k in self._cache if k.startswith("topic:")]
            for old in topics[: max(0, len(topics) - self.TOPIC_CACHE)]:
                del self._cache[old]
        return {**data, "fetched_at": wall}, False, None

    # --- public API --------------------------------------------------------
    def overview(self, members: bool = True) -> tuple[dict, bool, str | None]:
        """Server stats plus every listed topic, optionally with its members."""
        args = ["--members"] if members else []
        return self._cached(f"overview:{members}", args)

    def topic(self, topic_id: str) -> tuple[dict, bool, str | None]:
        """One topic's members, by hex id. Works for unlisted topics too.

        That is not a backdoor: LOOKUP is keyed by topic_id alone and needs no
        proof of anything, so this exposes nothing a peer could not already ask
        for. "Unlisted" means absent from the directory, not secret.
        """
        topic_id = topic_id.strip().lower()
        if len(topic_id) != 32 or any(c not in "0123456789abcdef" for c in topic_id):
            raise ObserverError("topic id must be 32 hex characters")
        return self._cached(f"topic:{topic_id}", ["--topic", topic_id])


def deployment_info(sha_path: str | None = None) -> dict:
    """What commit the running deployment was built from, and how the newest
    deploy attempt went.

    The watcher writes the sha only after the build passed its tests and the
    service came up, so this is the commit actually serving, not merely the
    newest one pushed. That distinction is the entire reason to show it.

    `attempt` is the watcher's deploy.status beside it -- building, testing,
    failed (with why) or deployed -- or None. Without it a commit the watcher
    refused looks exactly like no new commit at all, since the sha above just
    stays where it was.
    """
    sha_path = sha_path or os.environ.get("UCONNECT_SHA_FILE", "/opt/uconnect/deployed.sha")
    info: dict[str, Any] = {"sha": None, "short": None, "subject": None, "url": None,
                            "attempt": None}
    folder = os.path.dirname(sha_path)
    try:
        with open(sha_path) as fh:
            sha = fh.read().strip()
        if sha:
            info["sha"] = sha
            info["short"] = sha[:7]
            info["url"] = f"https://github.com/AbdoWise-z/uconnect/commit/{sha}"
            info["age_s"] = int(time.time() - os.path.getmtime(sha_path))
    except OSError:
        pass

    # Written by the watcher next to the sha. Deliberately not a git call: this
    # process runs as its own unprivileged user and the source tree is
    # root-owned, so git trips the dubious-ownership guard and returns nothing
    # -- indistinguishable, from here, from a commit with no subject.
    if info["sha"]:
        try:
            with open(os.path.join(folder, "deployed.subject")) as fh:
                info["subject"] = fh.read().strip() or None
        except OSError:
            pass

    try:
        with open(os.path.join(folder, "deploy.status")) as fh:
            st = json.load(fh)
        sha = str(st.get("sha") or "")
        info["attempt"] = {
            "sha": sha or None,
            "short": sha[:7] or None,
            "state": st.get("state"),
            "detail": st.get("detail") or None,
            "age_s": max(0, int(time.time() - float(st["time"]))) if st.get("time") else None,
        }
    except (OSError, ValueError, TypeError, AttributeError):
        pass  # absent (an older watcher) or unreadable: no attempt to report
    return info


def derived_stats(data: dict) -> dict:
    """Numbers a reader wants that the raw counters do not state outright."""
    s = data.get("stats") or {}
    topics = data.get("topics", [])

    peers = sum(t.get("peers", 0) for t in topics)
    fresh = sum(t.get("fresh_peers", 0) for t in topics)
    keyed = sum(1 for t in topics if t.get("mode") == "keyed")

    total_records = s.get("entries_total", 0)
    fresh_records = s.get("entries_fresh", 0)
    rejects = s.get("rej_quota", 0) + s.get("rej_rate_limited", 0)

    return {
        # The server counts every open control connection, and the one that
        # asked for these numbers is uconn-observe's own. An idle server
        # reported "1 connection" -- this dashboard.
        "node_connections": max(0, s.get("connections", 0) - 1) if s else 0,
        "listed_peers": peers,
        "listed_fresh": fresh,
        "keyed_topics": keyed,
        "open_topics": len(topics) - keyed,
        # Records past the 45s freshness line: their node's connection is still
        # open, but it has not refreshed the record, so its addresses may be
        # out of date. A climbing number here is the early symptom of clients
        # that have stopped sending keepalives.
        "stale_records": max(0, total_records - fresh_records),
        "largest_topic": max((t.get("peers", 0) for t in topics), default=0),
        "avg_peers_per_topic": round(peers / len(topics), 1) if topics else 0,
        "relay_share": (
            round(100.0 * s.get("relays_allocated", 0) / s["registers"], 1)
            if s.get("registers") else 0.0
        ),
        "relay_mib": round(s.get("relay_bytes", 0) / (1024 * 1024), 2),
        "rejects_total": rejects,
    }


def summarise(data: dict) -> dict:
    """Flatten the observer's output into what a template wants.

    Derives the one number the raw feed does not carry: how many of a topic's
    members the server actually returned. LOOKUP samples rather than
    enumerating -- capped at 30 by default, 100 at most -- so a 500-peer topic
    reports 500 peers and lists 30 of them, and a dashboard that did not say so
    would look like it was losing records.
    """
    topics = []
    for t in data.get("topics", []):
        members = t.get("members", [])
        topics.append(
            {
                "id": t["id"],
                "short": t["id"][:12],
                "mode": t.get("mode", "open"),
                "keyed": t.get("mode") == "keyed",
                "peers": t.get("peers", 0),
                "fresh_peers": t.get("fresh_peers", 0),
                "members": members,
                "shown": len(members),
                "sampled": len(members) < t.get("peers", 0),
            }
        )
    topics.sort(key=lambda t: (-t["peers"], t["id"]))
    return {
        "server": data.get("server", ""),
        "stats": data.get("stats"),
        "topics": topics,
        "topic_count": len(topics),
        "peer_count": sum(t["peers"] for t in topics),
        "derived": derived_stats(data),
    }
