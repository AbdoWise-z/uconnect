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
from typing import Any


class ObserverError(RuntimeError):
    pass


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
        self._cache: dict[str, tuple[float, Any]] = {}

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
        """
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(key)
            if hit and now - hit[0] < self.ttl:
                return hit[1], False, None

        try:
            data = self._run(args)
        except ObserverError as exc:
            with self._lock:
                hit = self._cache.get(key)
            if hit:
                return hit[1], True, str(exc)
            raise

        with self._lock:
            self._cache[key] = (now, data)
        return data, False, None

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
    }
