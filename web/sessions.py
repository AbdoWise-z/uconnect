"""Session tracking and per-IP limits for the interactive app.

No login: a session is a random id in a cookie, and that is the whole identity
model. It exists to bound resource use, not to authenticate anyone -- nothing
here decides what a visitor may see, because everything the dashboard shows is
public anyway.

Flask-free so the limits can be tested without a web server. Single-process
state, which is why the gunicorn unit runs one worker: with several workers
each would keep its own counts and the per-IP limit would be the limit times
the worker count.
"""

from __future__ import annotations

import os
import secrets
import threading
import time
from dataclasses import dataclass, field


@dataclass
class Session:
    sid: str
    ip: str
    created: float
    last_seen: float
    streams: int = 0
    # Topics created in this session, newest first. Ids only -- the key is
    # generated in the browser and never sent here, so there is nothing secret
    # to keep.
    topics: list[str] = field(default_factory=list)


class LimitError(RuntimeError):
    """Raised when a limit would be exceeded. The message is shown to the user."""


class SessionRegistry:
    """Caps sessions per IP, and live event streams globally.

    Two different limits because they protect two different things. Sessions are
    cheap (a dict entry) and the cap is about stopping one host from farming
    identities. A live stream is expensive -- it pins a server thread for as
    long as the browser is open -- so that one is capped globally as well, or a
    handful of visitors could exhaust the worker pool and take the whole
    dashboard down without any of them meaning to.
    """

    def __init__(
        self,
        max_per_ip: int = 10,
        idle_timeout: float = 1800.0,
        max_total_streams: int = 24,
        max_streams_per_session: int = 2,
        max_topics_per_session: int = 20,
    ) -> None:
        self.max_per_ip = max_per_ip
        self.idle_timeout = idle_timeout
        self.max_total_streams = max_total_streams
        self.max_streams_per_session = max_streams_per_session
        self.max_topics_per_session = max_topics_per_session

        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}
        self._live_streams = 0

    # --- internals ---------------------------------------------------------
    def _reap(self, now: float) -> None:
        """Drop idle sessions. Called under the lock on every touch.

        Without this the per-IP cap becomes permanent: ten visits from an office
        NAT would lock everyone behind it out forever, which is a denial of
        service implemented by the thing meant to prevent one.
        """
        dead = [s for s in self._sessions.values()
                if now - s.last_seen > self.idle_timeout and s.streams == 0]
        for s in dead:
            self._sessions.pop(s.sid, None)

    def _count_for_ip(self, ip: str) -> int:
        return sum(1 for s in self._sessions.values() if s.ip == ip)

    # --- public API --------------------------------------------------------
    def touch(self, sid: str | None, ip: str) -> Session:
        """Return the session for `sid`, creating one if needed.

        Raises LimitError if this IP already holds max_per_ip sessions.
        """
        now = time.monotonic()
        with self._lock:
            self._reap(now)

            if sid and sid in self._sessions:
                s = self._sessions[sid]
                # A cookie is not proof of anything, but it is not a credential
                # here either -- it only names a bucket. Rebinding it to the
                # current address keeps a roaming client from being counted
                # twice rather than defending against anything.
                s.ip = ip
                s.last_seen = now
                return s

            if self._count_for_ip(ip) >= self.max_per_ip:
                raise LimitError(
                    f"too many sessions from this address ({self.max_per_ip}). "
                    f"Close a tab, or wait for an idle one to expire."
                )

            s = Session(sid=secrets.token_urlsafe(18), ip=ip, created=now, last_seen=now)
            self._sessions[s.sid] = s
            return s

    def open_stream(self, sid: str) -> None:
        with self._lock:
            s = self._sessions.get(sid)
            if s is None:
                raise LimitError("session expired; reload the page")
            if self._live_streams >= self.max_total_streams:
                raise LimitError("the live feed is at capacity; try again shortly")
            if s.streams >= self.max_streams_per_session:
                raise LimitError("this session already has a live feed open")
            s.streams += 1
            self._live_streams += 1

    def close_stream(self, sid: str) -> None:
        with self._lock:
            s = self._sessions.get(sid)
            if s and s.streams > 0:
                s.streams -= 1
            # Decrement the global count even when the session is gone, or a
            # session reaped mid-stream would leak a slot permanently and the
            # feed would slowly close itself to everyone.
            if self._live_streams > 0:
                self._live_streams -= 1

    def record_topic(self, sid: str, topic_id: str) -> None:
        with self._lock:
            s = self._sessions.get(sid)
            if s is None:
                raise LimitError("session expired; reload the page")
            # Idempotent first, capped second. Re-recording an id already held
            # adds nothing, so refusing it at the cap would turn a page reload
            # or a client retry into an error for a no-op.
            if topic_id in s.topics:
                return
            if len(s.topics) >= self.max_topics_per_session:
                raise LimitError(
                    f"this session has created {self.max_topics_per_session} topics already"
                )
            s.topics.insert(0, topic_id)

    def stats(self) -> dict:
        now = time.monotonic()
        with self._lock:
            self._reap(now)
            ips = {s.ip for s in self._sessions.values()}
            return {
                "sessions": len(self._sessions),
                "unique_ips": len(ips),
                "live_streams": self._live_streams,
                "max_per_ip": self.max_per_ip,
                "max_total_streams": self.max_total_streams,
            }


def client_ip(headers, remote_addr: str | None, trust_proxy: bool = False) -> str:
    """The address to count against.

    X-Forwarded-For is only honoured when explicitly enabled. It is a header,
    so anyone can send one -- trusting it by default would turn the per-IP limit
    into a suggestion, since an attacker could present a fresh address on every
    request. Enable it only when something in front is known to overwrite it.
    """
    if trust_proxy:
        fwd = headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return remote_addr or "unknown"


def trust_proxy_enabled() -> bool:
    return os.environ.get("UCONNECT_TRUST_PROXY", "").lower() in ("1", "true", "yes")
