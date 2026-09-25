"""Runs uconn-bridge processes on behalf of browsers.

A browser cannot be a uConnect peer -- no UDP socket, no hole punching, no
Noise handshake -- so chatting from a page means something on this host joins
the topic and relays. That something is `uconn-bridge`, one process per chat
session.

The cost is not hideable and is not this file's to hide: whatever runs the
handshake must hold K, so a web chat trusts this host with the topic key, and
this host can read every message in that topic. Native clients do not make
that trade. The UI says so before anyone types.

Bridges are far more expensive than anything else here -- each is a real UDP
node that registers, punches and holds a session -- so they are capped hard,
given a lifetime, and reaped when the browser goes away.
"""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import threading
import time


class ChatError(RuntimeError):
    pass


def _default_binary() -> str:
    env = os.environ.get("UCONNECT_BRIDGE")
    if env:
        return env
    found = shutil.which("uconn-bridge")
    if found:
        return found
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for c in (os.path.join(root, "build", "tools", "uconn-bridge"),
              os.path.join(root, "build", "tools", "uconn-bridge.exe")):
        if os.path.exists(c):
            return c
    return "uconn-bridge"


class Bridge:
    """One live topic membership, owned by one session."""

    def __init__(self, proc: subprocess.Popen, topic_id: str, nick: str, backlog: int = 256):
        self.proc = proc
        self.topic_id = topic_id
        self.nick = nick
        self.started = time.monotonic()
        self.dev_id: str | None = None

        self._lock = threading.Lock()
        self._subs: set[queue.Queue] = set()
        self._recent: list[dict] = []
        self.backlog = backlog

        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()

    # --- fan-out -----------------------------------------------------------
    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=self.backlog)
        with self._lock:
            self._subs.add(q)
            history = list(self._recent)
        # Replay what has happened so far. A second tab, or a reconnect after a
        # dropped stream, should see the conversation rather than an empty box
        # with no way to scroll back.
        for ev in history:
            try:
                q.put_nowait(ev)
            except queue.Full:
                break
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            self._subs.discard(q)

    def _publish(self, ev: dict) -> None:
        with self._lock:
            self._recent.append(ev)
            if len(self._recent) > 200:
                del self._recent[: len(self._recent) - 200]
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(ev)
            except queue.Full:
                pass

    def _pump(self) -> None:
        try:
            for raw in self.proc.stdout:  # type: ignore[union-attr]
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    ev = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if ev.get("t") == "ready":
                    self.dev_id = ev.get("dev")
                self._publish(ev)
        except (OSError, ValueError):
            pass
        finally:
            self._publish({"t": "closed"})

    # --- commands ----------------------------------------------------------
    def say(self, text: str) -> None:
        if self.proc.poll() is not None:
            raise ChatError("this chat session has ended; rejoin to continue")
        try:
            assert self.proc.stdin is not None
            self.proc.stdin.write(json.dumps({"cmd": "say", "text": text}) + "\n")
            self.proc.stdin.flush()
        except (OSError, ValueError) as exc:
            raise ChatError("chat session closed") from exc

    def alive(self) -> bool:
        return self.proc.poll() is None

    def stop(self) -> None:
        try:
            if self.proc.stdin and not self.proc.stdin.closed:
                self.proc.stdin.write('{"cmd":"bye"}\n')
                self.proc.stdin.flush()
                self.proc.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            # It owes the topic a Bye but not indefinitely.
            self.proc.kill()


class BridgeManager:
    def __init__(self, server: str, binary: str | None = None,
                 max_total: int = 8, lifetime: int = 1800) -> None:
        self.server = server
        self.binary = binary or _default_binary()
        self.max_total = max_total
        self.lifetime = lifetime

        self._lock = threading.Lock()
        self._bridges: dict[str, Bridge] = {}

    def _reap(self) -> None:
        """Drop finished bridges. Called under the lock."""
        for sid, b in list(self._bridges.items()):
            if not b.alive():
                self._bridges.pop(sid, None)

    def start(self, sid: str, topic_uri: str, nick: str) -> Bridge:
        topic_uri = topic_uri.strip()
        if not topic_uri.startswith("uconn://"):
            raise ChatError("that does not look like a uconn:// topic URI")
        if len(topic_uri) > 200 or "\n" in topic_uri or "\r" in topic_uri:
            # It is written to the process's stdin as a single line, so a
            # newline would be read as a command rather than as part of the URI.
            raise ChatError("malformed topic URI")

        body = topic_uri[len("uconn://"):]
        tid = body.split("#", 1)[0].lower()
        if len(tid) != 32 or any(c not in "0123456789abcdef" for c in tid):
            raise ChatError("topic id must be 32 hex characters")

        nick = "".join(c for c in nick if c.isprintable())[:24].strip() or "web"

        with self._lock:
            self._reap()
            old = self._bridges.pop(sid, None)
            if old is None and len(self._bridges) >= self.max_total:
                raise ChatError(
                    f"the chat gateway is full ({self.max_total} sessions). "
                    f"Use a native client -- it is faster, and it does not hand "
                    f"the topic key to this server."
                )
        if old is not None:
            old.stop()

        try:
            proc = subprocess.Popen(
                [self.binary, "--server", self.server, "--nick", nick,
                 "--seconds", str(self.lifetime)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, bufsize=1,
            )
        except FileNotFoundError as exc:
            raise ChatError(
                f"uconn-bridge not found at {self.binary!r}; build it or set UCONNECT_BRIDGE"
            ) from exc

        # The URI -- key and all -- goes on stdin, never argv. argv is visible
        # in `ps` to every user on the box, and a key in a process listing is a
        # key in logs, monitoring and support tickets.
        try:
            assert proc.stdin is not None
            proc.stdin.write(topic_uri + "\n")
            proc.stdin.flush()
        except (OSError, ValueError) as exc:
            proc.kill()
            raise ChatError("could not start the chat bridge") from exc

        b = Bridge(proc, tid, nick)
        with self._lock:
            self._bridges[sid] = b
        return b

    def get(self, sid: str) -> Bridge | None:
        with self._lock:
            self._reap()
            return self._bridges.get(sid)

    def stop(self, sid: str) -> None:
        with self._lock:
            b = self._bridges.pop(sid, None)
        if b:
            b.stop()

    def stats(self) -> dict:
        with self._lock:
            self._reap()
            return {"chats": len(self._bridges), "max_chats": self.max_total}
