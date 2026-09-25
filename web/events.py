"""Turns periodic snapshots of the rendezvous server into a live event feed.

What can and cannot be observed is set by the protocol, not by this file. Peer
traffic is end-to-end encrypted and never reaches the rendezvous server, so
there is no way to stream message contents and there never will be. What the
server does see, and therefore what this publishes, is *signaling*: who
registered, who went away, which topics exist, and how much the relay carried.

One poller for everyone. Each browser gets its own queue but not its own
lookups -- N viewers must not mean N times the load on the server they are
watching, or the dashboard becomes the thing that takes it down.
"""

from __future__ import annotations

import queue
import threading
import time
from typing import Any

from observer import Observer, ObserverError


class EventHub:
    def __init__(self, observer: Observer, interval: float = 3.0, backlog: int = 64) -> None:
        self.observer = observer
        self.interval = interval
        self.backlog = backlog

        self._lock = threading.Lock()
        self._subscribers: set[queue.Queue] = set()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

        self._prev: dict[str, Any] | None = None
        self._recent: list[dict] = []     # replayed to a new subscriber
        self._seq = 0

    # --- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    # --- subscription ------------------------------------------------------
    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=self.backlog)
        with self._lock:
            self._subscribers.add(q)
            history = list(self._recent[-20:])
        for ev in history:
            try:
                q.put_nowait(ev)
            except queue.Full:
                break
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            self._subscribers.discard(q)

    # --- publishing --------------------------------------------------------
    def _publish(self, kind: str, **fields) -> None:
        self._seq += 1
        ev = {"seq": self._seq, "kind": kind, "at": time.time(), **fields}

        with self._lock:
            self._recent.append(ev)
            if len(self._recent) > 100:
                del self._recent[: len(self._recent) - 100]
            subs = list(self._subscribers)

        for q in subs:
            try:
                q.put_nowait(ev)
            except queue.Full:
                # A browser that stopped reading must not be able to grow this
                # process's memory. Dropping the event is right: the feed is a
                # live view, not a ledger, and the next snapshot re-states the
                # world anyway.
                pass

    # --- the poll loop -----------------------------------------------------
    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                data, stale, _ = self.observer.overview(members=True)
                if not stale:
                    self._diff(data)
            except ObserverError as exc:
                self._publish("error", message=str(exc))
            self._stop.wait(self.interval)

    def _diff(self, data: dict) -> None:
        """Emit what changed since the previous snapshot."""
        cur_topics = {t["id"]: t for t in data.get("topics", [])}

        if self._prev is None:
            # First snapshot is the baseline, not a burst of "everything
            # appeared" -- a viewer opening the page should not see a hundred
            # join events for peers that have been there for hours.
            self._prev = {"topics": cur_topics, "stats": data.get("stats") or {}}
            self._publish("ready", topics=len(cur_topics))
            return

        prev_topics: dict = self._prev["topics"]

        for tid, t in cur_topics.items():
            if tid not in prev_topics:
                self._publish("topic_new", topic=tid, mode=t.get("mode"),
                              peers=t.get("peers", 0))

        for tid in prev_topics:
            if tid not in cur_topics:
                self._publish("topic_gone", topic=tid)

        for tid, t in cur_topics.items():
            old = prev_topics.get(tid)
            if not old:
                continue
            now_members = {m["dev_id"]: m for m in t.get("members", [])}
            old_members = {m["dev_id"]: m for m in old.get("members", [])}

            # Only meaningful when the whole membership was returned. LOOKUP
            # samples, so on a big topic a peer can drop out of one sample and
            # back into the next without having gone anywhere -- reporting that
            # as join/leave would be pure noise.
            sampled = len(t.get("members", [])) < t.get("peers", 0)
            if not sampled:
                for dev, m in now_members.items():
                    if dev not in old_members:
                        self._publish("peer_join", topic=tid, dev_id=dev,
                                      name=m.get("meta_text"))
                for dev, m in old_members.items():
                    if dev not in now_members:
                        self._publish("peer_leave", topic=tid, dev_id=dev,
                                      name=m.get("meta_text"))

            if t.get("peers") != old.get("peers"):
                self._publish("topic_count", topic=tid, peers=t.get("peers", 0),
                              fresh=t.get("fresh_peers", 0))

        # Counter deltas. These are the only view of activity between peers the
        # server can honestly offer: it sees that a lookup happened, never what
        # was said afterwards.
        cur_stats = data.get("stats") or {}
        old_stats = self._prev.get("stats") or {}
        deltas = {
            k: cur_stats[k] - old_stats.get(k, 0)
            for k in ("registers", "keepalives", "lookups", "connects", "rebinds",
                      "expired", "relay_bytes", "relays_allocated")
            if k in cur_stats and cur_stats[k] != old_stats.get(k, 0)
        }
        if deltas:
            self._publish("activity", deltas=deltas)

        self._prev = {"topics": cur_topics, "stats": cur_stats}
