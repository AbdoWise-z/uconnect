#!/usr/bin/env python3
"""demo.py -- uconn-demo, in Python, over the C API.

    python demo.py --server 127.0.0.1:4433 --create
        prints a uconn:// URI

    python demo.py --server 127.0.0.1:4433 --topic uconn://<id>#<key> --name bob
        joins, publishes, connects to everyone, and greets each peer

Like uconn-demo it publishes, looks the topic up, connects to every peer it
finds, and sends each one a greeting once connected. Unlike it, every event --
a peer's state, a message, a goodbye -- arrives through the C API's event
queue, drained here on the main thread, not through callbacks.

Exits 0 once it has received at least one message, 3 if it never did.
"""

import argparse
import sys
import time

import uconnect
from uconnect import EventKind, PeerState


def short(dev: bytes) -> str:
    return dev.hex()[:8]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--server", required=True, help="rendezvous server, host:port")
    ap.add_argument("--topic", help="uconn:// URI of the topic to join")
    ap.add_argument("--create", action="store_true", help="generate a keyed topic, print its URI")
    ap.add_argument("--name", default="anon", help="name announced in metadata")
    ap.add_argument("--seconds", type=float, default=20, help="how long to run")
    ap.add_argument("--stats", action="store_true", help="print server stats and exit")
    args = ap.parse_args()

    def say(line: str) -> None:
        print(f"[{args.name}] {line}", flush=True)

    if args.create:
        print(f"\n  topic: {uconnect.Creds.generate(keyed=True).to_uri()}\n", flush=True)
        return 0

    with uconnect.Node(args.server) as node:
        node.run_in_background()

        if args.stats:
            stats = node.stats()
            if stats is None:
                print("no reply from server", file=sys.stderr)
                return 1
            print(" ".join(f"{k}={v}" for k, v in stats.items()))
            return 0

        if not args.topic:
            print("need --topic or --create", file=sys.stderr)
            return 2
        topic = node.join(uconnect.Creds.parse(args.topic))
        topic.queue_events()
        say(f"topic {topic.id.hex()} "
            f"({'keyed, mutually authenticated' if topic.is_authenticated() else 'OPEN'})")

        if not topic.publish(args.name.encode()):
            say("publish failed (is the server running?)")
            return 1
        say(f"published as {short(topic.self_id() or b'')}")

        received = 0
        greeting = f"hello from {args.name}".encode()
        deadline = time.monotonic() + args.seconds
        next_lookup = 0.0

        while time.monotonic() < deadline:
            # Every couple of seconds, dial whoever the topic has that we
            # have not tried yet.
            if time.monotonic() >= next_lookup:
                for p in topic.peers() or []:
                    if not p.stale and topic.state(p.dev_id) == PeerState.UNKNOWN:
                        topic.connect(p.dev_id)
                next_lookup = time.monotonic() + 2

            ev = node.next_event(timeout_ms=200)
            if ev is None:
                continue
            if ev.kind == EventKind.PEER:
                say(f"peer {short(ev.dev)} -> {uconnect.peer_state_name(ev.peer_state)}")
                if ev.peer_state == PeerState.CONNECTED and topic.send(ev.dev, greeting):
                    say(f"-> {short(ev.dev)}: {greeting.decode()}")
            elif ev.kind == EventKind.DATA:
                say(f"<- {short(ev.dev)}: {ev.data.decode('utf-8', 'replace')}")
                received += 1
            elif ev.kind == EventKind.PEER_CLOSED:
                # A goodbye and a disappearance read differently: only this
                # event says which it was.
                say(f"peer {short(ev.dev)} gone: {uconnect.peer_gone_name(ev.peer_gone)}")

        say(f"done: {received} message(s) received, {len(topic.connected())} peer(s) connected")
        node.shutdown()
        return 0 if received > 0 else 3


if __name__ == "__main__":
    sys.exit(main())
