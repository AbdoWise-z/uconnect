# uConnect dashboard

A read-only web view of a rendezvous server: which topics exist, who is
registered in them, and what the server's own counters say.

```sh
cmake --build build --target uconn-observe     # once
pip install -r web/requirements.txt
UCONNECT_SERVER=127.0.0.1:4433 python web/app.py
# http://127.0.0.1:8080
```

## How it fits together

```
uconnect-rendezvous          the server, unchanged, running in a terminal
        ▲  UDP, ordinary client protocol
        │
   uconn-observe             C++, links the library, prints JSON
        ▲  stdout
        │
   observer.py               runs it, caches, degrades gracefully
        ▲
        │
     app.py                  Flask routes + templates
```

**The server is not modified and does not know this exists.** It keeps running
in a terminal; the dashboard watches it from outside over the same protocol any
peer uses. It can run on another machine, be restarted freely, or not run at
all, and the server never notices.

**The dashboard does not speak the wire protocol.** It shells out to
`uconn-observe`, which links the real library. A second implementation of the
framing in Python would drift from the C++ one the first time a field moved,
and the symptom would be a quietly wrong dashboard rather than a build error.
The boundary is JSON on a pipe, and the protocol has exactly one
implementation.

**The observer does not participate.** It never calls `publish()`, so it
registers no record and does not appear in the listings it reports. Measuring a
swarm should not change its size.

## Caching is load-bearing

The server rate-limits per source IP, measured in bytes returned, and a LOOKUP
for every topic is the most expensive thing it serves. An open dashboard on a
short refresh would throttle itself and then report an outage it had caused. So
results are cached (`UCONNECT_CACHE_TTL`, default 5s).

When a refresh fails, the last good data is served with a visible "stale"
banner rather than blanking the page — a server restart or one throttled lookup
should not wipe a view that was correct a moment ago, but it must be obviously
old rather than quietly wrong.

## What it can and cannot see

Everything shown is **already public to anyone who can reach the server**:

- Listing is opt-in per record — `publish(meta, listed=true)`. A topic absent
  from the directory was never offered to it.
- LOOKUP needs no key. `K` never reaches the server and is only ever used
  between peers, so knowing a `topic_id` is sufficient — which is exactly how
  every peer already finds the others.
- Metadata is plaintext by design.

So the dashboard makes existing exposure visible; it does not create any. That
also means the topic-lookup box works for unlisted topics: "unlisted" means
absent from the directory, not secret, and any peer with the id can do the same
thing.

What it cannot see: message contents, `K`, or anything about a peer-to-peer
session. Those never reach the server.

LOOKUP returns a **random sample**, capped at 30 by default and 100 at most,
never the whole swarm. A 500-peer topic reports 500 peers and lists 30 of them,
and the UI says so — otherwise a large topic looks like it is losing records.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `UCONNECT_SERVER` | `127.0.0.1:4433` | rendezvous server to watch |
| `UCONNECT_OBSERVE` | auto | path to `uconn-observe` |
| `UCONNECT_CACHE_TTL` | `5` | seconds before refetching |
| `UCONNECT_LIMIT` | `30` | members per topic, max 100 |
| `HOST` | `127.0.0.1` | bind address |
| `PORT` | `8080` | bind port |

`HOST` defaults to loopback deliberately. This is an unauthenticated read-only
view, and defaulting to `0.0.0.0` would publish a topic directory from whatever
host happened to run it. Put it behind a reverse proxy with auth if it should
be reachable.

`python app.py` runs Flask's development server. For anything long-lived use a
real WSGI server:

```sh
pip install gunicorn
UCONNECT_SERVER=1.2.3.4:4433 gunicorn -w 2 -b 127.0.0.1:8080 --chdir web app:app
```

## Running it on the server

The repo watcher that redeploys the rendezvous server on every commit deploys
this too. Install once:

```sh
sudo bash deploy/install-watcher.sh --with-web
sudo firewall-cmd --add-port=8080/tcp --permanent && sudo firewall-cmd --reload
# plus an inbound TCP rule in the cloud firewall: Source All / Destination 8080
```

You do **not** need to stop the rendezvous server first. The installer only
adds the new unit; the server is restarted by the next deploy, which it would
be anyway, and restarts are cheap — records live in memory with a 90s expiry
and clients re-register within one 20s keepalive.

On each commit the watcher then builds `uconn-observe`, refreshes the venv if
`requirements.txt` changed, swaps the app tree, and restarts `uconnect-web`.

**The dashboard is strictly an accessory.** It is deployed only after the
rendezvous server is confirmed healthy, and every failure path in its
deployment is non-fatal: a failed `pip install`, a syntax error, a unit that
will not start — all of them log loudly and leave the server alone. A broken
dashboard is an inconvenience; a rolled-back rendezvous server is an outage.

It also runs under gunicorn with **one worker and several threads**, not
several workers. Workers do not share memory, so four processes would mean four
independent caches and four times the lookups — and the cache is the thing
keeping the dashboard from tripping the server's rate limiter.

It watches `127.0.0.1:4433`, so its traffic never leaves the box. That also
means its lookups are rate-limited under the loopback address rather than the
public one, so a busy dashboard cannot throttle real peers.

If it does not come up:

```sh
journalctl -u uconnect-web -f          # the app
journalctl -u uconnect-watch -f        # the deploy that installed it
```

The most likely cause on a Debian/Ubuntu host is a missing `python3-venv`
package. `python3 -m venv --help` succeeds even when venv creation cannot, so
both the installer and the watcher build a real one and print the actual error
rather than guessing.

## Routes

| Route | Returns |
|---|---|
| `/` | topics, members, server counters |
| `/topic/<hex>` | one topic, listed or not |
| `/api/overview` | the same data as JSON (`?members=0` to skip lookups) |
| `/api/topic/<hex>` | one topic as JSON |
| `/healthz` | 200 if the rendezvous server is reachable, 503 otherwise |

## Tests

```sh
python3 web/test_observer.py
```

Covers the data layer without Flask and without a network, using a fake binary
at the subprocess seam: caching, stale-on-failure, topic-id validation, and the
error messages for a missing binary or unparseable output.

`uconn-observe` itself is exercised against a live server by the C++ side.
