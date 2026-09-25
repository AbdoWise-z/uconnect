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

- Topics are listed by default; a record opts out with
  `publish(meta, unlisted=true)`. Hiding is sticky and topic-wide, so one
  member asking for it hides the topic from everyone.
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
`requirements.txt` changed, swaps the app tree, refreshes the unit file if it
changed (preserving the configured bind address), and restarts `uconnect-web`.

The watcher also **updates itself** from each commit it deploys, so changes to
the deploy logic take effect from the next tick. Two things it deliberately
does not self-update, and which still need `install-watcher.sh`:

- `uconnect-rendezvous.service` — the running server's lifeline. Quietly
  rewriting it from a commit turns a bad edit into an outage instead of a
  failed deploy.
- `uconnect-watch.service` / `.timer` — generated per host with the repo,
  branch and interval baked in, so the repo copy is not authoritative.

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

## The interactive app (`/app`)

Create a topic, and watch signaling activity as it happens.

**Topic keys are generated in the browser and never sent here.** `crypto.
getRandomValues` produces the 128-bit id and the 256-bit key; only the id is
POSTed, so the page can list what you made. A server that minted keys would
know every secret it handed out, which would quietly undo the one property the
whole protocol exists to provide — so `/api/topic` *rejects* a request carrying
a key rather than ignoring it, because a client sending one has misunderstood
something worth failing loudly over.

Nothing is created on the rendezvous server by pressing the button. A topic
comes into being when a peer registers under it; until then the URI is just two
random numbers.

### What the live feed can and cannot show

It carries **signaling, not conversations**. Peer traffic is end-to-end
encrypted and never reaches the rendezvous server, so the observable events are
registrations, membership changes, topic lifecycle and counter deltas. There is
no way to stream message contents and there never will be.

Membership join/leave is suppressed for sampled topics. LOOKUP returns at most
30 members, so on a large topic a peer drops out of one sample and back into the
next without having gone anywhere — reporting that as join/leave would be pure
noise.

The transport is **Server-Sent Events, not WebSockets**. Data only ever flows
one way; SSE needs no extra dependency, works with the existing threaded worker,
and reconnects by itself. A WebSocket would add a handshake, a second protocol
and an async worker to operate, for a channel nothing ever sends up. The hub
already speaks in discrete events, so swapping it later is contained.

## Web chat (`/chat`) — and what it costs

A browser **cannot be a uConnect peer**. No UDP socket, no hole punching, no
Noise handshake. So chatting from a page means `uconn-bridge` — a real peer —
runs on this host and relays between the topic and the browser.

**That hands the topic key to this server.** Whatever runs the handshake must
hold `K`, so the gateway can read every message in any topic you chat in.
Native clients never make that trade; there the key does not leave your
machine. Over plain HTTP the key also crosses the network in the clear. The
page says all of this above the input box, not in a footnote.

The key goes to the bridge on **stdin, never argv** — `argv` is visible in `ps`
to every user on the box, and a key in a process listing is a key in logs,
monitoring and support tickets. `/app` passes the URI to `/chat` in the URL
*fragment*, which browsers never send to the server, so merely opening the page
does not put it in an access log; pressing Join is what hands it over.

Messages use the same framing as `uconn-chat` (a type byte then UTF-8), so a
browser peer and a terminal peer are in one conversation rather than two that
happen to share a topic id.

Bridges are the most expensive thing here — each is a real UDP node that
registers, punches and holds a session — so they are capped at 8 concurrently,
one per session, with a 30-minute lifetime. Without that ceiling a browser that
vanished mid-conversation would leave a node registered and punching until the
host was rebooted.

### Why a created topic does not show up in the list

Because it does not exist yet. Creating a topic in `/app` produces two random
numbers; the rendezvous server learns of a topic when a peer **registers** under
it, and forgets it 90 seconds after the last one leaves. Join it — from `/chat`
or from `uconn-chat` — and it appears. The page says so where the topic is
created.

### Sessions and limits

A session is a random id in a cookie. There is no login, and the session is not
a credential — everything here is public anyway. It exists to bound resources.

| Limit | Default | Why |
|---|---|---|
| sessions per IP | 10 | stops one host farming identities |
| live feeds, global | 24 | each pins a server thread for as long as the tab is open |
| live feeds per session | 2 | one tab cannot corner the pool |
| topics per session | 20 | keeps `/api/topic` from being free storage |
| idle session timeout | 30 min | without it the per-IP cap is permanent |

That last one matters more than it looks: ten visits from an office NAT would
otherwise lock out everyone behind it forever — a denial of service implemented
by the thing meant to prevent one.

`X-Forwarded-For` is **ignored** unless `UCONNECT_TRUST_PROXY=1`. It is a header
anyone can send; trusting it without a proxy in front would let one host present
a fresh address per request and make the per-IP limit decorative.

All of this is single-process state, which is the third reason the unit runs one
gunicorn worker. With four workers each would keep its own counts and "10 per
IP" would really be forty.

## Routes

| Route | Returns |
|---|---|
| `/` | topics, members, server counters, derived stats |
| `/app` | create a topic, live activity feed |
| `/chat` | join a topic and talk, via a server-side bridge |
| `/api/chat/join`, `/say`, `/leave` (POST) | bridge lifecycle |
| `/api/chat/stream` | SSE of that session's conversation |
| `/topic/<hex>` | one topic, listed or not |
| `/api/overview` | the same data as JSON (`?members=0` to skip lookups) |
| `/api/topic/<hex>` | one topic as JSON |
| `/api/topic` (POST) | record a browser-generated topic id against the session |
| `/api/events` | Server-Sent Events feed |
| `/api/build` | the commit the running deployment was built from |
| `/healthz` | 200 if the rendezvous server is reachable, 503 otherwise |

Every page header shows the deployed commit. The watcher writes that sha only
after the build passed its tests and the service came up, so it names the commit
actually serving rather than the newest one pushed — which is the whole reason
to display it.

## Tests

```sh
python3 web/test_observer.py
```

Covers the data layer without Flask and without a network, using a fake binary
at the subprocess seam: caching, stale-on-failure, topic-id validation, and the
error messages for a missing binary or unparseable output.

`uconn-observe` itself is exercised against a live server by the C++ side.
