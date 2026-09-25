# uConnect

Peer-to-peer networking where a server only introduces peers, then gets out of
the way. Two devices sharing a topic and a secret find each other through a
rendezvous server, punch through NAT, and talk over an authenticated,
forward-secret channel the server cannot read or impersonate.

When both ends sit behind symmetric NAT, punching cannot work and the server
stays in the path as a relay — but only as a pipe. It forwards ciphertext it
cannot decrypt, on a session negotiated end to end, so the trust model does not
change when the route does.

```cpp
uconnect::Node node{"rv.example.com:4433"};
node.run_in_background();

auto& topic = node.join(uconnect::TopicCreds::parse(
    "uconn://9f86d081884c7d659a2feaa0c55ad015#a3f1...e7").value());

topic.on_data([](auto dev, auto bytes) { /* ... */ });
topic.publish(meta);       // become findable
topic.connect_all(8);      // LOOKUP -> punch -> Noise handshake
topic.broadcast(payload);  // unreliable datagram

// ...or a reliable ordered stream, when delivery matters
auto s = topic.open_stream(dev);
s.write(bytes);
s.finish();
```

**Contents** — [Using the library](#using-the-library) ·
[Architecture](#architecture) ·
[How a connection is made](#how-a-connection-is-made) ·
[Security guarantees](#security-guarantees) · [Building](#building) ·
[Public servers](#public-servers) · [Status](#status)

---

# Using the library

Link `uconnect` and include `<uconnect/uconnect.hpp>`. That one header is the
whole public surface; everything under `src/` is internal.

```cmake
target_link_libraries(your_app PRIVATE uconnect)
```

## The two values

Everything starts from a pair:

```
topic_id   16 bytes / 32 hex   PUBLIC.  The server's index key.
K          32 bytes / 64 hex   SECRET.  Never sent to the server, never on the wire.
```

They travel together as a URI, which is the only thing you need to share:

```
uconn://9f86d081884c7d659a2feaa0c55ad015#a3f1...e7
        \_________ topic_id ___________/ \__ K __/
```

```cpp
auto creds = TopicCreds::generate_keyed();   // 128-bit id + 256-bit key, CSPRNG
auto open  = TopicCreds::generate_open();    // id only: encrypted, NOT authenticated
auto given = TopicCreds::parse(uri);         // nullopt if malformed

creds.to_uri();        // the string to hand to the other side
creds.is_keyed();      // false for an open topic
```

**Generate `K` with `generate_keyed()`, not by hand.** Key size is never the
weak link; generation is. A passphrase stretched to 64 hex characters has the
entropy of the passphrase, not of 256 bits.

## Starting a node

A `Node` owns one UDP socket, one background thread, and every topic joined
through it.

```cpp
Node::Config cfg;
cfg.server      = "rv.example.com:4433";   // the only required field
cfg.bind_port   = 0;                       // 0 = ephemeral
cfg.keepalive   = 20s;                     // also holds the NAT binding open
cfg.force_relay = false;                   // skip punching, go straight to relay
cfg.verbose     = false;                   // protocol tracing to stderr

cfg.stream_recv_window   = 256 * 1024;     // per stream
cfg.conn_recv_window     = 1024 * 1024;    // across all streams on one peer
cfg.max_streams_per_peer = 64;

Node node{cfg};
node.run_in_background();      // or node.run() to block on this thread
```

The constructor throws `std::runtime_error` if it cannot bind the socket or
resolve the server. Those are the only two failures that happen before anything
is running.

## Joining a topic

```cpp
Topic& topic = node.join(creds);   // valid until leave() or shutdown()
```

`join()` only creates local state. To be *findable* you must publish:

```cpp
std::vector<uint8_t> meta(name.begin(), name.end());
topic.publish(meta);                     // listed in the public directory
topic.publish(meta, /*unlisted=*/true);  // reachable by id, absent from the directory
```

Metadata is an opaque blob the server stores and hands to anyone who looks the
topic up. **It is plaintext by design** — put a display name in it, not a
secret.

Hiding is sticky and topic-wide: one member asking to be unlisted hides the
topic from everyone, for as long as the topic exists. Unlisted is not secrecy —
anyone holding the `topic_id` can still look it up, because that is exactly how
peers find each other.

## Finding and connecting

```cpp
auto peers = topic.peers();       // random sample, <=30 by default, <=100 max
for (auto& p : peers) { p.dev_id; p.age; p.stale; p.meta; }

topic.connect(dev);               // one peer
topic.connect_all(8);             // up to 8 from a fresh lookup
topic.set_auto_connect(true);     // keep doing it, on the library's interval
topic.set_max_peers(16);
```

Prefer `set_auto_connect(true)` to a polling loop. Calling `peers()` on a 20 ms
tick produces thousands of lookups a minute and will trip the server's rate
limiter.

`connect()` returns immediately; connecting is asynchronous and takes a few
round trips. Watch `on_peer` for progress:

```
Unknown -> Probing -> Handshaking -> Connected
                   \-> Failed          \-> Closed
```

## Datagrams

Unreliable, unordered and cheap — the session's native shape.

```cpp
topic.send(dev, bytes);        // one peer
topic.broadcast(bytes);        // every connected peer; returns how many
topic.on_data([](DevId dev, std::span<const uint8_t> bytes) { /* ... */ });
```

Good for presence, telemetry, a game tick — anything where the next update makes
a lost one irrelevant. Use a stream when delivery matters.

## Streams

The session layer gives you authenticated datagrams: confidential, replay-proof,
and free to lose or reorder. `Stream` adds the rest — reliability, ordering, flow
control and congestion control — in a layer shaped like QUIC (RFC 9000/9002).

| | session datagram | `Stream` |
|---|---|---|
| confidentiality, authentication, dedup | yes | inherited |
| reliability, ordering | no | **yes** |
| flow control, congestion control | no | **yes** |
| `Topic::send` / `broadcast` | yes | |
| `Topic::open_stream` | | yes |

Streams are **multiplexed**, so head-of-line blocking is per stream, not per
connection: a lost packet stalls its own stream while the others keep flowing.
That is the reason to build on datagrams rather than one ordered pipe, and it is
the thing TCP cannot offer.

```cpp
Stream s = topic.open_stream(dev);          // invalid handle if not connected
                                            // or at the stream limit
Stream u = topic.open_stream(dev, false);   // unidirectional

s.write(bytes);                             // short count = backpressure
s.read(buf);                                // contiguous prefix only
s.readable();  s.readable_bytes();  s.writable();  s.finished();
s.id();  s.peer();  s.valid();
```

Always check the handle: `open_stream` returns an invalid `Stream` if the peer
is not connected, or if this peer is already at `max_streams_per_peer`.

A short `write()` is backpressure, not an error — wait for `on_stream_writable`
rather than polling `writable()` on a timer.

### Ending a stream

Four verbs, and the difference is worth reading once:

| | ends | releases the stream |
|---|---|---|
| `finish()` | our sending direction, gracefully | only once **both** ends finish |
| `reset(code)` | our sending direction, abruptly | no — the peer may still send to us |
| `close(code)` | **both** directions | yes, from one side |
| `stop_sending(code)` | the **peer's** direction | no — ours stays open |

`finish()` is a half-close. On a bidirectional stream the reverse direction stays
open, which is the point — but it means a one-way transfer where only the sender
finishes leaves the stream live on both ends. For one-way transfers open the
stream **unidirectional**; it then retires as soon as the receiver drains it.

`close()` is the one-sided teardown: it aborts our direction and asks the peer to
abort its own, and the peer's answer is what releases our side. It closes a
*stream*, not the connection — the session and every other stream on that peer
keep running.

`stop_sending()` is the reader's verb: "I have what I need, stop" — without
giving up our own direction the way `close()` does.

Finished streams are retired and their buffers released. Late frames for a
retired stream are rejected by a high-water mark rather than per-id tombstones,
which would be unbounded again.

## Events

All callbacks run on the node's loop thread. **Do not block in them** — no
sleeping, no synchronous I/O, no waiting on a lock the loop might hold. Copy
what you need and hand it to your own thread.

```cpp
topic.on_peer        ([](DevId, PeerState)                 { });
topic.on_peer_closed ([](DevId, PeerGone)                  { });
topic.on_data        ([](DevId, std::span<const uint8_t>)  { });

topic.on_stream          ([](Stream)           { });  // peer opened one
topic.on_stream_readable ([](Stream)           { });  // bytes ready
topic.on_stream_writable ([](Stream)           { });  // backpressure lifted
topic.on_stream_finished ([](Stream)           { });  // peer sent FIN, all read
topic.on_stream_reset    ([](Stream, uint64_t) { });  // aborted
topic.on_stream_closed   ([](Stream)           { });  // done, state released
```

`PeerGone` separates a peer that said goodbye from one that simply vanished:

```
Local | TimedOut | GoingAway | ShuttingDown | Unspecified
```

`TimedOut` is what a crash, a cable pull or a NAT rebind looks like — worth
retrying. Anything else means the peer was alive enough to say so — worth
reporting calmly. The *cause* is always our own account of events; a peer
supplies only a reason code, so a hostile one cannot dress its own
disappearance up as our idle timer.

## Diagnostics

```cpp
if (auto li = topic.link(dev)) {
    li->relayed;              // through the server, or direct
    li->rtt;                  // smoothed
    li->congestion_window;    li->bytes_in_flight;    li->slow_start;
    li->packets_sent;         li->packets_lost;
    li->datagrams_sent;       li->datagrams_received;
    li->open_streams;
}

topic.state(dev);     topic.connected();    topic.streams(dev);
node.reflexive();     node.local_port();
node.stats();         node.explore();       // server counters; listed topics
```

All diagnostic — nothing in the protocol depends on it — except `relayed`, which
is worth showing users. A relayed connection is still end to end encrypted, but
the rendezvous server is back in the path and can see traffic patterns.

`uconn-stream` prints this after a transfer, which is how the difference shows
up concretely: the same megabyte over a relay loses packets where the direct
path loses none.

## Shutting down

```cpp
topic.disconnect(dev);        // one peer, and tell it
topic.disconnect_all();
topic.unpublish();            // stop being findable, stay connected
node.leave(topic_id);         // invalidates the Topic&
node.shutdown();              // UNREGISTER everything, close every session, stop
```

`disconnect()` and `shutdown()` tell the peer, so it learns in one round trip
instead of waiting out the 90-second idle timeout while holding a NAT binding
and possibly a relay slot. A deliberate shutdown should not look identical to a
cable being pulled.

## Adding identity

The protocol is anonymous by design: possession of `K` is the only credential,
and `dev_id`s rotate. When you add your own identity above it, **bind the proof
to the channel**:

```cpp
auto binding = topic.channel_binding(dev);   // 32 bytes, unique to this session
// identity_msg = { app_pubkey, Sign(app_privkey, "your-app:v1" || binding) }
```

Without the binding, an insider — which on a keyed topic means anyone holding
`K` — can run two sessions and relay A's identity proof into the second one to
impersonate A to B.

For open topics, `topic.sas(dev)` returns a four-word Short Authentication
String derived from the handshake hash. Compare it out of band; an interposed
attacker necessarily produces two different hashes, and therefore two different
strings.

---

# Architecture

## The layer stack

```
                    your application
   +---------------------------------------------------+
   | src/api/      Node, Topic                          |  threads, clock, socket
   +---------------------------------------------------+
   | src/stream/   reliability, ordering, flow and      |  sans-IO
   |               congestion control (QUIC-shaped)     |
   +---------------------------------------------------+
   | src/session/  Noise handshake, AEAD transport,     |  sans-IO
   |               replay window, path migration        |
   +---------------------------------------------------+
   | src/path/     candidate ranking, hole punching     |  sans-IO
   +---------------------------------------------------+
   | src/crypto/   BLAKE2s, ChaCha20-Poly1305, X25519,  |  pure
   |               Noise, HKDF                          |
   | src/wire/     encode/decode, varints               |  pure
   +---------------------------------------------------+
                          |
                  src/io/ |  the ONLY target that owns a socket
```

Layering is enforced by CMake, not by convention: if `uconnect_path` ever needs
to link `uconnect_io`, the build fails. Note that `uconnect_stream` does **not**
link `uconnect_crypto` — it sits above the session and never sees a key.

## Sans-IO

Every protocol state machine is pure. They take `(bytes, now)` and return
`(bytes, events, next_timeout)`. No sockets, no threads, no clock reads below
the `io` layer.

This is the decision everything else rests on, because NAT traversal and secure
transport are exactly the two things you cannot debug against the real internet.
`tests/netsim.hpp` gives four NAT behaviours, hairpinning on or off, packet
loss, latency, jitter and reordering as parameters — so a symmetric-NAT failure,
a router that refuses to hairpin, and a punch under 30% loss all run
deterministically in microseconds.

The practical payoff: a ten-second transfer with 20% loss runs in milliseconds
and gives the same answer every time. A bug that would be a one-in-fifty flake
against a real network reproduces on the first try.

## Threading

One background thread per `Node`, owning the socket and every timer. Callbacks
fire on it. The public API is safe to call from any thread — `Topic` methods take
the node's lock — but a callback that blocks stalls every peer on that node, not
just the one that triggered it.

## The server

A separate binary that depends only on `wire` and `crypto`, never on the client
library. Its store is sans-IO too, so the whole 90-second record lifecycle is
tested by advancing a fake clock rather than by sleeping.

Everything is in memory. With a 90-second hard expiry there is no database, no
persistence and no migrations — a restart just means every live device
re-registers within one keepalive. Roughly 200 bytes per record; 10k live
devices is about 3.4 MB.

---

# How a connection is made

## 1. Register

Registration and keepalive go over **UDP from the same socket used for data**.
This is not a style preference: the client cannot know its own public mapping,
and the TCP source port an HTTP server would observe is a different NAT mapping
than the UDP socket's — registering it would punch a hole to nowhere. The server
reports the source address it observed, which is the STUN result.

The server derives an identity rather than letting the client choose one:

```
dev_id = HMAC(server_secret, topic_id || src_ip || src_port)
```

`topic_id` is mixed in deliberately: without it the same device registering in
two topics would get the same `dev_id` in both, letting anyone who reads two
topic listings link them.

The reply carries a **lease token**, sent once. Every later keepalive or update
carries only a MAC over it plus a monotonic sequence number, so the token itself
never goes back on the wire.

### Two clocks that are easy to conflate

| Timer | Value | Meaning |
|---|---|---|
| Keepalive | 20 s | also what holds the NAT binding open |
| Stale | 45 s | entry still returned, but flagged |
| Hard expiry | 90 s | deleted, memory reclaimed |

NAT UDP mappings commonly die in 30 s–5 min, with the short end normal on mobile
carriers. A record can be nominally alive while its reflexive candidate has been
dead for most of that time, which is why the expiry sits close to the keepalive
rather than minutes away.

Peer sessions need their **own** keepalive: on many NATs the mapping toward the
server and the mapping toward a peer are separate bindings with separate timers,
so an idle peer session dies while the server record stays perfectly healthy.

## 2. Look up

`LOOKUP` returns a **random sample**, capped at 30 by default and 100 at most,
never the whole swarm. That is both an amplification defence and a load
balancer: no peer becomes everyone's first choice.

Each entry carries the peer's candidates — its reflexive address as the server
observed it, plus any host addresses it supplied.

## 3. Punch

Candidates are ranked host > srflx > relay, with two adjustments:

- **Same-NAT detection.** If a peer's reflexive address shares our public IP we
  are almost certainly behind the same NAT, where the srflx pair needs the
  router to hairpin a packet addressed to its own external IP back inside —
  which many consumer routers simply drop. There the host candidate is not an
  optimisation, it is the only thing that works, so the srflx pair is demoted.
- **IPv6 preferred**, since it is frequently unfiltered end to end when IPv4 is
  double-NATed.

Probes are staggered, retransmitted with jittered exponential backoff, and the
first packets are *expected* to be lost — until both sides have sent, neither
NAT has a reason to let the other in. A `ProbeOk` echoing our transaction id
validates a path; that round trip is also the challenge-response the handshake
is later gated on.

**Symmetric NAT on both ends defeats punching**, and the test suite asserts this
rather than papering over it: a symmetric NAT allocates a fresh external port
per destination, so the port the rendezvous server observed is not the port the
peer must hit.

## 4. Handshake

`Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s` for a keyed topic, `Noise_NN_...` for an
open one. Before anything else, a prologue is mixed in:

```
prologue = "uconnect:v1" || topic_id || key_epoch || probe_txn
```

Both sides must agree on the topic, the key epoch and the exact validated path,
or the handshake fails cryptographically rather than through a check someone
remembered to write. The `probe_txn` term is what makes a replayed
`HandshakeInit` useless: it arrives bound to a transaction the responder never
issued.

The initiator's `dev_id` travels in message 1's authenticated payload rather
than being inferred from the source address. Behind a symmetric NAT the address
a handshake *arrives* from is not the address it *advertised*, so address
matching silently files the session under a synthetic identity.

Failures are **silent**. A bad PSK, a stale transaction, a malformed message —
all dropped with no response. Any error reply would turn a peer into an oracle
for topic membership.

When both ends open at once, the numerically smaller `dev_id` is the designated
initiator. Without that tie-break both sides replace their own session with the
accepted one, both report "connected", and no data flows.

## 5. Transport

Authenticated datagrams with a 64-packet replay window, IPsec style: a
high-water mark plus a bitmap of the counters below it. UDP reorders, so a
strictly-increasing check would drop legitimate packets and accepting anything
would permit replay.

Sessions have a 15-minute lifetime and then ask the layer above for a fresh
handshake — there is no in-place rekey. Rekeying needs both ends to step in
lockstep, and getting it wrong desynchronises a session in a way that looks
exactly like packet loss. A fresh handshake on an already-validated path is
cheap.

The session survives an address change: matching on `conn_id` rather than the
4-tuple means a NAT rebind or a Wi-Fi/LTE handoff keeps it alive, once the AEAD
verifies that the peer arriving from the new address really is the peer.

## When punching fails: the relay

The relay runs on the rendezvous server. A peer asks for an allocation, both
ends address their traffic to the server, and it forwards between them.

It forwards **opaque ciphertext**. The relay sits below the crypto layer, so the
session is still end-to-end authenticated and forward-secret, and the server
learns only that two `dev_id`s are exchanging bytes and how many.

Relayed traffic gets its own rate budget rather than sharing the signaling one,
which is small and bursty. Charging a whole session against a limit sized for
lookups throttles every relayed transfer with no error and no counter to point
at. `Node::Config::force_relay` skips punching entirely — the only practical way
to exercise that path from a network where punching happens to work.

## Saying goodbye

`Topic::disconnect()` and `Node::shutdown()` send a `Close`: the same envelope
as a transport packet — `conn_id`, counter, ciphertext — sealed with the same
session keys and drawn from the same counter space, so the peer's existing
replay window covers it and a captured close is inert against any other session.

It is sealed against **its own type byte as associated data**, and that detail
is load-bearing. The header is not covered by the AEAD tag, so if a close and a
data packet were sealed the same way, anyone on path could flip one byte —
`0x40` to `0x41` — and tear down a session they cannot read. Binding each kind
to its type makes that forgery fail the tag check. There are tests for the
forgery in both directions, and they fail if the binding is removed.

Best effort by construction. Nothing acknowledges a close, so it goes out a few
times and the idle timeout stays as the backstop. This makes a *deliberate*
disconnect fast; crashes, cable pulls and NAT rebinds still take the full
timeout, because there is nobody left to send anything.

A close before the handshake completes puts nothing on the wire: there are no
keys to authenticate it with, and an unauthenticated one would be a teardown
primitive for anybody.

---

# Security guarantees

## What you get, and what you do not

| | Open topic | Keyed topic |
|---|---|---|
| Noise pattern | `Noise_NN` | `Noise_NNpsk0` |
| Confidentiality vs. a passive observer | yes | yes |
| Forward secrecy | yes | yes |
| Replay protection | yes | yes |
| Authentication | **none** | mutual, as topic members |
| Rendezvous server can MITM | **yes, undetectably** | no |
| Harvest-now-decrypt-later resistant | no | yes |

An open topic is encrypted and nothing more. Anyone who can modify or inject
traffic — the rendezvous server, an ISP, a hostile Wi-Fi AP — can sit between
two peers and read everything, and neither side can detect it. That is inherent
to having no shared secret, not a defect. It is fine for public swarms and
unsuitable for anything confidential, so the API says so in as many words:
`Topic::is_authenticated()`, and the constructor is `TopicCreds::generate_open()`.

A `Topic` built with `K` **fails closed**. There is no fallback to `NN`, no
degraded mode, no warn-and-continue. Silent downgrade is how otherwise-sound
protocols get broken.

## What the rendezvous server knows

A `dev_id` it derived itself, an IP:port, a `topic_id`, and an opaque blob. It
does not hold `K`, cannot read a keyed topic's traffic, and cannot impersonate a
member.

It *does* see metadata, in both senses: the literal `meta` blob you publish, and
the traffic patterns of who looks up what and when. For a relayed pair it also
sees byte counts. If that matters for your threat model, run your own — it is a
single static binary with no configuration and no database.

## Key handling

`K` is never used directly. Purpose-specific subkeys are derived with
domain-separated HKDF, so a leak in one use cannot cross into another:

```
psk    = HKDF(K, "uconnect:v1:psk",   32)   -> mixed into the Noise handshake
probe  = HKDF(K, "uconnect:v1:probe", 32)   -> keys probe tags
```

**32 bytes, not 64.** Every construction downstream is 256-bit — the Noise PSK
slot, the ChaCha20 key, the BLAKE2s output — so a 512-bit input is compressed to
256 bits regardless, and the security of a chain is bounded by its narrowest
link. A longer key buys nothing but characters to copy.

Randomness comes from `BCryptGenRandom` on Windows and `getentropy` elsewhere,
never `std::random_device`. On MinGW — the toolchain CLion ships —
`std::random_device` has historically been a deterministic Mersenne Twister that
returns the same sequence on every run, with no error and no warning. A CSPRNG
failure throws rather than returning weak bytes: there is no safe way to
continue, and a silent fallback would compromise every key the process
generates.

## Explicit non-goals

Worth stating, because each is a reasonable thing to expect and none of it is
provided:

- **Who a peer is.** Possession of `K` is the only credential. Everyone holding
  it is equal, and `dev_id`s rotate with the address. Build identity above this
  layer, bound to `channel_binding()`.
- **Protection from insiders.** On a keyed topic, any member can read everything
  and can MITM two other members unless they bind identity to the channel.
- **Traffic analysis resistance.** No padding, no cover traffic, no timing
  defence. Packet sizes and timing are visible to anyone on path.
- **Denial of service resistance for peers.** The server has quotas and
  rate limits; a peer does not. An authenticated member can flood you.
- **Anything about the application layer.** Message framing, ordering across
  streams, and what a peer is allowed to say are yours.

## Abuse resistance on the server

- **Retry cookies.** Any response larger than its request requires a validated
  source address first — `HMAC(secret, ip || port || epoch)`, stateless, valid
  for the current and previous epoch. Without this a 60-byte `LOOKUP` returning
  4.6 KB is a 77x amplifier aimed at whoever the attacker spoofed.
- **Random sampling.** `LOOKUP` returns a random sample, capped at 30 by default
  and 100 at most, never the whole swarm.
- **Quotas** per source IP, per topic and overall. Generous by default because a
  corporate NAT legitimately has many devices behind one address; tune against
  the rejection counters in `/stats` rather than by guessing.
- **Token-bucket rate limiting** measured in bytes returned, not requests, with
  a separate budget for relayed payload.
- **Bounded everything.** Ack ranges, stream counts, send and receive buffers,
  relay bytes per binding. A peer chooses how much of each it asks for, so each
  one has a ceiling.

## Verification

The crypto is validated against published vectors — RFC 7693 (BLAKE2s),
RFC 8439 §2.3.2/§2.5.2/§2.8.2 (ChaCha20, Poly1305, the full AEAD with exact
ciphertext and tag), RFC 7748 §5.2/§6.1 (X25519). This is not decoration: every
one of these primitives is self-consistent when implemented wrongly, and two
peers running the same broken code will complete a handshake and talk happily to
each other. Only the vectors distinguish "works" from "correct".

---

# Building

Requires CMake 3.28+, a C++20 compiler and Ninja. **No external dependencies** —
no libsodium, no package manager, nothing to install.

## Windows with CLion

CLion bundles everything needed (CMake 4.3, GCC 15.2 MinGW, Ninja), but **none
of it is on PATH in a normal shell**. Use one of:

```powershell
.\scripts\build.ps1              # PowerShell: configure + build + unit tests
.\scripts\build.ps1 -All         # also run the end-to-end smoke test
.\scripts\build.ps1 -Clean       # wipe build/ first
```

```sh
bash scripts/build.sh            # Git Bash: same thing
```

Or just open the folder in CLion and hit build — it uses its own toolchain and
needs no setup at all.

If your CLion is somewhere unusual, set `UCONNECT_TOOLCHAIN` to its install
directory. If you have your own CMake/GCC/Ninja on PATH, the plain commands
below work and you can ignore the scripts entirely.

## macOS and Linux

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

Clang and GCC both work; macOS needs the Xcode command line tools
(`xcode-select --install`) and nothing else.

Platform requirements are narrow by design. Randomness comes from `getentropy`,
which needs **macOS 10.12+** or **glibc 2.25+** — chosen over Linux's
`getrandom` precisely so there is one POSIX path rather than a second branch
that only ever compiles on someone else's machine. Sockets are plain BSD sockets
with `select`, not `epoll` or `kqueue`, so the same code serves both. Apple
Silicon needs nothing special: the vendored X25519 and Poly1305 are portable C
with no intrinsics and no endianness assumptions.

## Running the built binaries

They need no environment at all — run them from any shell, or double-click them.
`libstdc++` and `libgcc` are linked statically, and `libwinpthread-1.dll` is
copied next to each executable at build time. Without that last step they exit
**127 with no diagnostic**, which is a confusing failure to debug.

(Bare `-static` is not usable on this toolchain: it fails to link with an
undefined `__ms_vsnprintf` out of `libmsvcrt`. Hence the copy.)

## Trying it

```sh
./build/server/uconnect-rendezvous --port 4433

# prints a uconn:// URI
./build/examples/uconn-demo --server 127.0.0.1:4433 --create

./build/examples/uconn-demo --server 127.0.0.1:4433 --topic 'uconn://...' --name alice
./build/examples/uconn-demo --server 127.0.0.1:4433 --topic 'uconn://...' --name bob
```

`scripts/smoke.sh` does exactly this and asserts that both peers punch,
handshake and exchange messages.

An interactive chat over the same library:

```sh
./build/examples/chat/uconn-chat --server 127.0.0.1:4433 --topic 'uconn://...' --nick alice
```

And a stream transfer, which verifies every byte it receives. Add `--relay` to
force the path through the server instead of punching:

```sh
./build/examples/uconn-stream --server 127.0.0.1:4433 --topic 'uconn://...' --recv
./build/examples/uconn-stream --server 127.0.0.1:4433 --topic 'uconn://...' --send 1048576
```

`scripts/stream-smoke.sh` runs that pair and fails unless the bytes arrive
intact.

## Watching a server

The server runs in a terminal and is not a web service. To see what it holds,
`tools/uconn-observe` queries it over the ordinary client protocol and prints
JSON, and `web/` is a read-only Flask dashboard on top of that.

```sh
./build/tools/uconn-observe --server 127.0.0.1:4433 --members
UCONNECT_SERVER=127.0.0.1:4433 python web/app.py    # http://127.0.0.1:8080
```

The server is untouched and unaware. The observer never calls `publish()`, so it
registers nothing and does not appear in the listings it reports. Nothing in
Python speaks the wire protocol — it shells out to a binary that links this
library, so the framing has exactly one implementation and cannot drift. See
[web/README.md](web/README.md).

## Layout

```
src/wire/      protocol codec, varints             no dependencies
src/crypto/    BLAKE2s, ChaCha20-Poly1305, X25519, Noise, HKDF
src/path/      candidate ranking, punch state machine
src/session/   Noise session, replay window, path migration
src/stream/    frames, loss recovery, congestion control, streams
src/io/        UDP sockets                         the ONLY target with a socket
src/api/       Node and Topic
server/        record store (sans-IO) + UDP service + relay + binary
third_party/   vendored X25519 and Poly1305
tests/         unit suite + a simulated network
examples/      uconn-demo, uconn-chat, uconn-stream
tools/         uconn-observe -- reads a server's public view as JSON
web/           read-only Flask dashboard over uconn-observe
deploy/        Oracle Cloud setup, systemd units, git watcher
```

## Tests

225 unit cases plus two end-to-end smoke tests — one for punch + handshake +
messaging, one that moves a megabyte over a stream and verifies every byte.
`python3 web/test_observer.py` covers the dashboard's data layer.

---

# Public servers

| Rendezvous | Dashboard | Notes |
|---|---|---|
| `129.152.22.201:4433` (UDP) | http://129.152.22.201:8080 | Oracle Cloud, Ubuntu. Redeployed from `master` on every commit. |

Try it without running anything yourself:

```sh
./build/examples/uconn-demo --server 129.152.22.201:4433 --stats
./build/examples/uconn-demo --server 129.152.22.201:4433 --create
```

It is a **best-effort public instance**, not a service: it holds no state worth
keeping, restarts on every push, and may vanish. Run your own for anything that
matters.

The rendezvous server cannot read your traffic either way. It holds a `dev_id`
it derived itself, an IP:port, a `topic_id` and an opaque blob; `K` never
reaches it.

---

# Status

Working end to end: registration, keepalive with rebinding, lookup with
sampling, topic listing, stats, candidate ranking, punching, the relay fallback
for symmetric NAT, `Noise_NN`/`NNpsk0`, authenticated transport with replay
protection, path migration, an N-peer mesh, reliable ordered streams with flow
and congestion control, an authenticated connection close, and a read-only web
dashboard.

Verified against the live deployment above as well as the simulator:
byte-verified transfers of 512 KB–1 MB over both punched and relayed paths, and
225 unit cases gating every deploy.

Not yet implemented:

- **REST front end.** The store is sans-IO so an HTTP service sits beside the
  UDP one. It must be read-only: the TCP source port an HTTP server observes is
  a different NAT mapping than the client's UDP socket, so a record registered
  that way would punch to nowhere.
- **In-place rekey.** Sessions have a 15-minute lifetime and then ask for a
  fresh handshake. Rekeying needs both ends to step in lockstep, and getting it
  wrong desynchronises a session in a way that looks like packet loss.
- **Key rotation.** `key_epoch` is carried on the wire and in the prologue but
  nothing drives it yet.
- **Path migration for network changes.** A device that switches Wi-Fi to
  cellular gets a new mapping, and there is no migration for it — both ends time
  out and reconnect from scratch.

Known sharp edges:

- A **bidirectional** stream is only released when both ends `finish()`. A
  one-way transfer over one leaves state on both sides until the session ends.
  Use a unidirectional stream, or `close()`.
- `SendBuffer` never returns its capacity to the allocator, so a stream that
  carried a large transfer holds its peak send buffer until it is retired.
