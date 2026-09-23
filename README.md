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

## The two values

```
topic_id   16 bytes / 32 hex   PUBLIC.  The server's index key.
K          32 bytes / 64 hex   SECRET.  Never sent to the server, never on the wire.
```

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

Key size is also never the weak link. Generation is. `K` must come from a
CSPRNG; a passphrase stretched to 64 hex characters has the entropy of the
passphrase, not of 256 bits. On MinGW — the toolchain CLion ships —
`std::random_device` has historically been a deterministic Mersenne Twister that
returns the same sequence on every run, with no error and no warning. This
library uses `BCryptGenRandom` / `getrandom` directly and never
`std::random_device`.

## Two modes, and the difference matters

| | Open topic | Keyed topic |
|---|---|---|
| Pattern | `Noise_NN` | `Noise_NNpsk0` |
| Confidentiality vs. passive observer | yes | yes |
| Forward secrecy | yes | yes |
| Authentication | **none** | mutual, as topic members |
| Rendezvous server can MITM | **yes, undetectably** | no |
| Harvest-now-decrypt-later resistant | no | yes |

An open topic is encrypted and nothing more. Anyone who can modify or inject
traffic — the rendezvous server, an ISP, a hostile Wi-Fi AP — can sit between
two peers and read everything, and neither side can detect it. That is inherent
to having no shared secret, not a defect. It is fine for public swarms and
unsuitable for anything confidential, so the API says so in as many words:
`Topic::is_authenticated()`, and the constructor is
`TopicCreds::generate_open()`.

A `Topic` built with `K` **fails closed**. There is no fallback to `NN`, no
degraded mode, no warn-and-continue. Silent downgrade is how otherwise-sound
protocols get broken.

For open topics that need real authentication without a PSK, `Topic::sas()`
returns a four-word Short Authentication String derived from the handshake hash.
Compare it out of band; an interposed attacker necessarily produces two
different hashes and therefore two different strings.

## What the server knows

A `dev_id` it derived itself, an IP:port, a `topic_id`, and an opaque blob.
It does not hold `K`, cannot read a keyed topic's traffic, and cannot
impersonate a member.

```
dev_id = HMAC(server_secret, topic_id || src_ip || src_port)
```

`topic_id` is mixed in deliberately: without it the same device registering in
two topics would get the same `dev_id` in both, letting anyone who reads two
topic listings link them.

Everything is in memory. With a 90-second hard expiry there is no database, no
persistence and no migrations — a restart just means every live device
re-registers within one keepalive. Roughly 200 bytes per record; 10k live
devices is about 3.4 MB.

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

Note the peer sessions need their **own** keepalive: on many NATs the mapping
toward the server and the mapping toward a peer are separate bindings with
separate timers, so an idle peer session dies while the server record stays
perfectly healthy.

### Abuse resistance

- **Retry cookies.** Any response larger than its request requires a validated
  source address first — `HMAC(secret, ip || port || epoch)`, stateless, valid
  for the current and previous epoch. Without this a 60-byte `LOOKUP` returning
  4.6 KB is a 77x amplifier aimed at whoever the attacker spoofed.
- **Random sampling.** `LOOKUP` returns a random sample, capped at 30 by default
  and 100 at most, never the whole swarm. Also keeps a swarm balanced: no peer
  becomes everyone's first choice.
- **Quotas** per source IP, per topic and overall. Generous by default because a
  corporate NAT legitimately has many devices behind one address; tune against
  the rejection counters in `/stats` rather than by guessing.
- **Token-bucket rate limiting** measured in bytes returned, not requests.

## NAT traversal

Registration and keepalive go over **UDP from the same socket used for data**.
This is not a style preference: the client cannot know its own public mapping,
and the TCP source port an HTTP server would observe is a different NAT mapping
than the UDP socket's — registering it would punch a hole to nowhere. The
server reports the source address it observed, which is the STUN result.

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

The answer is the relay, and it runs on the rendezvous server. A peer asks for
an allocation, both ends address their traffic to the server, and it forwards
between them. It forwards **opaque ciphertext**: the relay sits below the crypto
layer, so the session is still end-to-end authenticated and forward-secret, and
the server learns only that two `dev_id`s are exchanging bytes and how many.

Relayed traffic gets its own rate budget rather than sharing the signaling one,
which is small and bursty. Charging a whole session against a limit sized for
lookups throttles every relayed transfer with no error and no counter to point
at. `Node::Config::force_relay` skips punching entirely — the only practical way
to exercise the path from a network where punching happens to work, and what a
peer on a known-symmetric NAT wants anyway.

## Handshake binding

```
prologue = "uconnect:v1" || topic_id || key_epoch || probe_txn
```

Mixed into Noise before anything else, so both sides must agree on the topic,
the key epoch and the exact validated path, or the handshake fails
cryptographically rather than through a check someone remembered to write. The
`probe_txn` term is what makes a replayed `HandshakeInit` useless: it arrives
bound to a transaction the responder never issued.

Failures are **silent**. A bad PSK, a stale transaction, a malformed message —
all dropped with no response. Any error reply would turn a peer into an oracle
for topic membership.

### If you add identity at the application layer

The protocol is anonymous by design: possession of `K` is the only credential,
and `dev_id`s rotate. When you add your own identity above it, **bind the proof
to the channel**:

```
identity_msg = { app_pubkey, Sign(app_privkey, "your-app:v1" || handshake_hash) }
```

`Topic::channel_binding(dev)` returns that hash. Without the binding, an insider
— which on a keyed topic means anyone holding `K` — can run two sessions and
relay A's identity proof into the second one to impersonate A to B.

## Streams

The session layer gives you authenticated datagrams: confidential, replay-proof,
and free to lose or reorder. `Stream` adds the rest — reliability, ordering, flow
control and congestion control — in a layer shaped like QUIC (RFC 9000/9002).

| | session datagram | `Stream` |
|---|---|---|
| confidentiality, authentication, dedup | yes | inherited |
| reliability, ordering | no | **yes** |
| flow control, congestion control | no | **yes** |
| `Topic::send` / `broadcast` | ✓ | |
| `Topic::open_stream` | | ✓ |

Streams are **multiplexed**, so head-of-line blocking is per stream, not per
connection: a lost packet stalls its own stream while the others keep flowing.
That is the reason to build on datagrams rather than one ordered pipe, and it is
the thing TCP cannot offer.

```cpp
Stream s = topic.open_stream(dev);          // invalid handle if not connected
                                            // or at the stream limit
s.write(bytes);                             // short count = backpressure
s.read(buf);                                // contiguous prefix only

topic.on_stream         ([](Stream s)            { /* peer opened one */ });
topic.on_stream_readable([](Stream s)            { /* bytes ready */ });
topic.on_stream_writable([](Stream s)            { /* backpressure lifted */ });
topic.on_stream_finished([](Stream s)            { /* peer sent FIN, all read */ });
topic.on_stream_reset   ([](Stream s, uint64_t c){ /* aborted */ });
topic.on_stream_closed  ([](Stream s)            { /* done, state released */ });
```

A short `write()` is backpressure, not an error. Wait for `on_stream_writable`
rather than polling `writable()` on a timer.

### Ending a stream

Three verbs, and the difference is worth reading once:

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

### Seeing what the path is doing

```cpp
if (auto li = topic.link(dev)) {
    li->relayed;              // through the server, or direct
    li->rtt;                  // smoothed
    li->congestion_window;    li->bytes_in_flight;    li->slow_start;
    li->packets_sent;         li->packets_lost;
    li->datagrams_sent;       li->datagrams_received;
    li->open_streams;
}
```

All diagnostic — nothing in the protocol depends on it — except `relayed`, which
is worth showing users. A relayed connection is still end to end encrypted, but
the rendezvous server is back in the path and can see traffic patterns.

`uconn-stream` prints this after a transfer, which is how the difference shows
up concretely: the same megabyte over a relay loses packets where the direct
path loses none.

### Limits

Peer-opened streams are capped (`max_concurrent_streams`, 64 by default,
`Node::Config::max_streams_per_peer`). Each
one costs a receive and a send buffer, and the peer decides how many stream ids
it puts on the wire — without a cap an authenticated peer pins unbounded memory
by sending one byte to each of arbitrarily many ids. Frames past the cap are
dropped rather than answered, since any reply would need the per-id state being
rationed.

## Saying goodbye

`Topic::disconnect()` and `Node::shutdown()` tell the peer, so it learns in one
round trip instead of waiting out the 90-second idle timeout holding a NAT
binding and possibly a relay slot. A deliberate shutdown should not look
identical to a cable being pulled.

The notice is a `Close` message: the same envelope as a transport packet —
`conn_id`, counter, ciphertext — sealed with the same session keys and drawn
from the same counter space, so the peer's existing replay window covers it and
a captured close is inert against any other session.

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

That difference is the useful one, so it reaches the application:

```cpp
topic.on_peer_closed([](DevId dev, PeerGone why) {
    // Local | TimedOut | GoingAway | ShuttingDown | Unspecified
});
```

`TimedOut` is what a vanished peer looks like — worth retrying. Anything else
means the peer was alive enough to say goodbye — worth reporting calmly. The
*cause* is always our own account of events; a peer supplies only a reason code,
so a hostile one cannot dress its own disappearance up as our idle timer.

A close before the handshake completes puts nothing on the wire: there are no
keys to authenticate it with, and an unauthenticated one would be a teardown
primitive for anybody.

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
deploy/        Oracle Cloud setup, systemd units, git watcher
```

Layering is enforced by CMake: if `uconnect_path` ever needs to link
`uconnect_io`, the build says so. Note that `uconnect_stream` does **not** link
`uconnect_crypto` — it sits above the session and never sees a key.

### Sans-IO

Every protocol state machine is pure. They take `(bytes, now)` and return
`(bytes, events, next_timeout)`. No sockets, no threads, no clock reads below
the `io` layer.

This is the decision everything else rests on, because NAT traversal and secure
transport are exactly the two things you cannot debug against the real internet.
`tests/netsim.hpp` gives four NAT behaviours, hairpinning on or off, packet
loss, latency, jitter and reordering as parameters — so a symmetric-NAT failure,
a router that refuses to hairpin, and a punch under 30% loss all run
deterministically in microseconds.

## Building

Requires CMake 3.28+, a C++20 compiler and Ninja. **No external dependencies** —
no libsodium, no package manager, nothing to install.

### Windows with CLion

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

### Anywhere else

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

### Running the built binaries

They need no environment at all — run them from any shell, or double-click them.
`libstdc++` and `libgcc` are linked statically, and `libwinpthread-1.dll` is
copied next to each executable at build time. Without that last step they exit
**127 with no diagnostic**, which is a confusing failure to debug.

(Bare `-static` is not usable on this toolchain: it fails to link with an
undefined `__ms_vsnprintf` out of `libmsvcrt`. Hence the copy.)

### Trying it

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
./build/examples/chat/uconn-chat --server 127.0.0.1:4433 --topic 'uconn://...' --name alice
```

And a stream transfer, which verifies every byte it receives. Add `--relay` to
force the path through the server instead of punching:

```sh
./build/examples/uconn-stream --server 127.0.0.1:4433 --topic 'uconn://...' --recv
./build/examples/uconn-stream --server 127.0.0.1:4433 --topic 'uconn://...' --send 1048576
```

`scripts/stream-smoke.sh` runs that pair and fails unless the bytes arrive
intact.

## Tests

224 unit cases plus two end-to-end smoke tests — one for punch + handshake +
messaging, one that moves a megabyte over a stream and verifies every byte.

The crypto is validated against published vectors — RFC 7693 (BLAKE2s),
RFC 8439 §2.3.2/§2.5.2/§2.8.2 (ChaCha20, Poly1305, the full AEAD with exact
ciphertext and tag), RFC 7748 §5.2/§6.1 (X25519). This is not decoration: every
one of these primitives is self-consistent when implemented wrongly, and two
peers running the same broken code will complete a handshake and talk happily to
each other. Only the vectors distinguish "works" from "correct".

## Status

Working end to end: registration, keepalive with rebinding, lookup with
sampling, topic listing, stats, candidate ranking, punching, the relay fallback
for symmetric NAT, `Noise_NN`/`NNpsk0`, authenticated transport with replay
protection, path migration, an N-peer mesh, reliable ordered streams with flow
and congestion control, and an authenticated connection close.

Verified against a live deployment as well as the simulator: byte-verified
transfers of 512 KB–1 MB over both punched and relayed paths.

Not yet implemented:

- **REST front end.** The store is sans-IO so an HTTP service sits beside the
  UDP one. It must be read-only, for the registration reason above.
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
