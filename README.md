# uConnect

Peer-to-peer networking where a server only introduces peers, then gets out of
the way. Two devices sharing a topic and a secret find each other through a
rendezvous server, punch a TCP connection through NAT, and talk over an
authenticated, forward-secret channel the server cannot read or impersonate.
When they need it, a UDP datagram channel opens beside it, keyed from the same
handshake.

When the NATs will not let a connection through, the server stays in the path
as a relay — but only as a pipe. It forwards ciphertext it cannot decrypt, on a
session negotiated end to end, so the trust model does not change when the
route does.

```cpp
uconnect::Node node{"rv.example.com:4433"};
node.run_in_background();

auto& topic = node.join(uconnect::TopicCreds::parse(
    "uconn://9f86d081884c7d659a2feaa0c55ad015#a3f1...e7").value());

topic.on_data([](auto dev, auto bytes) { /* ... */ });
topic.publish(meta);       // become findable
topic.connect_all(8);      // LOOKUP -> punch TCP -> Noise handshake
topic.broadcast(payload);  // a reliable, ordered message to every peer

// ...or unreliable datagrams, when late is as bad as lost
topic.open_datagrams(dev, uconnect::DatagramFallback::Relay);
topic.send_datagram(dev, frame);
```

**Contents** — [Using the library](#using-the-library) ·
[Architecture](#architecture) ·
[How a connection is made](#how-a-connection-is-made) ·
[Security guarantees](#security-guarantees) · [Building](#building) ·
[Running your own server](#running-your-own-server) ·
[Auto-deploying from GitHub](#auto-deploying-from-github) ·
[Customising](#customising) ·
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

A `Node` owns one TCP port, one background thread, and every topic joined
through it — plus a UDP socket, opened the first time a datagram channel needs
one.

```cpp
Node::Config cfg;
cfg.server        = "rv.example.com:4433";  // the only required field
cfg.bind_port     = 0;                      // 0 = ephemeral
cfg.keepalive     = 20s;                    // refreshes records with the server
cfg.punch_timeout = 8s;                     // then fall back to the relay
cfg.force_relay   = false;                  // skip punching, go straight to the fallback
cfg.verbose       = false;                  // protocol tracing to stderr

cfg.datagram_fallback = DatagramFallback::Tcp;  // for channels peers open to us
cfg.rekey_shift       = 16;                     // preferred interval; peers use the smaller shift

Node node{cfg};
node.run_in_background();      // or node.run() to block on this thread
```

The constructor throws `std::runtime_error` if it cannot listen on its port or
resolve the server, and `std::invalid_argument` for a `rekey_shift` outside
7..63. Those are the only failures that happen before anything is running.

The node connects to the server on its own, keeps that connection up, and
reconnects — registering every published topic again — if it drops.
`node.server_connected()` says whether it is up right now.

A control connection attempt or a loop-issued request left unanswered for ten
seconds also triggers reconnection. Keepalive and discovery requests are not
duplicated while awaiting replies; a stalled server cannot grow those queues
indefinitely. Blocking queries retain their own API timeouts.

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

`connect()` needs a published topic: the server introduces peers only to a
registered member. Prefer `set_auto_connect(true)` to a polling loop — calling
`peers()` on a 20 ms tick produces thousands of lookups a minute.

`connect()` returns immediately; connecting is asynchronous and takes a few
round trips. Watch `on_peer` for progress:

```
Unknown -> Probing -> Handshaking -> Connected
                   \-> Failed          \-> Closed
```

`Probing` covers both punching and, if that fails, the relay. `Failed` means
neither worked.

## Messages

Each peer connection is one TCP connection, so messages are what TCP is:
reliable and ordered. Each arrives whole, once, in the order sent, as one
`on_data` call.

```cpp
topic.send(dev, bytes);        // one peer; up to Topic::max_message() = 1 MiB
topic.broadcast(bytes);        // every connected peer; returns how many
topic.on_data([](DevId dev, std::span<const uint8_t> bytes) { /* ... */ });
```

`send()` returns false if the peer is not connected, the message is too large,
or the peer is reading so slowly that 16 MiB is already queued for it — that
last one is backpressure; try again later.

## Datagrams

TCP's reliability has a price: one lost segment holds up everything behind it.
For traffic where late is as bad as lost — voice, game state, telemetry — open a
datagram channel:

```cpp
topic.open_datagrams(dev, DatagramFallback::Relay);   // asynchronous
topic.on_datagram_path([](DevId, DatagramPath p) { /* Opening -> Direct ... */ });

topic.send_datagram(dev, bytes);   // up to Topic::max_datagram() = 1100 bytes
topic.on_datagram([](DevId dev, std::span<const uint8_t> bytes) { /* ... */ });
topic.close_datagrams(dev);
```

Unreliable, unordered, never waiting on each other. The channel is keyed from
the TCP connection's handshake, so it authenticates the same peer and needs no
handshake of its own; opening it only punches a UDP path. The peer accepts
automatically.

The fallback policy is fixed when the channel opens. `open_datagrams()` returns
false if a channel is already opening or open, including one accepted from a
peer. Call `close_datagrams()` before reopening with a different policy; a
`Failed` channel can be retried directly. Closing the datagram channel keeps
the peer's TCP connection up.

When UDP cannot be punched, **you choose what happens**, and each side applies
its own choice to what it sends:

| `DatagramFallback` | datagrams travel | trade-off |
|---|---|---|
| `Tcp` | over the TCP connection | always works, costs nothing, but arrives reliably and in order — late rather than lost |
| `Relay` | through the server's UDP relay | stays unreliable and low-latency, but the server is in the path and the pair's relay budget is finite |
| `None` | nowhere | `send_datagram()` returns false |

```
None -> Opening -> Direct                       punched UDP
                \-> Relayed | Tcp | Failed      the fallback, or none
```

A punch that comes through late is always taken, whatever the fallback was.
`send_datagram()` returns true when a datagram was sent, not delivered.

## Events

All callbacks run on the node's loop thread. **Do not block in them** — no
sleeping, no synchronous I/O, no waiting on a lock the loop might hold. Copy
what you need and hand it to your own thread. Calling back into the library
from a callback is fine for nonblocking operations such as `send`, `connect`,
and `disconnect`. Synchronous `publish`, `peers`, `resolve`, `explore`, and
`stats` return failure immediately on the loop thread, without sending a
request; `connect_all` consequently does nothing there. Run these calls on
an application thread. Their failure values are `false`, an empty vector,
or `nullopt`, matching the method's return type.

```cpp
topic.on_peer          ([](DevId, PeerState)                 { });
topic.on_peer_closed   ([](DevId, PeerGone)                  { });
topic.on_data          ([](DevId, std::span<const uint8_t>)  { });
topic.on_datagram      ([](DevId, std::span<const uint8_t>)  { });
topic.on_datagram_path ([](DevId, DatagramPath)              { });
```

Whatever a callback captures must outlive the node: the loop can call it right
up until an external call to `shutdown()` returns. Calling `shutdown()` from
a callback requests a stop; the loop finishes cleanup after callbacks return.
Keep the node and callback captures alive until an external thread has waited
for shutdown. Destroying the node inside a callback is not supported.

`PeerGone` separates a peer that said goodbye from one that simply vanished:

```
Local | TimedOut | GoingAway | ShuttingDown | Unspecified
```

`TimedOut` is what a crash, a cable pull or a dropped connection looks like —
worth retrying. Anything else means the peer was alive enough to say so — worth
reporting calmly. The *cause* is always our own account of events; a peer
supplies only a reason code, so a hostile one cannot dress its own
disappearance up as our idle timer.

## Diagnostics

```cpp
if (auto li = topic.link(dev)) {
    li->relayed;                                   // through the server, or direct
    li->messages_sent;    li->messages_received;
    li->bytes_sent;       li->bytes_received;      // message payload
    li->datagrams_sent;   li->datagrams_received;  // however they travelled
}

topic.state(dev);     topic.connected();    topic.datagram_path(dev);
node.reflexive();     node.local_port();    node.server_connected();
node.stats();         node.explore();       // server counters; listed topics
```

All diagnostic — nothing in the protocol depends on it — except `relayed`, which
is worth showing users. A relayed connection is still end to end encrypted, but
the rendezvous server is back in the path and can see traffic patterns.

## Shutting down

```cpp
topic.disconnect(dev);        // one peer, and tell it
topic.disconnect_all();
topic.unpublish();            // stop being findable, stay connected
node.leave(topic_id);         // invalidates the Topic&
node.shutdown();              // unregister everything, close every session, stop
```

`disconnect()` and `shutdown()` tell the peer, so it learns at once instead of
waiting out the 90-second idle timeout. A deliberate shutdown should not look
identical to a cable being pulled.

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
   | src/api/      Node, Topic                          |  threads, clock, sockets
   +---------------------------------------------------+
   | src/session/  TcpSession: Noise handshake and      |  sans-IO
   |               sealed records over a TCP stream     |
   |               Session: the UDP datagram channel,   |
   |               replay window, key ratchet, paths    |
   +---------------------------------------------------+
   | src/path/     candidate ranking, UDP hole punching |  sans-IO
   +---------------------------------------------------+
   | src/crypto/   BLAKE2s, ChaCha20-Poly1305, X25519,  |  pure
   |               Noise, HKDF                          |
   | src/wire/     encode/decode, the control protocol  |  pure
   +---------------------------------------------------+
                          |
                  src/io/ |  the ONLY target that owns a socket
```

Layering is enforced by CMake, not by convention: if `uconnect_path` ever needs
to link `uconnect_io`, the build fails.

Reliability is TCP's. An earlier version of this library carried its own
QUIC-shaped stream layer over UDP — loss recovery, flow and congestion control
— and it was replaced by a TCP connection, because the operating system's TCP is
better tested, better tuned and cheaper than anything a library can carry. UDP
stays for what TCP cannot do: datagrams that do not wait for each other.

## Sans-IO

Every protocol state machine is pure. They take `(bytes, now)` and return
`(bytes, events, next_timeout)`. No sockets, no threads, no clock reads below
the `io` layer.

This is the decision everything else rests on, because NAT traversal and secure
transport are exactly the two things you cannot debug against the real internet.
`tests/netsim.hpp` gives four NAT behaviours, hairpinning on or off, packet
loss, latency, jitter and reordering as parameters — so a symmetric-NAT failure,
a router that refuses to hairpin, and a punch under 30% loss all run
deterministically in microseconds. The TCP session is tested the same way,
fed its bytes one at a time or in any chunking TCP is free to deliver.

## Threading

One background thread per `Node`, owning the sockets and every timer. Callbacks
fire on it. The public API is safe to call from any thread — `Topic` methods take
the node's lock — but a callback that blocks stalls every peer on that node, not
just the one that triggered it.

## The server

A separate binary on the `wire`, `crypto` and `io` targets, never the client
library. Its registry and control service are sans-IO too, so record, ownership
and relay logic is tested without a socket; `tests/test_rendezvous.cpp` then
runs the real runtime over loopback.

Everything is in memory, and every record **belongs to the connection that
registered it**: when a node's connection closes, its records go with it. There
is no database, no persistence and no expiry sweep to tune — a restart just
means every live node reconnects and registers again.

---

# How a connection is made

## 1. One port, one connection to the server

A node owns one TCP port, P, and does everything from it: it listens on P,
keeps its connection to the server from P, and punches to peers from P. That is
not tidiness. The address the server observes for the control connection is
P's NAT mapping, and that is the address peers are told to dial — punching from
any other port would open a hole to nowhere. Sockets share P with
`SO_REUSEADDR` (and `SO_REUSEPORT` on Linux).

The control protocol is length-prefixed frames on that one connection:
registration, keepalive, lookup, introductions, relay allocation. It is also how
the server reaches the node — an introduction or a relay offer arrives on it
unprompted.

## 2. Register

The server derives an identity rather than letting the client choose one:

```
dev_id = MAC(server_secret, topic_id || TCP source address)
```

`topic_id` is mixed in deliberately: without it the same device registering in
two topics would get the same `dev_id` in both, letting anyone who reads two
topic listings link them.

**Ownership is the connection.** Only the connection that registered a record
can refresh, update or remove it, or introduce and relay on its behalf. There
are no lease tokens, MACs or sequence numbers, because there is nothing to
authenticate that the TCP connection does not already prove — and no expiry
timer, because the record ends when the connection does.

### The timers that remain

| Timer | Value | Meaning |
|---|---|---|
| Keepalive | 20 s | the node refreshes each record; also holds P's NAT mapping open |
| Stale | 45 s | a record not refreshed this long is still returned, but flagged |
| Idle | 90 s | a connection that says nothing this long is closed, and its records with it |
| First frame | 10 s | a new connection must say what it is |

A node with nothing published still sends a bare keepalive, which keeps the
connection and tells it its reflexive address.

## 3. Look up

`LOOKUP` returns a **random sample**, capped at 30 by default and 100 at most,
never the whole swarm. No peer becomes everyone's first choice.

Each entry carries the peer's candidates — its reflexive address as the server
observed it, plus any host addresses it supplied.

## 4. Introduce and punch

The side that connects sends `CONNECT` with a fresh 16-byte **attempt nonce**
and its candidates. The server delivers it to the peer's connection, stamped
with the caller's real `dev_id`. Now both sides know the attempt, and both do
the same thing at once: dial every candidate of the other from P, while
accepting on P. The two SYNs cross the NATs and open them — a TCP simultaneous
open, where neither side "connected" to the other.

The first connection to come up carries the handshake, and the others are
dropped. A connection must name its attempt before anything else happens: the
initiator's first frame carries the nonce, and a responder that dialed opens
with a short hello naming it. A connection that names no attempt of ours, or
says nothing for ten seconds, is closed.

When both sides introduce themselves at once, each with its own nonce, the
smaller `dev_id`'s wins. A live session is never given up for a new
introduction — claiming to be the same peer proves nothing, and a working
connection is worth more than a new one.

**Symmetric NAT defeats punching.** A symmetric NAT allocates a fresh external
port per destination, so the port the server observed is not the port a peer
must hit. The punch simulator's tests assert this rather than papering over it.

## 5. Handshake

`Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s` for a keyed topic, `Noise_NN_...` for an
open one, whichever way the TCP connection went: the numerically smaller
`dev_id` is always the initiator. Before anything else, a prologue is mixed in:

```
prologue = "uconnect:v2:tcp" || topic_id || key_epoch || attempt_nonce
```

Both sides must agree on the topic, the key epoch and the exact introduction,
or the handshake fails cryptographically rather than through a check someone
remembered to write. The node accepts each nonce once, for the one peer it was
issued for, so a replayed first message goes nowhere.

Failures are **silent**. A bad PSK, a stale attempt, a malformed message — the
connection is closed with nothing said. Any error reply would turn a peer into
an oracle for topic membership.

## 6. Records

After the handshake, everything on the connection is an AEAD record:

```
u32 length | AEAD(kind || body)
```

TCP delivers in order and loses nothing, so nonces are sequential and never
travel; each direction's key is ratcheted every 2²⁰ records. The session owns a
few kinds — keepalive, close — and the node the rest: messages, and the
datagram channel's signaling. A length above the 1 MiB ceiling ends the
connection before anything is buffered.

## When punching fails: the TCP relay

After `punch_timeout` the smaller `dev_id` asks the server for a relay (the
other asks too, a little later, in case the first request went nowhere; the
server hands both the same binding). Each side gets its own token, and opens a
**second** connection to the server whose first frame joins the relay. Once both
legs are in, the server splices raw bytes between them — and the two nodes run
exactly the same handshake over the splice, bound to the same attempt nonce.

The relay forwards **opaque ciphertext**. It sits below the crypto layer, so the
session is still end-to-end authenticated and forward-secret, and the server
learns only that two `dev_id`s are exchanging bytes and how many. Each binding
has a byte budget, and a splice stops reading from a sender whose receiver has
fallen behind rather than buffer without bound.

`Node::Config::force_relay` skips punching entirely — the only practical way
to exercise the relay from a network where punching happens to work.

## The datagram channel

Opened on demand, over the TCP session:

1. The node opens a UDP socket (on P's number when free) and asks the server
   `WhoAmI` to learn its UDP mapping. The request is padded so the answer is
   never larger than what provoked it.
2. Each side sends an **offer** record: the channel's epoch and its UDP
   candidates.
3. Both punch, with probes tagged under the channel's **probe key**. Only the
   peer holds it, so nobody else can make a node answer — a scanner never
   learns anything is listening.
4. Datagrams are sealed with keys exported from the TCP handshake, under their
   own labels:

```
root(0) = exported
root(n+1) = HKDF(root(n), "uconnect:v3:udp:next")
send, recv, probe, conn_id = HKDF(root(epoch), salt = epoch, "uconnect:v2:udp:...")
```

The **epoch** matters more than it looks. The UDP channel numbers its packets
from zero, and the packet number is the nonce; a channel reopened under the
previous one's keys would reuse every nonce. Every channel on a session gets a
new epoch, so every channel gets new keys.

Deriving a channel consumes its epoch root: only the next root remains, and
initial traffic-key copies are erased after constructing the channel. Retired
epochs cannot be derived again. Epoch skips are limited to 64 to bound work.
The TCP handshake prologue is now `uconnect:v4:tcp`; upgrade both peers together.
Older peer libraries fail the handshake rather than silently disagreeing about
UDP keys or rekey schedules. The rendezvous control protocol remains version 2.

Each authenticated datagram offer includes the sender's preferred rekey shift.
The channel uses the smaller of the two shifts, fixed before UDP traffic starts.
Malformed offers are ignored, and a repeated offer cannot change an active
channel's schedule.

If punching fails, the fallback applies. For `Relay`, a UDP relay binding is
allocated like the TCP one, each side binds its UDP address to it with its
token, and datagrams travel wrapped in `RelayData` — still sealed end to end.
A late punch always wins over the relay or TCP.

When only one peer sends application datagrams through the UDP relay, the other
still sends encrypted UDP keepalives to maintain that incoming path. Its own
application datagrams continue to follow its selected TCP or None policy.

### Replay window and key generations

Datagrams are authenticated with a 64-packet replay window, IPsec style: a
high-water mark plus a bitmap of the counters below it. UDP reorders, so a
strictly-increasing check would drop legitimate packets and accepting anything
would permit replay.

Keys ratchet every 2¹⁶ packets. Retired generation keys are erased; the receiver
retains one previous generation for reordering. Compromise of the remaining
key state cannot reconstruct generations older than those retained:

```
gen  = counter >> rekey_shift
k(0) = the channel's key
k(n) = rekey(k(n-1))              // Noise s11.3, one-way
```

**The generation is a function of the packet counter, which is already in every
header.** That is the whole design. The usual way to rekey is to coordinate a
switch — a key-phase bit, a rule for retiring the old key, a rule for when it is
safe to discard it. Here there is nothing to coordinate, because both ends
compute the generation from a value that arrived with the packet. Each direction
ratchets independently on its own counter.

That matters because of how the failure would present. If two ends disagree
about the current key, the receiver decrypts with the wrong one, the AEAD tag
fails, and a failed tag is dropped silently — so a desynchronised rekey is
indistinguishable from total packet loss, with no counter or log line anywhere
to say otherwise.

Two details carry the safety:

- **Nothing mutates before the AEAD verifies.** Key selection has to happen on
  an unauthenticated counter, so a forged packet must cost a dropped packet and
  nothing more — never an advanced generation, and never a discarded key that
  real traffic still needed.
- **The forward jump is bounded.** An unauthenticated counter decides how much
  derivation to do, so a packet claiming counter 2⁶⁰ would otherwise walk the
  ratchet 2⁴⁴ times.

Only the previous generation is kept, and that is provable rather than guessed:
the replay window refuses anything more than 64 counters behind the high-water
mark, so once a generation exceeds 64 packets a straggler can be at most one
generation old.

The channel survives an address change: matching on `conn_id` rather than the
4-tuple means a NAT rebind keeps it alive, once the AEAD verifies that the peer
arriving from the new address really is the peer.

## Saying goodbye

`Topic::disconnect()` and `Node::shutdown()` send a sealed `Close` record with a
reason, then close the connection. The peer learns at once, and knows why.

On the datagram channel, a `Close` is the same envelope as a data packet —
`conn_id`, counter, ciphertext — sealed against **its own type byte as
associated data**. The header is not covered by the AEAD tag, so if a close and
a data packet were sealed the same way, anyone on path could flip one byte —
`0x40` to `0x41` — and tear down a channel they cannot read. There are tests for
the forgery in both directions.

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

The datagram channel inherits all of this: its keys come from the same
handshake.

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
member. It stamps every introduction with the caller's real `dev_id`, so one
member cannot claim to be another either.

It *does* see metadata, in both senses: the literal `meta` blob you publish, and
the traffic patterns of who looks up what, who connects to whom and when. For a
relayed pair it also sees byte counts. If that matters for your threat model,
run your own — it is a single static binary with no configuration and no
database.

## Key handling

`K` is never used directly. The Noise PSK is derived with domain-separated HKDF,
so a leak in one use cannot cross into another:

```
psk = HKDF(K, "uconnect:v1:psk", 32)   -> mixed into the Noise handshake
```

Everything else is keyed from the handshake: the TCP records by the Noise split,
and each datagram channel by an exported secret under its own labels and epoch,
so the two channels share no key.

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
  defence. Record sizes and timing are visible to anyone on path.
- **Denial of service resistance for peers.** The server has quotas and
  rate limits; a peer does not. An authenticated member can flood you.
- **Anything about the application layer.** What a message means and what a
  peer is allowed to say are yours.

## Abuse resistance on the server

- **TCP for everything that answers.** Every reply the server gives on TCP goes
  to an address that completed a handshake, so it cannot be aimed at a spoofed
  victim; the old UDP protocol's Retry cookies are gone with it. The UDP
  replies that remain never exceed the request that provoked them.
- **Random sampling.** `LOOKUP` returns a random sample, capped at 30 by default
  and 100 at most, never the whole swarm.
- **Quotas** per source IP, per topic and overall, and on connections per IP.
  Generous by default because a corporate NAT legitimately has many devices
  behind one address; tune against the rejection counters rather than by
  guessing.
- **Byte budgets.** Each control connection has a token bucket, and one that
  runs through it is closed rather than slowed. UDP has its own per-IP budget,
  and each relay binding a byte ceiling.
- **Bounded everything.** Frame sizes, record sizes, relay splice buffers,
  queued bytes per peer. A peer chooses how much of each it asks for, so each
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
waited on with `poll` (`WSAPoll` on Windows, where `select` stops at 64
sockets), not `epoll` or `kqueue`, so the same code serves every platform.
Apple Silicon needs nothing special: the vendored X25519 and Poly1305 are
portable C with no intrinsics and no endianness assumptions.

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
handshake, exchange messages, and learn why the other left.

An interactive chat over the same library:

```sh
./build/examples/chat/uconn-chat --server 127.0.0.1:4433 --topic 'uconn://...' --nick alice
```

And a transfer, which verifies every byte of a megabyte of messages and then
sends a burst of datagrams. Add `--relay` to both to force the path through the
server, and `--dgram-fallback relay|tcp|none` to pick where datagrams go then:

```sh
./build/examples/uconn-transfer --server 127.0.0.1:4433 --topic 'uconn://...' --recv
./build/examples/uconn-transfer --server 127.0.0.1:4433 --topic 'uconn://...' --send 1048576 --dgrams 500
```

`scripts/transfer-smoke.sh` runs that pair over the punched and the relayed
paths and fails unless the bytes arrive intact and the datagrams mostly do.

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

---

# Running your own server

The public instance is best-effort and restarts on every push. For anything that
matters, run your own — it is one static binary with no configuration file, no
database and no state worth backing up.

## The short version

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/server/uconnect-rendezvous --port 4433
```

That is a working rendezvous server. Everything below is about keeping it up.

**Open the port, for TCP and UDP.** This is the step people miss, and the
failure mode is a server that starts cleanly, logs nothing wrong, and answers
nobody. TCP carries every node's connection and the TCP relay — without it
nothing connects at all. UDP carries datagram channels' address discovery and
the UDP relay.

```sh
ufw:       sudo ufw allow 4433/tcp && sudo ufw allow 4433/udp
firewalld: sudo firewall-cmd --add-port=4433/tcp --add-port=4433/udp --permanent \
             && sudo firewall-cmd --reload
```

On a cloud VM the OS firewall is **not the only one in the path** — AWS, GCP,
Azure and Oracle all have their own, and both must allow it.

## As a service

```sh
sudo cp build/server/uconnect-rendezvous /usr/local/bin/
sudo cp deploy/uconnect-rendezvous.service /etc/systemd/system/
sudo systemctl enable --now uconnect-rendezvous
```

The unit is locked down hard — `DynamicUser`, `ProtectSystem=strict`,
`MemoryDenyWriteExecute`, a `@system-service` syscall filter — because the server
holds no keys, opens no files and writes nothing to disk.

One counter-intuitive line in it is deliberate:

```ini
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
```

`AF_UNIX` and `AF_NETLINK` look unnecessary for a process that only speaks TCP
and UDP, but glibc's resolver talks to `nscd`/`systemd-resolved` over a unix
socket and `getifaddrs()` uses netlink. Restricting to the internet families
alone makes the startup STUN lookup fail with a misleading "no reply".

## Oracle Cloud

Oracle puts **two** firewalls in front of an instance and its stock images ship
an iptables chain that rejects everything but SSH. A script handles the instance
side, for both protocols, and prints exactly what to click for the cloud side:

```sh
git clone https://github.com/AbdoWise-z/uconnect && cd uconnect
sudo bash deploy/oracle-setup.sh --port 4433
```

The cloud side needs **two** ingress rules, TCP and UDP. The one that catches
people out is the direction: **Source `0.0.0.0/0`, Destination port 4433** — not
source port 4433. A reversed rule looks plausible in the console and passes no
traffic.

## Docker

```sh
docker build -t uconnect-rendezvous .
docker run --rm -p 4433:4433/tcp -p 4433:4433/udp uconnect-rendezvous
```

Publish **both**. With only one, the container looks perfectly healthy while
half the protocol is unreachable.

The image is `FROM scratch` with a single static binary — no libc, no shell,
nothing to mount. The build runs the test suite and fails if it does not pass.

`deploy/fly.toml` covers Fly.io, which carries raw TCP and UDP. Two things there
will silently produce a server that answers nothing over UDP: UDP needs a
**dedicated** IPv4 address (the shared one is HTTP-only), and the process must
bind UDP to `fly-global-services` rather than `0.0.0.0` — which is what `--bind`
does; TCP always listens on every interface.

---

# Auto-deploying from GitHub

A watcher polls the repo and redeploys when `master` moves.

```sh
sudo bash deploy/install-watcher.sh                    # server only
sudo bash deploy/install-watcher.sh --with-web         # plus the dashboard
sudo bash deploy/install-watcher.sh --branch dev --interval 300
```

It installs a systemd timer. To point it at a fork:

```sh
sudo bash deploy/install-watcher.sh \
    --repo https://github.com/you/your-fork --branch main
```

## What it does on each tick

1. Asks the remote for `master`'s sha — a conditional query, not a fetch, so a
   network blip costs nothing
2. If it moved: fetch, reset, and **build in a tree separate from the running
   binary**
3. **Run the test suite, and refuse to install a build that fails it.** This
   process sits on the public internet; "it compiled" is not the bar
4. Keep the outgoing binary, install the new one, restart
5. **Roll back** if the service will not stay up

It also **updates itself** from the commit it is deploying, so a fix to the
deploy logic takes effect from the next tick. Two things it deliberately does
not self-update, and which still need `install-watcher.sh` re-run:
`uconnect-rendezvous.service` (the running server's lifeline — quietly
rewriting it turns a bad edit into an outage instead of a failed deploy) and its
own service/timer units (generated per host, so the repo copy is not
authoritative).

Restarting is cheap by design: records live in memory, tied to each node's
connection, and nodes reconnect and register again on their own, so a deploy
costs a few seconds of re-registration and nothing else.

```sh
journalctl -u uconnect-watch -f      # deploys
journalctl -u uconnect-rendezvous -f # the server
sudo systemctl start uconnect-watch  # deploy now
sudo /usr/local/bin/uconnect-watch --once --force   # rebuild the same commit
sudo systemctl disable --now uconnect-watch.timer   # stop watching
```

## Why polling rather than a webhook

A webhook needs an inbound HTTP listener, a second open port and a public
endpoint, on a box whose whole point is that only port 4433 is exposed. Polling
costs one conditional request a minute and needs nothing open.

---

# Customising

## Server

```sh
uconnect-rendezvous --port 4433 \
    --bind 0.0.0.0 \
    --threads 4 \
    --stale 45 \
    --max-per-ip 16 \
    --no-relay \
    --quiet
uconnect-rendezvous --config rendezvous.yaml   # every limit, from a file
uconnect-rendezvous --config rendezvous.yaml --print-config   # what is in force, then exit
uconnect-rendezvous --nat-check     # report what this host's NAT does, then exit
```

`--port` is TCP and UDP alike. `--bind` pins the UDP socket to one address; TCP
always listens on every interface. `--threads` is how many threads carry
traffic: beyond the first, each takes a share of the spliced TCP relays, and all
of them read UDP, so relayed traffic is not bound to one core. `--stale` is how
long a record may go unrefreshed before `LOOKUP` flags it. `--no-relay` refuses
relay allocations, so pairs that cannot punch fail instead of costing you
bandwidth.

Everything else -- quotas, relay limits and budgets, rate limits, connection
limits, timeouts -- is set in a YAML file given with `--config`;
`server/rendezvous.example.yaml` lists every key at its default. Flags override
the file. Tune those against real numbers rather than by guessing: unless
`--quiet` is set the server prints a `[stats]` line every 30 seconds, and the
same figures are available remotely from `uconn-demo --stats`, `uconn-observe`,
or the dashboard.

To change the deployed flags, edit `ExecStart` in
`deploy/uconnect-rendezvous.service` and re-run the installer. The watcher does
not overwrite that unit.

## Client

Everything is in `Node::Config`:

| Field | Default | Why you would change it |
|---|---|---|
| `server` | — | required |
| `bind_port` | `0` | a fixed port for a manual firewall rule |
| `keepalive` | `20s` | shorter on a mobile carrier with aggressive NAT timeouts |
| `max_total_peers` | `64` | across every topic on the node |
| `punch_timeout` | `8s` | how long to punch before the fallback |
| `force_relay` | `false` | skip punching when you know it cannot work |
| `datagram_fallback` | `Tcp` | what to do with datagrams when a peer opens a channel and UDP cannot be punched |
| `verbose` | `false` | protocol tracing to stderr |
| `rekey_shift` | `16` | preferred datagram key interval; peers agree on the smaller shift |

## Dashboard

Environment variables, listed in [web/README.md](web/README.md). The ones that
matter: `UCONNECT_SERVER`, `UCONNECT_CACHE_TTL`, `UCONNECT_REFRESH`, and `HOST`
— which defaults to loopback deliberately, because this is an unauthenticated
read-only view and defaulting to `0.0.0.0` would publish a topic directory from
whatever host happened to run it.

## Layout

```
src/wire/      message codecs, the control protocol     no dependencies
src/crypto/    BLAKE2s, ChaCha20-Poly1305, X25519, Noise, HKDF
src/path/      candidate ranking, UDP punch state machine
src/session/   TcpSession; the UDP datagram Session
src/io/        TCP and UDP sockets, poll            the ONLY target with a socket
src/api/       Node and Topic
server/        registry and control service (sans-IO), runtime, binary
third_party/   vendored X25519 and Poly1305
tests/         unit suite + a simulated network
examples/      uconn-demo, uconn-chat, uconn-transfer
tools/         uconn-observe -- reads a server's public view as JSON
web/           read-only Flask dashboard over uconn-observe
deploy/        Oracle Cloud setup, systemd units, git watcher
```

## Tests

A unit suite of nearly two hundred cases — `uconnect_tests [name]` runs the
ones whose name contains the argument — plus two end-to-end tests with real
processes: `smoke.sh` for punch, handshake, messages and goodbyes, and
`transfer-smoke.sh`, which moves a megabyte and a burst of datagrams over both
the punched and the relayed paths. `python3 web/test_observer.py` covers the
dashboard's data layer (POSIX only: it fakes the observer with a shell script).

## Benchmark

`uconn-bench` measures how fast nodes share data, by node count and path. Each
run hosts a rendezvous server in-process and a full mesh of nodes on loopback,
checks that every link takes the path under test, then has every node send to
every peer at once:

```sh
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release && cmake --build build-release
./build-release/tools/uconn-bench --server-config tools/uconn-bench.server.yaml
./build-release/tools/uconn-bench --nodes 2,4 --modes tcp,udp-relay --csv out.csv
```

Modes are `tcp` and `udp` (punched directly) and `tcp-relay` and `udp-relay`
(through the server). `tools/uconn-bench.server.yaml` lifts the server's
per-address quotas, which loopback would otherwise hit, since every node comes
from 127.0.0.1, and runs the server on four threads (`--server-threads`
overrides that). TCP is measured flat out. Datagrams are measured twice:
flooded, and then paced up a ladder of rates to find the highest at which at
least 99% arrive.

Medians of three runs on an i7-11800H (8 cores/16 threads, Windows, MinGW
Release), 2026-10-04, server on four threads. Totals are across all links; a
link is one direction between two nodes. Every datagram figure here had at
least 99.5% arriving, sent as fast as the library would take them.

| Nodes (links) | TCP | TCP relayed | UDP | UDP relayed |
|---|---|---|---|---|
| 2 (2)  | 196 MiB/s | 184 MiB/s | 63 MiB/s | 43 MiB/s |
| 4 (12) | 346 MiB/s | 316 MiB/s | 82 MiB/s | 64 MiB/s |
| 6 (30) | 469 MiB/s | 403 MiB/s | 103 MiB/s | 80 MiB/s |
| 8 (56) | 567 MiB/s | 252 MiB/s | 118 MiB/s | 84 MiB/s |

Everything shares one machine, so these are the library's ceilings, not a
network's -- and at eight nodes the nodes' loops and senders and the server's
threads together outnumber its sixteen hardware threads, which is why relayed
TCP falls back there. Datagrams are sender-bound: an application thread and
the node's loop share one lock, which the loop takes first so that it always
drains its socket. On one server thread, relayed TCP stays at 111–160 MiB/s
and relayed UDP at 37–53 MiB/s, with up to 82% lost under load.

---

# Public servers

| Rendezvous | Dashboard | Notes |
|---|---|---|
| `129.152.22.201:4433` (TCP + UDP) | http://129.152.22.201:8080 | Oracle Cloud, Ubuntu. Redeployed from `master` on every commit. |

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

Working end to end: a persistent control connection with reconnection,
registration owned by that connection, lookup with sampling, topic listing,
stats, TCP hole punching by simultaneous open, the TCP relay, `Noise_NN` /
`NNpsk0` over TCP with sealed records and a close reason, an N-peer mesh, and
on-demand UDP datagram channels — punched, relayed, or falling back to TCP as
the application chooses — with replay protection, a counter-driven key ratchet
and path migration. Plus a read-only web dashboard.

Verified over loopback against the in-process server and with real processes:
byte-verified megabyte transfers and datagram bursts over both punched and
relayed paths.

Not yet implemented:

- **Key rotation driven by `key_epoch`.** The epoch is carried in the prologue,
  but nothing rotates it. Keys do ratchet within a session; what is missing is
  rotating `K` itself across sessions.
- **Connection migration.** A device that switches Wi-Fi to cellular loses its
  TCP connections — the peer sees them end and they reconnect from scratch.
  Datagram channels survive an address change on their own, but only for as
  long as the TCP session they are keyed from.
- **Verification on real NATs.** The punch logic is exercised by the simulator
  and loopback; TCP simultaneous open across real consumer NATs, and
  `SO_REUSEPORT` port sharing on Linux, have not yet been tested in the field.
