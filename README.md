# uConnect

Peer-to-peer networking where a server only introduces peers, then gets out of
the way. Two devices sharing a topic and a secret find each other through a
rendezvous server, punch through NAT, and talk over an authenticated,
forward-secret channel the server cannot read or impersonate.

```cpp
uconnect::Node node{"rv.example.com:4433"};
node.run_in_background();

auto& topic = node.join(uconnect::TopicCreds::parse(
    "uconn://9f86d081884c7d659a2feaa0c55ad015#a3f1...e7").value());

topic.on_data([](auto dev, auto bytes) { /* ... */ });
topic.publish(meta);       // become findable
topic.connect_all(8);      // LOOKUP -> punch -> Noise handshake
topic.broadcast(payload);
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
peer must hit. A relay fallback is the answer and is **not yet implemented** —
see Status.

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

## Layout

```
src/wire/      protocol codec                      no dependencies
src/crypto/    BLAKE2s, ChaCha20-Poly1305, X25519, Noise, HKDF
src/path/      candidate ranking, punch state machine
src/session/   Noise session, replay window, path migration
src/io/        UDP sockets                         the ONLY target with a socket
src/api/       Node and Topic
server/        record store (sans-IO) + UDP service + binary
third_party/   vendored X25519 and Poly1305
tests/         unit suite + a simulated network
examples/      uconn-demo
```

Layering is enforced by CMake: if `uconnect_path` ever needs to link
`uconnect_io`, the build says so.

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

## Tests

139 unit cases plus an end-to-end smoke test.

The crypto is validated against published vectors — RFC 7693 (BLAKE2s),
RFC 8439 §2.3.2/§2.5.2/§2.8.2 (ChaCha20, Poly1305, the full AEAD with exact
ciphertext and tag), RFC 7748 §5.2/§6.1 (X25519). This is not decoration: every
one of these primitives is self-consistent when implemented wrongly, and two
peers running the same broken code will complete a handshake and talk happily to
each other. Only the vectors distinguish "works" from "correct".

## Status

Working end to end: registration, keepalive with rebinding, lookup with
sampling, topic listing, stats, the relay that coordinates simultaneous
punching, candidate ranking, punching, `Noise_NN`/`NNpsk0`, authenticated
transport with replay protection, path migration, and an N-peer mesh.

Not yet implemented:

- **Relay fallback for symmetric NAT.** The known gap. Punching covers roughly
  80–90% of pairs; the rest need a relay. It belongs *below* the crypto layer so
  the relay forwards opaque ciphertext and learns only metadata.
- **REST front end.** The store is sans-IO so an HTTP service sits beside the
  UDP one. It must be read-only, for the registration reason above.
- **In-place rekey.** Sessions have a 15-minute lifetime and then ask for a
  fresh handshake. Rekeying needs both ends to step in lockstep, and getting it
  wrong desynchronises a session in a way that looks like packet loss.
- **Key rotation.** `key_epoch` is carried on the wire and in the prologue but
  nothing drives it yet.
- **Reliability/ordering.** Transport is datagrams. There is no retransmission
  or stream layer above it.
- **`Topic::set_auto_connect`** is stored but not acted on.
