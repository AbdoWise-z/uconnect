#pragma once
// uConnect public API.
//
//   uconnect::Node node{"rv.example.com:4433"};   // server address is the only input
//   node.run_in_background();
//
//   for (auto& t : node.explore()) { ... }        // browse listed topics
//
//   auto& topic = node.join(uconnect::TopicCreds::parse("uconn://<32hex>#<64hex>"));
//   topic.on_data([](auto dev, auto bytes) { ... });
//   topic.publish(meta);                          // become findable
//   topic.connect_all(8);                         // LOOKUP -> punch -> Noise
//   topic.broadcast(payload);
//
//   node.shutdown();
//
// Connections are owned by the Topic and addressed by dev_id; there is no
// separate connection object to manage.

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "uconnect/types.hpp"

namespace uconnect {

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------
// topic_id is public -- the server indexes on it. K is secret and never
// transmitted; everything is derived from it with domain-separated HKDF.
//
// K is 32 bytes. Not 64: every construction downstream is 256-bit, so a longer
// key is compressed to 256 bits anyway and buys nothing but characters to copy.
struct TopicCreds {
    TopicId            id{};
    std::optional<Key> key;  // nullopt => open topic

    static TopicCreds generate_keyed();
    static TopicCreds generate_open();

    // uconn://<32 hex topic>[#<64 hex key>]
    static std::optional<TopicCreds> parse(std::string_view uri);
    std::string                      to_uri() const;

    bool is_keyed() const { return key.has_value(); }
};

// ---------------------------------------------------------------------------
// Peers
// ---------------------------------------------------------------------------
enum class PeerState : uint8_t {
    Unknown,
    Probing,       // punching
    Handshaking,   // path validated, running Noise
    Connected,
    Failed,        // no candidate answered
    Closed,
};

const char* to_string(PeerState);

struct PeerInfo {
    DevId                dev_id{};
    std::chrono::seconds age{0};
    bool                 stale = false;
    std::vector<uint8_t> meta;  // empty unless want_meta
};

struct TopicSummary {
    TopicId   id{};
    TopicMode mode        = TopicMode::Open;
    uint32_t  peers       = 0;
    uint32_t  fresh_peers = 0;
};

struct ServerStats {
    uint64_t topics_total = 0, topics_listed = 0;
    uint64_t entries_total = 0, entries_fresh = 0;
    uint64_t registers = 0, keepalives = 0, lookups = 0, connects = 0;
    uint64_t rebinds = 0, expired = 0;
    uint64_t rej_bad_auth = 0, rej_quota = 0, rej_rate_limited = 0;
    uint64_t relays_open = 0, relays_allocated = 0, relay_bytes = 0;
};

class Node;
class Topic;

// ---------------------------------------------------------------------------
// Stream
// ---------------------------------------------------------------------------
// A reliable, ordered byte stream to one peer -- the guarantees TCP gives,
// layered over the datagram session.
//
// Streams are multiplexed, so head-of-line blocking is per stream rather than
// per connection: a lost packet on one stream stalls that stream while the
// others keep flowing. That is the reason this is built on datagrams instead
// of a single ordered pipe, and it is not something TCP can offer.
//
// This is a lightweight handle, not an owner. The Topic owns the stream state;
// copying a Stream is free and safe, and a handle to a stream that has since
// closed simply reports zero/false rather than misbehaving.
using StreamId = uint64_t;

// Why a peer connection ended, delivered with on_peer_closed.
//
// The first two are our own account of events; the rest come from the peer.
// The distinction is not cosmetic: a peer that crashes says nothing, so
// TimedOut is what a vanished peer looks like, and anything else means the
// peer was still alive enough to say goodbye.
enum class PeerGone : uint8_t {
    Local,        // we disconnected, or shut down
    TimedOut,     // silence: crash, cable pull, NAT rebind, or a failed handshake
    GoingAway,    // the peer's application closed this connection
    ShuttingDown, // the peer's node is exiting
    Unspecified,  // the peer said goodbye without saying why
};
const char* to_string(PeerGone);

// A snapshot of one peer connection. Everything here is diagnostic -- nothing
// in the protocol depends on it -- but `relayed` is worth surfacing to users:
// a relayed connection is still end-to-end encrypted, yet it puts the
// rendezvous server back in the path where it can see traffic patterns.
struct LinkInfo {
    bool relayed = false;   // going through the rendezvous server, not direct

    std::chrono::milliseconds rtt{0};      // smoothed, from the stream layer
    size_t   congestion_window = 0;
    size_t   bytes_in_flight   = 0;
    bool     slow_start        = false;

    uint64_t datagrams_sent     = 0;       // session level
    uint64_t datagrams_received = 0;
    uint64_t packets_sent       = 0;       // stream level
    uint64_t packets_lost       = 0;

    size_t open_streams = 0;
};

class Stream {
public:
    Stream() = default;

    // Returns bytes accepted. A short count is backpressure -- flow control or
    // the send buffer cap -- not an error; retry when the peer's window opens.
    size_t write(std::span<const uint8_t> data);

    // Reads the contiguous prefix only, so bytes always arrive in the order
    // they were written. Returns bytes copied; 0 means nothing is ready yet.
    size_t read(std::span<uint8_t> out);

    // Half-close: no more writes from us. On a bidirectional stream the other
    // direction stays open, so the stream is only released once BOTH ends
    // finish. For a one-way transfer open the stream unidirectional -- it then
    // retires as soon as the receiver has drained it.
    void finish();

    // Abort our sending direction, discarding anything pending. On a
    // bidirectional stream the peer may still send to us; use close() to end
    // both directions.
    void reset(uint64_t error_code = 0);

    // End the stream in both directions without needing the other application
    // to cooperate. The peer is told to stop sending and answers by aborting
    // its own direction, which is what releases this side.
    //
    // This closes a stream, not the connection: the session and every other
    // stream on this peer keep running.
    void close(uint64_t error_code = 0);

    // Tell the peer to stop sending, without touching our own direction. The
    // peer answers by aborting its side, so this is how a reader says "I have
    // what I need" while still having something left to write.
    void stop_sending(uint64_t error_code = 0);

    bool   readable() const;
    size_t readable_bytes() const;
    bool   writable() const;
    bool   finished() const;             // peer sent FIN and we have read it all

    StreamId id() const { return id_; }
    DevId    peer() const { return peer_; }
    bool     valid() const { return topic_ != nullptr; }
    explicit operator bool() const { return valid(); }

private:
    friend class Topic;
    Stream(Topic* t, DevId p, StreamId i) : topic_(t), peer_(p), id_(i) {}

    Topic*   topic_ = nullptr;
    DevId    peer_{};
    StreamId id_ = 0;
};

// ---------------------------------------------------------------------------
// Topic
// ---------------------------------------------------------------------------
class Topic {
public:
    ~Topic();
    Topic(const Topic&)            = delete;
    Topic& operator=(const Topic&) = delete;

    // --- membership --------------------------------------------------------
    // REGISTER with the server and start the ~20s keepalive. Until this is
    // called the node can find others but cannot be found.
    // Topics appear in the public listing by default. Pass unlisted=true to
    // keep this one out of it.
    //
    // Hiding is sticky and topic-wide: one member asking for it hides the
    // topic from everyone, for as long as the topic exists. Being unlisted is
    // not secrecy -- anyone holding the topic_id can still look the topic up,
    // because that is how peers find each other. It only means the topic is
    // absent from the directory.
    bool publish(std::span<const uint8_t> meta = {}, bool unlisted = false);
    void unpublish();
    std::optional<DevId> self() const;

    // --- discovery ---------------------------------------------------------
    // Returns a random sample, never the whole swarm. Capped at 30 by default
    // and 100 at most: a 5000-peer topic would otherwise be an amplification
    // hazard and an invitation to punch 5000 paths.
    std::vector<PeerInfo> peers(uint8_t max = 30, bool want_meta = false,
                                std::chrono::milliseconds timeout = std::chrono::seconds(3));
    std::optional<PeerInfo> resolve(const DevId&,
                                    std::chrono::milliseconds timeout = std::chrono::seconds(3));

    // --- connections, owned here, addressed by dev_id ----------------------
    void connect(const DevId&);
    void connect_all(size_t max_peers = 8);
    void disconnect(const DevId&);
    void disconnect_all();

    std::vector<DevId> connected() const;
    PeerState          state(const DevId&) const;

    // Diagnostics for one connected peer. Nullopt if there is no live session.
    std::optional<LinkInfo> link(const DevId&) const;

    // --- datagrams ---------------------------------------------------------
    // Unreliable and unordered, like the session underneath. Fine for things
    // that are cheap to lose -- presence, telemetry, a game tick. Use a Stream
    // when delivery matters.
    bool   send(const DevId&, std::span<const uint8_t>);
    size_t broadcast(std::span<const uint8_t>);

    // --- streams -----------------------------------------------------------
    // Reliable and ordered. Available once a peer reaches PeerState::Connected.
    // Returns an invalid handle if the peer is not connected, or if this peer
    // already has the configured maximum number of streams open.
    Stream open_stream(const DevId&, bool bidirectional = true);
    Stream stream(const DevId&, StreamId);          // handle to an existing one
    std::vector<StreamId> streams(const DevId&) const;

    // --- events (invoked on the node's loop thread; do not block) ----------
    void on_peer(std::function<void(DevId, PeerState)>);
    void on_data(std::function<void(DevId, std::span<const uint8_t>)>);

    // Fires alongside the PeerState::Closed transition, with the reason. Use
    // this to tell a peer that said goodbye from one that simply vanished --
    // the first is worth reporting calmly, the second is worth retrying.
    void on_peer_closed(std::function<void(DevId, PeerGone)>);

    // The peer opened a stream. Nothing is readable yet -- wait for
    // on_stream_readable, or just try to read.
    void on_stream(std::function<void(Stream)>);
    void on_stream_readable(std::function<void(Stream)>);
    void on_stream_finished(std::function<void(Stream)>);

    // Flow control reopened after a short write. Retry the write from here
    // rather than polling writable() on a timer.
    void on_stream_writable(std::function<void(Stream)>);

    // The stream was aborted -- by the peer, or by us because the peer overran
    // the receive window. No further bytes will arrive on it.
    void on_stream_reset(std::function<void(Stream, uint64_t error_code)>);

    // Both directions are done and the state behind the handle has been
    // released. The handle stays safe to call; it just reports empty.
    void on_stream_closed(std::function<void(Stream)>);

    // --- policy ------------------------------------------------------------
    void set_max_peers(size_t);
    void set_auto_connect(bool);

    const TopicId& id() const;

    // False for open topics. An open topic is encrypted against a passive
    // observer and nothing else: anyone on path, including the rendezvous
    // server, can MITM it undetectably. Check this before trusting a peer.
    bool is_authenticated() const;

    // Short Authentication String for a connected peer on an open topic.
    // Compare out of band; matching strings prove there is no MITM.
    std::optional<std::string> sas(const DevId&) const;

    // Unique per session, identical on both ends. An application layer adding
    // its own identity MUST sign this value -- otherwise an insider (anyone
    // holding K) can relay another peer's identity proof into a second session
    // and impersonate them.
    std::optional<std::array<uint8_t, 32>> channel_binding(const DevId&) const;

private:
    friend class Node;
    friend class Stream;
    struct Impl;
    explicit Topic(std::unique_ptr<Impl>);

    // Disconnect carrying a specific wire close reason. Private because the
    // reason codes are a wire-layer detail; Node uses it so that a shutdown
    // tells peers the node is exiting rather than that one link was dropped.
    void disconnect_all_with_reason(uint16_t reason);
    void drop_peer_locked(const DevId&, uint16_t reason);

    std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------
class Node {
public:
    struct Config {
        std::string          server;            // the only required field
        uint16_t             bind_port = 0;     // 0 = ephemeral
        std::chrono::seconds keepalive{20};
        size_t               max_total_peers = 64;

        // Skip punching and go straight to the relay. Normally the relay is a
        // fallback taken only after probing fails, but forcing it is the only
        // practical way to exercise that path from a network where punching
        // happens to work -- and it is what a peer on a known-symmetric NAT
        // would want anyway, to avoid wasting seconds on probes that cannot
        // succeed.
        bool                 force_relay     = false;
        bool                 verbose         = false;

        // --- stream tuning -------------------------------------------------
        // Receive window for one stream. The main memory-against-throughput
        // knob: a long fat path needs a window near bandwidth x delay to keep
        // the pipe full, and the cost is per stream.
        size_t stream_recv_window = 256 * 1024;

        // Receive window across every stream on one peer, so many half-idle
        // streams cannot together pin far more than one busy stream would.
        size_t conn_recv_window = 1024 * 1024;

        // Concurrent streams per peer, counted separately for each end's
        // streams. open_stream returns an invalid handle once ours are used up,
        // and inbound frames past the peer's share are dropped -- each stream
        // costs buffers, and the peer chooses how many ids it puts on the wire.
        size_t max_streams_per_peer = 64;

        // Ratchet the transport keys every 2^rekey_shift packets, so traffic
        // older than the current generation cannot be recovered from a later
        // compromise. Driven by the packet counter, which travels in every
        // header, so both ends agree without negotiating anything.
        //
        // Must stay above 64 (the replay window width): that is what bounds a
        // reordered packet to at most one generation old. Lower it only to
        // exercise the boundary in a test.
        uint8_t rekey_shift = 16;
    };

    explicit Node(Config);
    explicit Node(std::string server);
    ~Node();
    Node(const Node&)            = delete;
    Node& operator=(const Node&) = delete;

    // --- discovery without joining ----------------------------------------
    std::vector<TopicSummary> explore(size_t limit = 100,
                                      std::chrono::milliseconds timeout = std::chrono::seconds(3));
    std::optional<ServerStats> stats(std::chrono::milliseconds timeout = std::chrono::seconds(3));

    // --- topics ------------------------------------------------------------
    // References stay valid until leave() or shutdown() -- the only two places
    // that invalidate them, and both are explicit.
    Topic& join(const TopicCreds&);
    Topic& create(bool keyed = true);
    void   leave(const TopicId&);

    std::vector<TopicId> topics() const;
    const TopicCreds*    creds(const TopicId&) const;

    // --- lifecycle ---------------------------------------------------------
    void run();                // blocking
    void run_in_background();
    void shutdown();           // UNREGISTER everything, close sessions, stop

    bool     is_running() const;
    uint16_t local_port() const;

    // Our reflexive address as the server last reported it, once registered.
    std::optional<Endpoint> reflexive() const;

private:
    // Topic::Impl holds a Node::Impl* -- a nested class inherits its enclosing
    // class's access, so befriending Topic is enough.
    friend class Topic;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace uconnect
