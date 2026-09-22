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

class Stream {
public:
    Stream() = default;

    // Returns bytes accepted. A short count is backpressure -- flow control or
    // the send buffer cap -- not an error; retry when the peer's window opens.
    size_t write(std::span<const uint8_t> data);

    // Reads the contiguous prefix only, so bytes always arrive in the order
    // they were written. Returns bytes copied; 0 means nothing is ready yet.
    size_t read(std::span<uint8_t> out);

    void finish();                       // half-close: no more writes from us
    void reset(uint64_t error_code = 0); // abort, discarding anything pending

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
    bool publish(std::span<const uint8_t> meta = {}, bool listed = false);
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

    // --- datagrams ---------------------------------------------------------
    // Unreliable and unordered, like the session underneath. Fine for things
    // that are cheap to lose -- presence, telemetry, a game tick. Use a Stream
    // when delivery matters.
    bool   send(const DevId&, std::span<const uint8_t>);
    size_t broadcast(std::span<const uint8_t>);

    // --- streams -----------------------------------------------------------
    // Reliable and ordered. Available once a peer reaches PeerState::Connected.
    Stream open_stream(const DevId&, bool bidirectional = true);
    Stream stream(const DevId&, StreamId);          // handle to an existing one
    std::vector<StreamId> streams(const DevId&) const;

    // --- events (invoked on the node's loop thread; do not block) ----------
    void on_peer(std::function<void(DevId, PeerState)>);
    void on_data(std::function<void(DevId, std::span<const uint8_t>)>);

    // The peer opened a stream. Nothing is readable yet -- wait for
    // on_stream_readable, or just try to read.
    void on_stream(std::function<void(Stream)>);
    void on_stream_readable(std::function<void(Stream)>);
    void on_stream_finished(std::function<void(Stream)>);

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
        bool                 verbose         = false;
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
