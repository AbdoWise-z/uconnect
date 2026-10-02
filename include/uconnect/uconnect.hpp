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
//   topic.connect_all(8);                         // LOOKUP -> punch TCP -> Noise
//   topic.broadcast(payload);
//
//   node.shutdown();
//
// Connections are owned by the Topic and addressed by dev_id; there is no
// separate connection object to manage.
//
// Transport. Each peer connection is one TCP connection: punched directly when
// the NATs allow, relayed through the rendezvous server when they do not. The
// Noise handshake runs over it, so it carries the session's keys, and every
// message on it is reliable, ordered and encrypted. A UDP datagram channel can
// be opened beside it on demand, keyed from the same handshake.

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
    Probing,       // dialing: punching TCP, or waiting on a relay
    Handshaking,   // a connection is up, running Noise
    Connected,
    Failed,        // no path: punching failed and no relay could be had
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
    uint64_t registers = 0, lookups = 0, connects = 0, expired = 0;
    uint64_t rej_quota = 0, rej_rate_limited = 0;
    uint64_t relays_open = 0, relays_allocated = 0, relay_bytes = 0;
    uint64_t connections = 0;  // control connections open on the server
};

class Node;
class Topic;

// Why a peer connection ended, delivered with on_peer_closed.
//
// The first two are our own account of events; the rest come from the peer.
// The distinction is not cosmetic: a peer that crashes says nothing, so
// TimedOut is what a vanished peer looks like, and anything else means the
// peer was still alive enough to say goodbye.
enum class PeerGone : uint8_t {
    Local,        // we disconnected, or shut down
    TimedOut,     // silence or a dropped connection: crash, cable pull, NAT timeout
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
    bool relayed = false;  // through the rendezvous server, not direct

    uint64_t messages_sent     = 0;
    uint64_t messages_received = 0;
    uint64_t bytes_sent        = 0;  // message payload bytes
    uint64_t bytes_received    = 0;

    uint64_t datagrams_sent     = 0;  // however they travelled
    uint64_t datagrams_received = 0;
};

// ---------------------------------------------------------------------------
// Datagrams
// ---------------------------------------------------------------------------
// Messages ride the peer's TCP connection: reliable and ordered, which also
// means one lost segment holds up everything behind it. Datagrams are the
// other option -- unreliable, unordered, never waiting on each other -- for
// traffic where late is as bad as lost: voice, game state, telemetry.
//
// They need a UDP path of their own, opened on demand with open_datagrams().
// The keys come from the TCP connection's handshake, so a datagram channel
// authenticates the same peer and needs no handshake of its own; UDP is only
// punched. Where that fails, the application chooses what happens:
enum class DatagramFallback : uint8_t {
    // Send datagrams over the TCP connection instead. Always available and
    // costs nothing extra, but they arrive reliably and in order -- that is,
    // late rather than lost when the network drops something.
    Tcp,
    // Relay them through the rendezvous server's UDP relay. Stays unreliable
    // and low-latency, but puts the server in the path (still end-to-end
    // encrypted) and spends its relay budget, which is finite per pair.
    Relay,
    // No datagrams for this peer; send_datagram() returns false.
    None,
};

enum class DatagramPath : uint8_t {
    None,     // no channel open
    Opening,  // exchanging addresses, punching, or binding the relay
    Direct,   // punched UDP
    Relayed,  // the rendezvous server's UDP relay
    Tcp,      // falling back over the TCP connection
    Failed,   // no path, and the fallback was None (or the relay refused)
};

const char* to_string(DatagramPath);

// ---------------------------------------------------------------------------
// Topic
// ---------------------------------------------------------------------------
class Topic {
public:
    ~Topic();
    Topic(const Topic&)            = delete;
    Topic& operator=(const Topic&) = delete;

    // --- membership --------------------------------------------------------
    // REGISTER with the server. Until this is called the node can find others
    // but cannot be found. Topics appear in the public listing by default;
    // pass unlisted=true to keep this one out of it.
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
    // and 100 at most: a 5000-peer topic would otherwise be an invitation to
    // dial 5000 peers.
    std::vector<PeerInfo> peers(uint8_t max = 30, bool want_meta = false,
                                std::chrono::milliseconds timeout = std::chrono::seconds(3));
    std::optional<PeerInfo> resolve(const DevId&,
                                    std::chrono::milliseconds timeout = std::chrono::seconds(3));

    // --- connections, owned here, addressed by dev_id ----------------------
    // Needs publish(): the server introduces a peer only to a registered one.
    void connect(const DevId&);
    void connect_all(size_t max_peers = 8);
    void disconnect(const DevId&);
    void disconnect_all();

    std::vector<DevId> connected() const;
    PeerState          state(const DevId&) const;

    // Diagnostics for one connected peer. Nullopt if there is no live session.
    std::optional<LinkInfo> link(const DevId&) const;

    // --- messages ----------------------------------------------------------
    // Reliable and ordered: each message arrives whole, once, in the order
    // sent, as one on_data call. Up to max_message() bytes. False if the peer
    // is not connected, the message is too large, or the peer is reading so
    // slowly that 16 MiB is already waiting for it -- try again later.
    bool   send(const DevId&, std::span<const uint8_t>);
    size_t broadcast(std::span<const uint8_t>);

    static constexpr size_t max_message() { return 1u << 20; }

    // --- datagrams ---------------------------------------------------------
    // Open a datagram channel to a connected peer. Asynchronous: watch
    // datagram_path() or on_datagram_path() for it to leave Opening. The peer
    // accepts automatically, applying its own Node::Config::datagram_fallback
    // to its sending side. False if the peer is not connected.
    bool open_datagrams(const DevId&, DatagramFallback = DatagramFallback::Tcp);
    void close_datagrams(const DevId&);
    DatagramPath datagram_path(const DevId&) const;

    // Unreliable and unordered, up to max_datagram() bytes -- small enough to
    // cross any path, relay included, without IP fragmentation. False if there
    // is no usable path (still Opening, Failed, or no channel) or the datagram
    // is too large, or the shared TCP output queue is full when using the TCP
    // fallback (retry after it drains); true means sent, not delivered.
    bool send_datagram(const DevId&, std::span<const uint8_t>);

    static constexpr size_t max_datagram() { return 1100; }

    // --- events (invoked on the node's loop thread; do not block) ----------
    // Synchronous publish(), peers(), resolve(), Node::explore() and
    // Node::stats() reject calls on this thread immediately (false, empty, or
    // nullopt) without sending a request. connect_all() is consequently a
    // no-op here. Run those calls on an application thread instead.
    void on_peer(std::function<void(DevId, PeerState)>);
    void on_data(std::function<void(DevId, std::span<const uint8_t>)>);
    void on_datagram(std::function<void(DevId, std::span<const uint8_t>)>);
    void on_datagram_path(std::function<void(DevId, DatagramPath)>);

    // Fires alongside the PeerState::Closed transition, with the reason. Use
    // this to tell a peer that said goodbye from one that simply vanished --
    // the first is worth reporting calmly, the second is worth retrying.
    void on_peer_closed(std::function<void(DevId, PeerGone)>);

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
    struct Impl;
    explicit Topic(std::unique_ptr<Impl>);

    // Disconnect carrying a specific close reason. Private because the reason
    // codes are a wire-level detail; Node uses it so that a shutdown tells
    // peers the node is exiting rather than that one link was dropped.
    void disconnect_all_with_reason(uint16_t reason);

    std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------
class Node {
public:
    struct Config {
        std::string server;  // the only required field: host:port

        // The node's one TCP port: it listens here, keeps its connection to
        // the server from here, and punches to peers from here, because the
        // NAT mapping of this port is the address peers are told to dial.
        // 0 = ephemeral.
        uint16_t bind_port = 0;

        // How often each published topic is refreshed with the server. The
        // same traffic keeps the NAT mapping of the node's port alive.
        std::chrono::seconds keepalive{20};

        size_t max_total_peers = 64;

        // How long to punch before falling back to the relay.
        std::chrono::seconds punch_timeout{8};

        // Skip punching -- TCP and UDP alike -- and go straight to the
        // fallback: the TCP relay for connections, the datagram fallback for
        // datagrams. Normally those are taken only after punching fails, but
        // forcing it is the only practical way to exercise them from a network
        // where punching happens to work -- and what a peer on a
        // known-symmetric NAT wants anyway, to avoid seconds of dialing that
        // cannot succeed.
        bool force_relay = false;
        bool verbose     = false;

        // What this node does with datagrams when a peer opens a channel to
        // it and UDP cannot be punched. open_datagrams() takes its own.
        DatagramFallback datagram_fallback = DatagramFallback::Tcp;

        // Ratchet the UDP datagram channel's keys every 2^rekey_shift packets,
        // erasing retired keys (the receiver retains one previous generation
        // for reordering). Driven by the packet counter, which travels in
        // every header, so both ends agree without negotiating anything.
        //
        // A generation must stay above 64 packets (the replay window width):
        // that is what bounds a reordered packet to at most one generation
        // old. So the shift must be in 7..63; the Node constructor throws
        // std::invalid_argument otherwise.
        uint8_t rekey_shift = 16;
    };

    explicit Node(Config);
    explicit Node(std::string server);
    ~Node();
    Node(const Node&)            = delete;
    Node& operator=(const Node&) = delete;

    // --- discovery without joining ----------------------------------------
    // Listed topics, up to `limit`, starting from `cursor` (0 = the start of
    // the listing). Follows the server's paging across as many requests as
    // `limit` needs, within one overall `timeout`.
    std::vector<TopicSummary> explore(
        uint32_t cursor = 0,
        size_t limit = 100,
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
    // Tell peers and the server, close everything, stop. From a callback this
    // requests shutdown; cleanup finishes after callbacks return. From another
    // thread it waits for the loop to finish. Keep the Node alive until then;
    // destroying it inside a callback is not supported. A stopped Node cannot
    // be restarted; construct a new Node instead.
    void shutdown();

    bool     is_running() const;
    uint16_t local_port() const;  // the node's TCP port

    // Our reflexive TCP address as the server last reported it, once registered.
    std::optional<Endpoint> reflexive() const;

    // True while the control connection to the server is up.
    bool server_connected() const;

    // Requests to the rendezvous server still awaiting a reply. Diagnostic:
    // on a healthy node this stays small no matter how long it runs.
    size_t pending_requests() const;

private:
    friend class Topic;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace uconnect
