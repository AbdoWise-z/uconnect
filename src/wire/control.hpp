#pragma once
// uConnect control protocol v2: node <-> rendezvous server, over ONE TCP
// connection per node, kept open for as long as the node is running.
//
// Framing. TCP is a byte stream, so every message is length-prefixed:
//
//     u16 length || message          message = Header (version 2) || body
//
// kMaxFrame bounds how much a peer can make the other end buffer.
//
// What running over TCP changes, relative to the v1 UDP signaling in
// messages.hpp:
//
//  - No address-validation round trip. There are no Retry cookies and no
//    padding rules: the TCP handshake has already proved the client receives
//    at its address, so no reply here can be aimed at a spoofed victim.
//
//  - No lease tokens, MACs or sequence numbers. A record belongs to the
//    connection that registered it. Only that connection may refresh, update
//    or unregister it, or CONNECT and relay on its behalf -- and the record
//    goes when the connection does.
//
//  - No paging. A reply is one frame however many entries it carries.
//
// UDP still exists for the optional datagram channel: WhoAmI learns a node's
// UDP mapping, and UdpRelayBind / RelayData carry relayed datagrams. Those
// are sent unframed, one message per datagram, and every reply is no larger
// than the request that provoked it.

#include <optional>
#include <span>
#include <string>
#include <vector>

#include "buffer.hpp"
#include "messages.hpp"
#include "uconnect/types.hpp"

namespace uconnect::wire::ctl {

inline constexpr uint8_t kVersion  = 2;
inline constexpr size_t  kMaxFrame = 32 * 1024;

inline constexpr size_t kRelayTokenLen = 16;
using RelayToken = std::array<uint8_t, kRelayTokenLen>;

// Prepends the length. Empty if the message is too large to frame.
std::vector<uint8_t> frame(std::span<const uint8_t> message);

// Accumulates bytes read from a TCP stream and hands back whole messages.
class FrameReader {
public:
    explicit FrameReader(size_t max_frame = kMaxFrame) : max_(max_frame) {}

    // False once the stream is malformed -- a frame over the limit. Framing
    // cannot be recovered after that, so the connection should be dropped.
    bool feed(std::span<const uint8_t> bytes);

    // The next complete message, if one has arrived.
    std::optional<std::vector<uint8_t>> next();

    // Bytes received beyond the last complete frame. A relay connection
    // switches to raw bytes after its handshake; whatever arrived with that
    // frame belongs to the raw stream, not to another frame.
    std::vector<uint8_t> take_rest();

    bool broken() const { return broken_; }

private:
    std::vector<uint8_t> buf_;
    size_t               max_;
    bool                 broken_ = false;
};

// Header(v2) || body, ready to frame.
template <typename T>
std::vector<uint8_t> message(MsgType type, uint32_t txn, const T& body, uint8_t flags = 0) {
    std::vector<uint8_t> buf(kMaxFrame);
    Writer               w{buf};
    Header{type, kVersion, flags, txn}.encode(w);
    body.encode(w);
    if (!w.ok()) return {};
    buf.resize(w.size());
    return buf;
}

// A message with no body.
std::vector<uint8_t> empty_message(MsgType type, uint32_t txn, uint8_t flags = 0);

// --- registration ------------------------------------------------------------
struct Register {
    TopicId                id{};
    TopicMode              mode      = TopicMode::Open;
    uint8_t                key_epoch = 0;
    bool                   unlisted  = false;  // header flag flags::kUnlisted
    std::vector<Candidate> host_cands;         // the node's own TCP addresses
    std::vector<uint8_t>   meta;

    void encode(Writer&) const;
    static std::optional<Register> decode(Reader&, const Header&);
};

struct RegisterOk {
    DevId    dev_id{};
    Endpoint srflx{};  // the TCP mapping the server observed
    uint16_t peers_in_topic = 0;

    void encode(Writer&) const;
    static std::optional<RegisterOk> decode(Reader&);
};

// Keepalive and Unregister: which of this connection's records.
struct DevRef {
    DevId dev_id{};

    void encode(Writer&) const;
    static std::optional<DevRef> decode(Reader&);
};

struct KeepaliveOk {
    Endpoint srflx{};

    void encode(Writer&) const;
    static std::optional<KeepaliveOk> decode(Reader&);
};

struct Update {
    DevId                  dev_id{};
    std::vector<Candidate> host_cands;
    std::vector<uint8_t>   meta;

    void encode(Writer&) const;
    static std::optional<Update> decode(Reader&);
};

// --- discovery ---------------------------------------------------------------
struct Lookup {
    TopicId id{};
    uint8_t max       = kLookupDefault;
    bool    want_meta = false;  // header flag flags::kWantMeta

    void encode(Writer&) const;
    static std::optional<Lookup> decode(Reader&, const Header&);
};

struct LookupOk {
    TopicId                id{};
    TopicMode              mode  = TopicMode::Open;
    uint16_t               total = 0;
    std::vector<PeerEntry> entries;

    void encode(Writer&) const;
    static std::optional<LookupOk> decode(Reader&);
};

struct Resolve {
    DevId dev_id{};

    void encode(Writer&) const;
    static std::optional<Resolve> decode(Reader&);
};

struct Topics {
    uint32_t cursor = 0;
    uint8_t  limit  = 100;

    void encode(Writer&) const;
    static std::optional<Topics> decode(Reader&);
};

struct TopicsOk {
    uint32_t                  next_cursor = 0;  // 0 = end of the listing
    std::vector<TopicSummary> topics;

    void encode(Writer&) const;
    static std::optional<TopicsOk> decode(Reader&);
};

struct StatsOk {
    uint64_t topics_total = 0, topics_listed = 0;
    uint64_t entries_total = 0, entries_fresh = 0;
    uint64_t registers = 0, lookups = 0, connects = 0, expired = 0;
    uint64_t rej_quota = 0, rej_rate_limited = 0;
    uint64_t relays_open = 0, relays_allocated = 0, relay_bytes = 0;
    uint64_t connections = 0;

    void encode(Writer&) const;
    static std::optional<StatsOk> decode(Reader&);
};

// --- introductions and relays ------------------------------------------------
// "I am about to punch you": delivered to `to_dev` as a Relayed{from_dev,
// payload}. The payload is opaque to the server.
struct Connect {
    DevId                from_dev{};
    DevId                to_dev{};
    std::vector<uint8_t> payload;

    void encode(Writer&) const;
    static std::optional<Connect> decode(Reader&);
};

enum class RelayKind : uint8_t {
    Tcp = 0,  // a spliced TCP connection: the reliable path, when punching fails
    Udp = 1,  // forwarded datagrams: the optional datagram channel's fallback
};

struct RelayAlloc {
    DevId     from_dev{};
    DevId     peer_dev{};
    RelayKind kind = RelayKind::Tcp;

    void encode(Writer&) const;
    static std::optional<RelayAlloc> decode(Reader&);
};

// The allocator's side of a relay. Each side gets its own token, and joins
// with it: knowing the relay id alone admits nobody.
struct RelayAllocOk {
    RelayId    relay_id = 0;
    RelayToken token{};
    RelayKind  kind    = RelayKind::Tcp;
    uint32_t   max_kib = 0;  // byte budget for the binding

    void encode(Writer&) const;
    static std::optional<RelayAllocOk> decode(Reader&);
};

// Pushed by the server to the peer a relay was allocated to reach: its own
// side of the binding, and who asked.
struct RelayOffer {
    RelayId    relay_id = 0;
    RelayToken token{};
    RelayKind  kind = RelayKind::Tcp;
    DevId      from_dev{};
    TopicId    topic{};

    void encode(Writer&) const;
    static std::optional<RelayOffer> decode(Reader&);
};

// First (and only framed) message on a TCP relay connection. Once both sides
// have joined the server answers each with RelayJoinOk, and from then on the
// connection carries raw bytes to the other side.
struct RelayJoin {
    RelayId    relay_id = 0;
    RelayToken token{};

    void encode(Writer&) const;
    static std::optional<RelayJoin> decode(Reader&);
};

// --- UDP: unframed, one message per datagram ---------------------------------
// Learn the node's UDP mapping. The request is padded to kWhoAmISize so the
// reply is never larger than what provoked it: this goes to an address
// nothing has validated.
inline constexpr size_t kWhoAmISize = 48;

struct WhoAmI {
    uint64_t nonce = 0;

    void encode(Writer&) const;  // pads to kWhoAmISize
    static std::optional<WhoAmI> decode(Reader&);
};

struct WhoAmIOk {
    uint64_t nonce = 0;
    Endpoint mapped{};

    void encode(Writer&) const;
    static std::optional<WhoAmIOk> decode(Reader&);
};

// Claim a UDP relay slot: the server forwards datagrams to the address this
// arrives from. The reply is smaller than the request.
struct UdpRelayBind {
    RelayId    relay_id = 0;
    RelayToken token{};

    void encode(Writer&) const;
    static std::optional<UdpRelayBind> decode(Reader&);
};

struct UdpRelayBindOk {
    RelayId relay_id = 0;

    void encode(Writer&) const;
    static std::optional<UdpRelayBindOk> decode(Reader&);
};

}  // namespace uconnect::wire::ctl
