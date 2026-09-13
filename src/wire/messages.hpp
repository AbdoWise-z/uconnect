#pragma once
// uConnect wire protocol v1.
//
// One UDP socket carries three traffic classes, demultiplexed on the first
// byte of the datagram:
//
//   0x01-0x1F  server signaling
//   0x20-0x2F  peer probe / punch
//   0x30-0x3F  Noise handshake
//   0x40-0x4F  Noise transport
//
// All integers are big-endian. Every datagram opens with an 8-byte Header.
//
// Authenticated messages (Keepalive/Update/Unregister/Connect) carry
// seq(8) | mac(16), where mac = BLAKE2s(key = lease_token, all preceding bytes
// of the datagram). The lease_token itself is transmitted exactly once, in
// RegisterOk, and never again -- sending a bearer token three times a minute
// over UDP would hand record ownership to any on-path observer.

#include <optional>
#include <string>
#include <vector>

#include "buffer.hpp"
#include "uconnect/types.hpp"

namespace uconnect::wire {

inline constexpr uint8_t kVersion = 0x01;

// Conservative MTU. 1200 is the floor QUIC assumes; staying under it avoids IP
// fragmentation, which NATs and middleboxes handle badly.
inline constexpr size_t kMaxDatagram     = 1200;
inline constexpr size_t kMaxMeta         = 256;
inline constexpr size_t kMaxRelayPayload = 512;
inline constexpr size_t kMaxCandidates   = 8;

inline constexpr uint8_t kLookupDefault = 30;   // hard default
inline constexpr uint8_t kLookupMax     = 100;  // client may request up to this

inline constexpr size_t kMacLen        = 16;
inline constexpr size_t kLeaseTokenLen = 32;
inline constexpr size_t kProbeTxnLen   = 16;
inline constexpr size_t kProbeTagLen   = 16;
inline constexpr size_t kMaxCookieLen  = 32;

using Mac        = std::array<uint8_t, kMacLen>;
using LeaseToken = std::array<uint8_t, kLeaseTokenLen>;
using ProbeTxn   = std::array<uint8_t, kProbeTxnLen>;
using ProbeTag   = std::array<uint8_t, kProbeTagLen>;
using ConnId     = uint32_t;

enum class MsgType : uint8_t {
    // --- server signaling ---
    Register      = 0x01, RegisterOk    = 0x02,
    Keepalive     = 0x03, KeepaliveOk   = 0x04,
    Update        = 0x05, UpdateOk      = 0x06,
    Unregister    = 0x07, UnregisterOk  = 0x08,
    Lookup        = 0x09, LookupOk      = 0x0A,
    Resolve       = 0x0B, ResolveOk     = 0x0C,
    Topics        = 0x0D, TopicsOk      = 0x0E,
    Stats         = 0x0F, StatsOk       = 0x10,
    Connect       = 0x11, Relayed       = 0x12,
    Retry         = 0x13, Error         = 0x14,
    // --- peer probe ---
    Probe         = 0x20, ProbeOk       = 0x21,
    // --- noise ---
    HandshakeInit = 0x30, HandshakeResp = 0x31,
    Transport     = 0x40,
};

enum class MsgClass : uint8_t { Signaling, Probe, Handshake, Transport, Unknown };

constexpr MsgClass classify(uint8_t type) {
    if (type >= 0x01 && type <= 0x1F) return MsgClass::Signaling;
    if (type >= 0x20 && type <= 0x2F) return MsgClass::Probe;
    if (type >= 0x30 && type <= 0x3F) return MsgClass::Handshake;
    if (type >= 0x40 && type <= 0x4F) return MsgClass::Transport;
    return MsgClass::Unknown;
}

// --- flags -----------------------------------------------------------------
namespace flags {
inline constexpr uint8_t kListed   = 1u << 0;  // Register: include in Topics listing
inline constexpr uint8_t kWantMeta = 1u << 1;  // Lookup: include meta in entries
inline constexpr uint8_t kStale    = 1u << 0;  // PeerEntry: past the freshness window
}  // namespace flags

// --- header ----------------------------------------------------------------
struct Header {
    MsgType  type{};
    uint8_t  version = kVersion;
    uint8_t  flags   = 0;
    uint32_t txn_id  = 0;

    static constexpr size_t kSize = 8;

    void encode(Writer& w) const {
        w.u8(static_cast<uint8_t>(type));
        w.u8(version);
        w.u8(flags);
        w.u8(0);  // reserved
        w.u32(txn_id);
    }

    static std::optional<Header> decode(Reader& r) {
        Header h;
        h.type    = static_cast<MsgType>(r.u8());
        h.version = r.u8();
        h.flags   = r.u8();
        r.u8();  // reserved
        h.txn_id = r.u32();
        if (!r.ok() || h.version != kVersion) return std::nullopt;
        if (classify(static_cast<uint8_t>(h.type)) == MsgClass::Unknown) return std::nullopt;
        return h;
    }
};

// Peek the type without consuming, for demultiplexing before a full decode.
inline std::optional<MsgType> peek_type(std::span<const uint8_t> dgram) {
    if (dgram.size() < Header::kSize) return std::nullopt;
    if (classify(dgram[0]) == MsgClass::Unknown) return std::nullopt;
    return static_cast<MsgType>(dgram[0]);
}

// ---------------------------------------------------------------------------
// Authenticated-message support.
//
// The wire layer does not compute MACs -- that would make it depend on crypto
// and break the layering. Instead it writes everything up to the MAC via
// encode_prefix(), then the caller MACs writer.written() and appends the
// result. On decode, `authed` holds the span the MAC covers, so the caller can
// verify it.
// ---------------------------------------------------------------------------
struct Authed {
    uint64_t                 seq = 0;
    Mac                      mac{};
    std::span<const uint8_t> authed{};  // valid while the source datagram is
};

// --- Register --------------------------------------------------------------
struct Register {
    TopicId                id{};
    TopicMode              mode      = TopicMode::Open;
    uint8_t                key_epoch = 0;
    bool                   listed    = false;
    std::vector<Candidate> host_cands;  // client supplies host only; srflx is observed
    std::vector<uint8_t>   meta;
    std::vector<uint8_t>   cookie;      // from Retry; empty on the first attempt

    void encode(Writer&) const;
    static std::optional<Register> decode(Reader&, const Header&);
};

struct RegisterOk {
    DevId      dev_id{};
    LeaseToken lease_token{};
    Endpoint   srflx{};  // the mapping the server observed -- this is the STUN result
    uint16_t   ttl_secs       = 0;
    uint16_t   peers_in_topic = 0;

    void encode(Writer&) const;
    static std::optional<RegisterOk> decode(Reader&);
};

// --- Keepalive / Unregister (identical shape) ------------------------------
struct DevAuth {
    DevId  dev_id{};
    Authed auth{};

    void encode_prefix(Writer&) const;
    static std::optional<DevAuth> decode(Reader&);
};
using Keepalive  = DevAuth;
using Unregister = DevAuth;

struct KeepaliveOk {
    Endpoint srflx{};  // re-reported every time: a NAT rebind shows up here
    uint16_t expires_in = 0;

    void encode(Writer&) const;
    static std::optional<KeepaliveOk> decode(Reader&);
};

// --- Update ----------------------------------------------------------------
struct Update {
    DevId                  dev_id{};
    std::vector<Candidate> host_cands;
    std::vector<uint8_t>   meta;
    Authed                 auth{};

    void encode_prefix(Writer&) const;
    static std::optional<Update> decode(Reader&);
};

// --- Lookup ----------------------------------------------------------------
struct Lookup {
    TopicId              id{};
    uint8_t              max       = kLookupDefault;
    bool                 want_meta = false;
    std::vector<uint8_t> cookie;

    void encode(Writer&) const;
    static std::optional<Lookup> decode(Reader&, const Header&);
};

struct PeerEntry {
    DevId                  dev_id{};
    uint16_t               age_secs = 0;
    bool                   stale    = false;
    std::vector<Candidate> cands;
    std::vector<uint8_t>   meta;

    void   encode(Writer&) const;
    size_t encoded_size() const;
    static std::optional<PeerEntry> decode(Reader&);
};

// Responses are paged: all parts share one txn_id, and the client uses whatever
// arrives before its reassembly timeout.
//
// Measured sizes against a 1200-byte budget (see test_store.cpp, which asserts
// these so they cannot drift):
//
//   30 entries, srflx v4 only      930   fits
//   30 entries, srflx + host v4   1170   fits, 30 bytes of headroom
//   30 entries, + one host v6     1770   needs 2 pages
//   30 entries, + 64B meta        3090   needs 3 pages
//   100 entries, srflx + host v4  3830   needs 4 pages
//
// So the common v4-only case fits in a single datagram, and paging exists for
// IPv6 candidates, metadata, and the larger caps. The headroom on the v4 case
// is thin enough that the server must size pages from encoded_size() rather
// than assume.
struct LookupOk {
    TopicId                id{};
    TopicMode              mode  = TopicMode::Open;
    uint16_t               total = 0;  // matching records on the server, pre-sampling
    uint8_t                part  = 0;
    uint8_t                parts = 1;
    std::vector<PeerEntry> entries;

    void encode(Writer&) const;
    static std::optional<LookupOk> decode(Reader&);
};

// --- Resolve ---------------------------------------------------------------
struct Resolve {
    DevId dev_id{};

    void encode(Writer&) const;
    static std::optional<Resolve> decode(Reader&);
};

struct ResolveOk {
    bool      found = false;
    TopicId   topic{};
    PeerEntry entry{};

    void encode(Writer&) const;
    static std::optional<ResolveOk> decode(Reader&);
};

// --- Topics ----------------------------------------------------------------
struct Topics {
    uint32_t             cursor = 0;
    uint8_t              limit  = 100;
    std::vector<uint8_t> cookie;

    void encode(Writer&) const;
    static std::optional<Topics> decode(Reader&);
};

struct TopicSummary {
    TopicId   id{};
    TopicMode mode        = TopicMode::Open;
    uint32_t  peers       = 0;
    uint32_t  fresh_peers = 0;

    void encode(Writer&) const;
    static std::optional<TopicSummary> decode(Reader&);
};

struct TopicsOk {
    uint32_t                  next_cursor = 0;
    uint8_t                   part        = 0;
    uint8_t                   parts       = 1;
    std::vector<TopicSummary> topics;

    void encode(Writer&) const;
    static std::optional<TopicsOk> decode(Reader&);
};

// --- Connect / Relayed -----------------------------------------------------
// Punching requires both ends to fire at once. Without a way to tell B that A
// is about to punch, A hammers a NAT with no reason to let it through and B
// never reciprocates. The server relays two or three opaque blobs, then stops.
struct Connect {
    DevId                from_dev{};
    DevId                to_dev{};
    std::vector<uint8_t> payload;
    Authed               auth{};

    void encode_prefix(Writer&) const;
    static std::optional<Connect> decode(Reader&);
};

struct Relayed {
    DevId                from_dev{};
    std::vector<uint8_t> payload;

    void encode(Writer&) const;
    static std::optional<Relayed> decode(Reader&);
};

// --- Retry / Error ---------------------------------------------------------
// Address validation, QUIC-Retry style. Any response larger than its request
// requires a valid cookie first, or the server is a UDP amplifier.
struct Retry {
    std::vector<uint8_t> cookie;

    void encode(Writer&) const;
    static std::optional<Retry> decode(Reader&);
};

struct Error {
    ErrorCode   code = ErrorCode::None;
    std::string reason;

    void encode(Writer&) const;
    static std::optional<Error> decode(Reader&);
};

// --- Probe -----------------------------------------------------------------
// probe_txn is CSPRNG, unique per candidate pair, single-use. Echoing it in
// ProbeOk is the challenge-response: it proves the peer can receive at that
// address, and it anchors handshake freshness.
//
// tag = BLAKE2s(key = HKDF(K, "uconnect:v1:probe"), txn || src || dst), zeroed
// on open topics. On a keyed topic a non-member cannot elicit a response at
// all, so you never confirm your existence to a scanner.
//
// Note there is no topic_id on the wire: probe_txn is matched against the local
// pending attempt, so an observer learns nothing about topic membership.
struct Probe {
    ProbeTxn txn{};
    ProbeTag tag{};

    void encode(Writer&) const;
    static std::optional<Probe> decode(Reader&);
};

struct ProbeOk {
    ProbeTxn txn{};     // echoed
    Endpoint mapped{};  // what the responder saw as our source address
    ProbeTag tag{};

    void encode(Writer&) const;
    static std::optional<ProbeOk> decode(Reader&);
};

// --- Noise -----------------------------------------------------------------
// conn_id is chosen by the initiator. Matching on it rather than on the 4-tuple
// is what lets a session survive a NAT rebind: packets from a new source
// address still find their session, the new path is revalidated with a fresh
// probe, and no rehandshake is needed.
struct HandshakeInit {
    ConnId               conn_id = 0;
    ProbeTxn             probe_txn{};  // binds this handshake to a validated path
    std::vector<uint8_t> noise_msg;    // [e, psk] + padding

    void encode(Writer&) const;
    static std::optional<HandshakeInit> decode(Reader&);
};

struct HandshakeResp {
    ConnId               conn_id = 0;
    std::vector<uint8_t> noise_msg;  // [e, ee]

    void encode(Writer&) const;
    static std::optional<HandshakeResp> decode(Reader&);
};

struct Transport {
    ConnId                   conn_id = 0;
    uint64_t                 counter = 0;
    std::span<const uint8_t> ciphertext{};  // includes the 16-byte AEAD tag

    void encode(Writer&) const;
    static std::optional<Transport> decode(Reader&);
};

}  // namespace uconnect::wire
