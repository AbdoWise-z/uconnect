#pragma once
// uConnect wire formats shared by every channel: the 8-byte header, the message
// type space, and the messages that are not the control protocol's own.
//
// Two protocols share the header and the type space, told apart by the
// header's version byte:
//
//   v2 (control.hpp)  the TCP control connection to the rendezvous server, and
//                     the few UDP messages the server answers (WhoAmI, the UDP
//                     relay). Types 0x01-0x1F.
//   v1 (this file)    the UDP datagram channel between two peers: probes that
//                     punch a path (0x20-0x2F) and AEAD-sealed transport
//                     (0x40-0x4F). Keys come from the peers' TCP session.
//
// A few bodies defined here -- PeerEntry, ResolveOk, TopicSummary, Relayed,
// RelayData, Error -- are carried by the control protocol too.
//
// All integers are big-endian.

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

inline constexpr size_t kProbeTxnLen = 16;
inline constexpr size_t kProbeTagLen = 16;

using ProbeTxn = std::array<uint8_t, kProbeTxnLen>;
using ProbeTag = std::array<uint8_t, kProbeTagLen>;
using ConnId   = uint32_t;

enum class MsgType : uint8_t {
    // --- control protocol (control.hpp) ---
    Register      = 0x01, RegisterOk    = 0x02,
    Keepalive     = 0x03, KeepaliveOk   = 0x04,
    Update        = 0x05, UpdateOk      = 0x06,
    Unregister    = 0x07, UnregisterOk  = 0x08,
    Lookup        = 0x09, LookupOk      = 0x0A,
    Resolve       = 0x0B, ResolveOk     = 0x0C,
    Topics        = 0x0D, TopicsOk      = 0x0E,
    Stats         = 0x0F, StatsOk       = 0x10,
    Connect       = 0x11, Relayed       = 0x12,
    // 0x13 was v1's Retry; retired with UDP signaling.
    Error         = 0x14,
    RelayAlloc    = 0x15, RelayAllocOk  = 0x16,
    RelayData     = 0x17,
    RelayOffer    = 0x18,  // server -> peer: a relay was allocated to reach you
    RelayJoin     = 0x19,  // first frame on a relay connection
    RelayJoinOk   = 0x1A,  // both sides joined; raw bytes from here on
    WhoAmI        = 0x1B, WhoAmIOk      = 0x1C,  // UDP: learn our UDP mapping
    UdpRelayBind  = 0x1D, UdpRelayBindOk = 0x1E, // UDP: claim a UDP relay slot
    // --- peer probe ---
    Probe         = 0x20, ProbeOk       = 0x21,
    // --- datagram transport ---
    // 0x30-0x3F was v1's UDP Noise handshake; the TCP session runs it now.
    Transport     = 0x40,
    Close         = 0x41,
};

enum class MsgClass : uint8_t { Signaling, Probe, Transport, Unknown };

constexpr MsgClass classify(uint8_t type) {
    if (type >= 0x01 && type <= 0x1F) return MsgClass::Signaling;
    if (type >= 0x20 && type <= 0x2F) return MsgClass::Probe;
    if (type >= 0x40 && type <= 0x4F) return MsgClass::Transport;
    return MsgClass::Unknown;
}

// --- flags -----------------------------------------------------------------
namespace flags {
// Register: keep this topic OUT of the public listing. Inverted from the
// obvious direction on purpose -- topics are listed by default, and the
// interesting request is the one to be hidden. An old client that set this bit
// meaning "list me" now reads as "hide me", which is the safe way round for a
// flag whose two failure modes are "invisible" and "exposed".
inline constexpr uint8_t kUnlisted = 1u << 0;
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

    // `version` is the protocol the caller speaks: v1 for the peer datagram
    // channel, v2 for the control protocol (control.hpp).
    static std::optional<Header> decode(Reader& r, uint8_t version = kVersion) {
        Header h;
        h.type    = static_cast<MsgType>(r.u8());
        h.version = r.u8();
        h.flags   = r.u8();
        r.u8();  // reserved
        h.txn_id = r.u32();
        if (!r.ok() || h.version != version) return std::nullopt;
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

// --- Directory entries (carried by the control protocol) --------------------
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

struct ResolveOk {
    bool      found = false;
    TopicId   topic{};
    PeerEntry entry{};

    void encode(Writer&) const;
    static std::optional<ResolveOk> decode(Reader&);
};

struct TopicSummary {
    TopicId   id{};
    TopicMode mode        = TopicMode::Open;
    uint32_t  peers       = 0;
    uint32_t  fresh_peers = 0;

    void encode(Writer&) const;
    static std::optional<TopicSummary> decode(Reader&);
};

// --- Relayed ---------------------------------------------------------------
// A CONNECT as the target receives it: who is calling, and their opaque
// introduction. The server stamps from_dev itself; the payload it only carries.
struct Relayed {
    DevId                from_dev{};
    std::vector<uint8_t> payload;

    void encode(Writer&) const;
    static std::optional<Relayed> decode(Reader&);
};

// --- Relay -----------------------------------------------------------------
// The fallback for pairs that cannot hole punch. The relay forwards OPAQUE
// BYTES: it sits below the crypto layer, so what it carries is AEAD-sealed. The
// server learns metadata -- who talks to whom, when, how much -- and nothing
// else. Bandwidth is metered per binding.
using RelayId = uint64_t;

// One datagram through the server's UDP relay, in either direction.
// Unauthenticated at this layer on purpose: the payload is already
// authenticated end to end, and a forged wrapper can only waste the relay's
// bandwidth -- which the per-binding quota already bounds.
struct RelayData {
    RelayId              relay_id = 0;
    std::vector<uint8_t> payload;

    void encode(Writer&) const;
    static std::optional<RelayData> decode(Reader&);
};

// --- Error -----------------------------------------------------------------
struct Error {
    ErrorCode   code = ErrorCode::None;
    std::string reason;

    void encode(Writer&) const;
    static std::optional<Error> decode(Reader&);
};

// --- Probe -----------------------------------------------------------------
// probe_txn is CSPRNG, unique per candidate pair, single-use. Echoing it in
// ProbeOk is the challenge-response: it proves the peer can receive at that
// address.
//
// tag = BLAKE2s(key = the channel's probe key, domain || txn). The probe key
// comes from the peers' TCP session, so nobody outside it can elicit an
// answer -- a scanner never learns that anything is listening.
//
// There is no topic_id or dev_id on the wire: probe_txn is matched against the
// local pending attempt, so an observer learns nothing about membership.
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

// --- Transport -------------------------------------------------------------
// conn_id is derived from the TCP session, identically on both ends. Matching
// on it rather than on the 4-tuple is what lets the channel survive a NAT
// rebind, and move between a punched path and the relay.
struct Transport {
    ConnId                   conn_id = 0;
    uint64_t                 counter = 0;
    std::span<const uint8_t> ciphertext{};  // includes the 16-byte AEAD tag

    void encode(Writer&) const;
    static std::optional<Transport> decode(Reader&);
};

// Header, conn_id, counter and tag around every datagram payload.
inline constexpr size_t kTransportOverhead = Header::kSize + 4 + 8 + 16;

// A peer telling us it is going away, so we learn in one round trip instead of
// waiting out the idle timeout holding a NAT binding open.
//
// Same envelope as Transport -- conn_id, counter, ciphertext -- because it IS a
// transport packet: same keys, same counter space, same replay window. What
// differs is the header type and the AEAD's associated data, and that second
// difference is load-bearing. The header is NOT covered by the tag, so with a
// shared AAD anyone on path could flip a data packet's type byte from 0x40 to
// 0x41 and tear down a session they cannot read. Sealing each kind against its
// own type byte makes that forgery fail the tag check.
using Close = Transport;

// Why a peer went away. Advisory only: a peer that crashes says nothing at all,
// so absence of a reason means nothing in particular.
namespace close_reason {
inline constexpr uint16_t kUnspecified = 0;
inline constexpr uint16_t kGoingAway   = 1;  // application closed this connection
inline constexpr uint16_t kShutdown    = 2;  // the whole node is exiting
}  // namespace close_reason

}  // namespace uconnect::wire
