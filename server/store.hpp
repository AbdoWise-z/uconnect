#pragma once
// The rendezvous server's record store. Sans-IO: no sockets, no clock, no
// threads. `now` is always a parameter, so the 20s/45s/90s lifetime rules can
// be tested deterministically in microseconds instead of by waiting.
//
// The store is the server's entire state. Everything in it is ephemeral: with a
// 90-second hard expiry there is no database, no persistence, and no migration
// path. A restart just means every live device re-registers within one
// keepalive interval.
//
// What the server knows about a device, in full:
//   a dev_id it derived itself, an IP:port, a topic_id, and an opaque blob.
//
// It does not hold K, cannot read a keyed topic's traffic, and cannot
// impersonate a member -- the PSK handshake happens strictly between peers.

#include <cstdint>
#include <functional>
#include <optional>
#include <random>
#include <unordered_map>
#include <utility>
#include <vector>

#include "messages.hpp"
#include "primitives.hpp"
#include "uconnect/types.hpp"

namespace uconnect::server {

// --- lifetimes -------------------------------------------------------------
// Two clocks that are easy to conflate. The lease is what the server promises;
// candidate freshness is what a peer can actually punch.
//
// NAT UDP mappings commonly expire in 30s-5min, with the short end normal on
// mobile carriers. So a record can be nominally alive while its srflx candidate
// has been dead for most of that time. Keeping the hard expiry close to the
// keepalive interval is what keeps the two from drifting apart.
struct StoreConfig {
    std::chrono::seconds keepalive_interval{20};
    std::chrono::seconds stale_after{45};   // ~2 missed keepalives: returned, but flagged
    std::chrono::seconds hard_expiry{90};   // ~4 missed: deleted, memory reclaimed

    // Generous by default: a corporate NAT or a CGNAT range legitimately has
    // many devices behind one address. Tune against the rejection counters in
    // stats() rather than by guessing.
    size_t max_per_ip_per_topic = 16;
    size_t max_per_ip_total     = 256;
    size_t max_entries          = 1'000'000;
    size_t max_topics           = 100'000;

    std::chrono::seconds cookie_lifetime{30};

    // --- relay -------------------------------------------------------------
    // The fallback for pairs that cannot punch. Unlike registration, relaying
    // keeps the server in the data path, so every limit here is about making
    // that cost bounded and predictable.
    bool                 relay_enabled = true;
    std::chrono::seconds relay_expiry{90};   // idle bindings evaporate
    size_t               max_relays          = 4096;
    size_t               max_relays_per_ip   = 8;
    // Per-binding ceiling. A relay is a fallback for a hard NAT, not a general
    // purpose tunnel, and without a cap one pair could saturate the host.
    uint64_t             relay_max_bytes     = 32ull * 1024 * 1024;
};

// --- record ----------------------------------------------------------------
struct Record {
    DevId                  dev_id{};
    TopicId                topic_id{};
    Endpoint               bound_addr{};  // srflx, observed by the server
    std::vector<Candidate> host_cands;    // client-supplied, for same-NAT paths
    std::vector<uint8_t>   meta;          // opaque; plaintext by design
    wire::LeaseToken       lease_token{};
    uint64_t               last_seq  = 0;
    Instant                last_seen{};
    Instant                created{};
    uint8_t                key_epoch = 0;
    TopicMode              mode      = TopicMode::Open;
    bool                   listed    = false;
};

// --- relay -----------------------------------------------------------------
// A two-slot forwarder. The allocating peer occupies slot A; the first
// datagram arriving from a different address claims slot B. After that the
// binding simply swaps datagrams between the two.
//
// What it carries is opaque: a Noise handshake message or an AEAD-sealed
// transport frame. The server sees who talks to whom, when, and how much, and
// nothing about content -- the same metadata it already has from registration.
struct RelayBinding {
    wire::RelayId id = 0;
    TopicId       topic{};
    DevId         a_dev{};
    DevId         b_dev{};
    Endpoint      a_addr{};
    Endpoint      b_addr{};
    Instant       created{};
    Instant       last_seen{};
    uint64_t      bytes = 0;
};

// --- stats -----------------------------------------------------------------
struct Stats {
    uint64_t topics_total   = 0;
    uint64_t topics_listed  = 0;
    uint64_t entries_total  = 0;  // records, NOT unique devices -- dev_ids churn
    uint64_t entries_fresh  = 0;

    uint64_t registers      = 0;
    uint64_t keepalives     = 0;
    uint64_t updates        = 0;
    uint64_t unregisters    = 0;
    uint64_t lookups        = 0;
    uint64_t resolves       = 0;
    uint64_t connects       = 0;
    uint64_t rebinds        = 0;  // NAT rebinds observed via token-authed address change
    uint64_t expired        = 0;

    uint64_t rej_bad_auth      = 0;
    uint64_t rej_rate_limited  = 0;
    uint64_t rej_quota         = 0;
    uint64_t rej_need_cookie   = 0;
    uint64_t rej_bad_request   = 0;

    uint64_t bytes_out_lookup = 0;

    uint64_t relays_open       = 0;
    uint64_t relays_allocated  = 0;
    uint64_t relay_bytes       = 0;
    uint64_t rej_relay_quota   = 0;
    uint64_t rej_relay_unknown = 0;
};

// --- results ---------------------------------------------------------------
struct RegisterResult {
    ErrorCode        code = ErrorCode::None;
    DevId            dev_id{};
    wire::LeaseToken lease_token{};
    Endpoint         srflx{};
    uint16_t         peers_in_topic = 0;
};

struct AuthResult {
    ErrorCode code = ErrorCode::None;
    Endpoint  srflx{};
    bool      rebound = false;
};

// --- hashing for array keys ------------------------------------------------
struct ArrayHash {
    template <size_t N>
    size_t operator()(const std::array<uint8_t, N>& a) const noexcept {
        // FNV-1a. These keys are already uniformly random (dev_id is an HMAC,
        // topic_id is client-chosen but high-entropy), so hash quality is not
        // load-bearing; speed is.
        uint64_t h = 1469598103934665603ULL;
        for (uint8_t b : a) {
            h ^= b;
            h *= 1099511628211ULL;
        }
        return static_cast<size_t>(h);
    }
};

class Store {
public:
    // server_secret keys both dev_id derivation and Retry cookies. Generated
    // from the CSPRNG at construction; rotating it invalidates every cookie and
    // changes every future dev_id, which is survivable given a 90s expiry.
    explicit Store(StoreConfig cfg = {});
    Store(StoreConfig cfg, const crypto::SymKey& server_secret, uint64_t sample_seed);

    // --- dev_id ------------------------------------------------------------
    // dev_id = HMAC(server_secret, topic_id || ip || port)
    //
    // topic_id is mixed in deliberately. Without it, the same device
    // registering in two topics would receive the same dev_id in both, letting
    // anyone who reads two topic listings link them -- a correlation leak that
    // cuts against the anonymity the protocol is built for.
    //
    // Derived once at registration and then stored, so a NAT rebind that
    // presents a valid lease token keeps its dev_id. Stable identity exactly
    // where it matters.
    DevId derive_dev_id(const TopicId&, const Endpoint&) const;

    // --- address validation ------------------------------------------------
    // Stateless Retry cookie: HMAC(secret, ip || port || epoch), truncated.
    // Valid for the current and previous epoch so a cookie issued at the edge
    // of a window still works.
    std::vector<uint8_t> make_cookie(const Endpoint&, Instant now) const;
    bool validate_cookie(std::span<const uint8_t> cookie, const Endpoint&, Instant now) const;

    // --- mutations ---------------------------------------------------------
    RegisterResult register_entry(const wire::Register&, const Endpoint& src, Instant now);

    // Authenticated operations. `authed` is the exact byte range the MAC
    // covers, handed up from the wire decoder.
    AuthResult keepalive(const DevId&, uint64_t seq, std::span<const uint8_t> authed,
                         const wire::Mac&, const Endpoint& src, Instant now);
    AuthResult update(const wire::Update&, const Endpoint& src, Instant now);
    AuthResult unregister(const DevId&, uint64_t seq, std::span<const uint8_t> authed,
                          const wire::Mac&, const Endpoint& src, Instant now);

    // --- queries -----------------------------------------------------------
    // Returns a random sample, never the full set. A popular topic with 5000
    // registrants would otherwise produce a 200KB response -- an amplification
    // disaster -- and a client trying to punch 5000 paths. Random sampling also
    // keeps the swarm balanced: no peer becomes everyone's first choice.
    struct LookupResult {
        std::vector<wire::PeerEntry> entries;
        uint16_t                     total = 0;  // matching records before sampling
        TopicMode                    mode  = TopicMode::Open;
    };
    LookupResult lookup(const TopicId&, uint8_t max, bool want_meta, Instant now);

    std::optional<std::pair<TopicId, wire::PeerEntry>> resolve(const DevId&, Instant now);

    struct TopicsResult {
        std::vector<wire::TopicSummary> topics;
        uint32_t                        next_cursor = 0;
    };
    TopicsResult list_topics(uint32_t cursor, uint8_t limit, Instant now);

    // Relay target for CONNECT. Returns the peer's current address if it is
    // registered in the same topic as the sender.
    std::optional<Endpoint> relay_target(const DevId& from, const DevId& to, uint64_t seq,
                                         std::span<const uint8_t> authed, const wire::Mac&,
                                         const Endpoint& src, Instant now);

    // --- relay -------------------------------------------------------------
    // Allocate a forwarding binding between two peers in the same topic. The
    // caller must already have verified the requester's MAC.
    struct RelayResult {
        ErrorCode     code     = ErrorCode::None;
        wire::RelayId relay_id = 0;
        uint32_t      max_kib  = 0;
    };
    RelayResult relay_alloc(const DevId& from, const DevId& peer, const Endpoint& src,
                            Instant now);

    // Where to forward a RelayData that arrived from `src`. Returns nullopt if
    // the binding is unknown, exhausted, or `src` belongs to neither slot.
    std::optional<Endpoint> relay_forward(wire::RelayId, const Endpoint& src, size_t bytes,
                                          Instant now);

    size_t relay_count() const { return relays_.size(); }

    // --- maintenance -------------------------------------------------------
    size_t sweep(Instant now);
    Stats  stats(Instant now) const;

    // --- introspection for tests ------------------------------------------
    const Record* find(const DevId&) const;
    size_t        size() const { return by_dev_.size(); }
    size_t        topic_count() const { return topics_.size(); }
    bool          is_fresh(const Record&, Instant now) const;

private:
    struct IpKey {
        IpAddr::Family          family;
        std::array<uint8_t, 16> bytes;
        bool operator==(const IpKey&) const = default;
    };
    struct IpKeyHash {
        size_t operator()(const IpKey& k) const noexcept {
            uint64_t h = 1469598103934665603ULL ^ static_cast<uint64_t>(k.family);
            for (uint8_t b : k.bytes) {
                h ^= b;
                h *= 1099511628211ULL;
            }
            return static_cast<size_t>(h);
        }
    };
    static IpKey ip_key(const Endpoint& ep) { return {ep.ip.family, ep.ip.bytes}; }

    struct TopicState {
        TopicMode          mode   = TopicMode::Open;
        bool               listed = false;
        std::vector<DevId> members;  // swap-and-pop; order is not meaningful
        std::unordered_map<DevId, size_t, ArrayHash> pos;
        // Per-source-IP counts, maintained incrementally. Scanning the member
        // list on every registration would be O(topic size) per call, which on
        // a 5000-peer swarm is 5000 iterations for every join.
        std::unordered_map<IpKey, size_t, IpKeyHash> per_ip;
    };

    // Verifies seq monotonicity and the MAC, and enforces the address rule:
    // same source is the fast path, a different source requires the token and
    // rebinds the record. Mobile networks rebind through no fault of the
    // client, and address-only binding would lock a device out of its own
    // record until expiry.
    AuthResult authenticate(Record&, uint64_t seq, std::span<const uint8_t> authed,
                            const wire::Mac&, const Endpoint& src, Instant now);

    void            add_member(TopicState&, const DevId&);
    void            remove_member(TopicState&, const DevId&);
    void            erase_record(const DevId&);
    wire::PeerEntry to_entry(const Record&, bool want_meta, Instant now) const;
    uint64_t        cookie_epoch(Instant now) const;
    std::vector<uint8_t> cookie_for_epoch(const Endpoint&, uint64_t epoch) const;

    StoreConfig     cfg_;
    crypto::SymKey  secret_{};
    mutable Stats   stats_{};

    std::unordered_map<DevId, Record, ArrayHash>       by_dev_;
    std::unordered_map<TopicId, TopicState, ArrayHash> topics_;
    std::unordered_map<IpKey, size_t, IpKeyHash>       per_ip_total_;

    std::unordered_map<wire::RelayId, RelayBinding> relays_;
    std::unordered_map<IpKey, size_t, IpKeyHash>    relays_per_ip_;

    // Ordered so list_topics can page over a stable sequence. Insertion order,
    // with the cursor an index into it.
    std::vector<TopicId> topic_order_;

    // Sampling only; not security-relevant, so a fast PRNG is fine. Seeded from
    // the CSPRNG so peers cannot predict which slice of a swarm they are given.
    mutable std::mt19937_64 sampler_;
};

}  // namespace uconnect::server
