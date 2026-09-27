#pragma once
// The rendezvous server's state under control protocol v2: records, topics and
// relay bindings. Sans-IO: no sockets, no clock, no threads -- `now` is always
// a parameter, and connections are opaque keys the runtime hands in.
//
// The difference from v1's Store is ownership. A node reaches the server over
// one TCP connection, and every record it registers belongs to that
// connection. Only the owner can refresh, update or unregister a record, or
// CONNECT and relay on its behalf, and when the connection closes everything
// it owned goes with it. There are no lease tokens, MACs or sequence numbers,
// because there is nothing to authenticate that the connection does not
// already prove.

#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <random>
#include <unordered_map>
#include <utility>
#include <vector>

#include "control.hpp"
#include "primitives.hpp"
#include "store.hpp"  // ArrayHash
#include "uconnect/types.hpp"

namespace uconnect::server {

// A control connection, as the runtime identifies it. Never reused.
using ConnKey = uint64_t;

struct RegistryConfig {
    // A record whose owner has not refreshed it this long is returned by
    // LOOKUP but flagged stale: its NAT mapping may be gone.
    std::chrono::seconds stale_after{45};

    size_t max_per_ip_per_topic = 16;
    size_t max_per_ip_total     = 256;
    size_t max_entries          = 1'000'000;
    size_t max_topics           = 100'000;

    // --- relay -------------------------------------------------------------
    bool                 relay_enabled   = true;
    std::chrono::seconds relay_expiry{90};  // unused bindings evaporate
    size_t               max_relays        = 4096;
    size_t               max_relays_per_ip = 8;
    uint64_t             relay_max_bytes   = 32ull * 1024 * 1024;  // per binding
};

struct RegistryStats {
    uint64_t topics_total = 0, topics_listed = 0;
    uint64_t entries_total = 0, entries_fresh = 0;
    uint64_t registers = 0, lookups = 0, connects = 0, expired = 0;
    uint64_t rej_quota = 0;
    uint64_t relays_open = 0, relays_allocated = 0, relay_bytes = 0;
};

class Registry {
public:
    explicit Registry(RegistryConfig cfg = {});
    Registry(RegistryConfig cfg, const crypto::SymKey& secret, uint64_t sample_seed);

    // dev_id = MAC(secret, topic || TCP address). Topic is mixed in so one
    // device in two topics cannot be linked across their listings.
    DevId derive_dev_id(const TopicId&, const Endpoint&) const;

    // --- records, all owned by a connection --------------------------------
    struct RegisterResult {
        ErrorCode code = ErrorCode::None;
        DevId     dev_id{};
        Endpoint  srflx{};
        uint16_t  peers_in_topic = 0;
    };
    // `src` is the TCP address the connection arrived from: the address the
    // record advertises, and the one quotas are counted against.
    RegisterResult register_entry(const wire::ctl::Register&, const Endpoint& src, ConnKey owner,
                                  Instant now);

    // NotFound when there is no such record, BadAuth when it is someone
    // else's: a connection can only touch its own.
    ErrorCode refresh(const DevId&, ConnKey owner, Instant now);
    ErrorCode update(const wire::ctl::Update&, ConnKey owner, Instant now);
    ErrorCode unregister(const DevId&, ConnKey owner);

    // Everything a closed connection owned: its records, and the relay
    // bindings it was party to. Returns how many records went.
    size_t drop_owner(ConnKey owner);

    // --- queries -----------------------------------------------------------
    struct LookupResult {
        std::vector<wire::PeerEntry> entries;
        uint16_t                     total = 0;
        TopicMode                    mode  = TopicMode::Open;
    };
    // A random sample, never the whole swarm.
    LookupResult lookup(const TopicId&, uint8_t max, bool want_meta, Instant now);

    std::optional<std::pair<TopicId, wire::PeerEntry>> resolve(const DevId&, Instant now);

    struct TopicsResult {
        std::vector<wire::TopicSummary> topics;
        uint32_t                        next_cursor = 0;
    };
    TopicsResult list_topics(uint32_t cursor, uint8_t limit, Instant now);

    // CONNECT: the connection to deliver to, if `from` is the caller's and
    // both are in one topic. The server introduces peers within a topic only.
    std::optional<ConnKey> connect_target(const DevId& from, const DevId& to, ConnKey owner);

    // --- relays ------------------------------------------------------------
    struct RelayGrant {
        ErrorCode                code = ErrorCode::None;
        wire::RelayId            id   = 0;
        wire::ctl::RelayToken    token{};       // the caller's side
        wire::ctl::RelayToken    peer_token{};  // the other side's, for the offer
        ConnKey                  peer_owner = 0;
        TopicId                  topic{};
        uint32_t                 max_kib = 0;
    };
    // A binding between the caller's record and `peer`, both in one topic.
    // Asking again for the same pair and kind -- from either side -- returns
    // the existing binding rather than a second one, unless it has spent its
    // byte budget.
    RelayGrant relay_alloc(const DevId& from, const DevId& peer, wire::ctl::RelayKind kind,
                           ConnKey owner, const Endpoint& src, Instant now);

    // Which side (0 or 1) a token is for, or nullopt if the id or token is
    // wrong -- knowing the relay id alone admits nobody.
    std::optional<int> relay_side(wire::RelayId, const wire::ctl::RelayToken&) const;

    // TCP relay: count spliced bytes against the binding's budget. False once
    // it is spent; the runtime then closes the splice.
    bool relay_charge(wire::RelayId, size_t bytes, Instant now);

    // UDP relay: bind a side to the address its UdpRelayBind came from, then
    // forward between the two bound addresses.
    bool                    udp_bind(wire::RelayId, const wire::ctl::RelayToken&,
                                     const Endpoint& src, Instant now);
    std::optional<Endpoint> udp_forward(wire::RelayId, const Endpoint& src, size_t bytes,
                                        Instant now);

    void   relay_close(wire::RelayId);
    size_t relay_count() const { return relays_.size(); }

    // --- maintenance -------------------------------------------------------
    // Expires idle relay bindings. Records need no sweep: they live exactly as
    // long as their owning connection.
    void          sweep(Instant now);
    RegistryStats stats(Instant now) const;

    // --- introspection for tests -------------------------------------------
    size_t size() const { return by_dev_.size(); }
    size_t topic_count() const { return topics_.size(); }

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

    struct Entry {
        DevId                  dev_id{};
        TopicId                topic_id{};
        Endpoint               bound_addr{};
        std::vector<Candidate> host_cands;
        std::vector<uint8_t>   meta;
        ConnKey                owner = 0;
        Instant                last_seen{};
        uint8_t                key_epoch = 0;
        TopicMode              mode      = TopicMode::Open;
    };

    struct TopicState {
        TopicMode          mode   = TopicMode::Open;
        bool               listed = true;   // one member asking to be hidden hides it
        std::vector<DevId> members;         // swap-and-pop
        std::unordered_map<DevId, size_t, ArrayHash>  pos;
        std::unordered_map<IpKey, size_t, IpKeyHash> per_ip;
        uint32_t           order = 0;       // position in the listing, stable for its life
    };

    struct Relay {
        wire::RelayId                        id = 0;
        wire::ctl::RelayKind                 kind = wire::ctl::RelayKind::Tcp;
        TopicId                              topic{};
        DevId                                dev[2]{};
        ConnKey                              owner[2]{};
        wire::ctl::RelayToken                token[2]{};
        std::optional<Endpoint>              udp[2];
        IpKey                                counted_ip{};  // the quota this binding holds
        Instant                              last_seen{};
        uint64_t                             bytes     = 0;
        bool                                 exhausted = false;
    };

    void erase_entry(const DevId&);
    wire::PeerEntry to_entry(const Entry&, bool want_meta, Instant now) const;
    bool            is_fresh(const Entry& e, Instant now) const {
        return now - e.last_seen < cfg_.stale_after;
    }
    void release_relay(std::unordered_map<wire::RelayId, Relay>::iterator);

    RegistryConfig          cfg_;
    crypto::SymKey          secret_{};
    mutable RegistryStats   stats_{};
    mutable std::mt19937_64 sampler_;

    std::unordered_map<DevId, Entry, ArrayHash>        by_dev_;
    std::unordered_map<TopicId, TopicState, ArrayHash> topics_;
    std::unordered_map<IpKey, size_t, IpKeyHash>       per_ip_total_;
    std::unordered_map<ConnKey, std::vector<DevId>>    by_owner_;

    // The listing: topics in creation order, keyed by a counter that never
    // repeats, so a cursor stays valid when topics before it disappear.
    std::map<uint32_t, TopicId> listing_;
    uint32_t                    next_order_ = 1;

    std::unordered_map<wire::RelayId, Relay>        relays_;
    std::unordered_map<IpKey, size_t, IpKeyHash>    relays_per_ip_;
};

}  // namespace uconnect::server
