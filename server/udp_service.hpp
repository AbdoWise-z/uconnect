#pragma once
// The UDP front end: decode, enforce address validation and rate limits,
// dispatch into the Store, encode the reply.
//
// Deliberately thin. All the state and all the policy live in Store, which is
// sans-IO, so this file contains nothing that needs a clock or a socket to
// test. A future REST front end sits beside this one over the same Store --
// read-only, because HTTP cannot carry registration: the TCP source port a
// server observes is a different NAT mapping than the client's UDP socket, so a
// record registered that way would punch to nowhere.

#include <functional>
#include <unordered_map>
#include <vector>

#include "store.hpp"

namespace uconnect::server {

struct ServiceConfig {
    // Per-source-IP token bucket, measured in bytes returned rather than
    // requests: a LOOKUP that returns 4KB should cost more than one that
    // returns 200 bytes.
    size_t   rate_bytes_per_sec = 256 * 1024;
    size_t   rate_burst_bytes   = 1024 * 1024;

    // Relayed payload gets its own budget rather than sharing the signaling
    // one. Signaling is small and bursty; a relay carries a whole session, and
    // charging it against a limit sized for lookups silently throttles every
    // relayed transfer to the signaling rate -- slowness with no error and no
    // counter to point at.
    //
    // Still bounded, because a relay is a fallback for a hard NAT rather than
    // a general purpose tunnel, and the operator is paying for this traffic.
    size_t   relay_bytes_per_sec = 4 * 1024 * 1024;
    size_t   relay_burst_bytes   = 8 * 1024 * 1024;
    uint8_t  max_pages          = 8;
};

struct Reply {
    Endpoint             to;
    std::vector<uint8_t> data;
};

class UdpService {
public:
    UdpService(Store& store, ServiceConfig cfg = {});

    // Handle one datagram. Returns zero or more replies (LookupOk may page).
    std::vector<Reply> handle(const Endpoint& from, std::span<const uint8_t> dgram,
                              Instant now);

    // Housekeeping: expire records and prune rate-limit state.
    void tick(Instant now);

    const Store& store() const { return store_; }

private:
    // Every request whose response is larger than itself validates the source
    // address in its own handler before replying -- Register, Lookup, Topics,
    // Resolve and Stats. Without that this server is a UDP amplifier pointed at
    // whoever the attacker spoofed.
    Reply make_retry(const Endpoint&, uint32_t txn_id, Instant now);
    Reply make_error(const Endpoint&, uint32_t txn_id, ErrorCode);

    bool consume_budget(const Endpoint&, size_t bytes, Instant now);
    bool consume_relay_budget(const Endpoint&, size_t bytes, Instant now);

    template <typename T>
    Reply encode(const Endpoint& to, wire::MsgType type, uint32_t txn_id, const T& msg,
                 uint8_t flags = 0);

    struct Bucket {
        double  tokens = 0;
        Instant last{};
    };
    struct IpHash {
        size_t operator()(const std::array<uint8_t, 16>& a) const noexcept {
            uint64_t h = 1469598103934665603ULL;
            for (uint8_t b : a) {
                h ^= b;
                h *= 1099511628211ULL;
            }
            return static_cast<size_t>(h);
        }
    };

    Store&        store_;
    ServiceConfig cfg_;
    std::unordered_map<std::array<uint8_t, 16>, Bucket, IpHash> buckets_;
    std::unordered_map<std::array<uint8_t, 16>, Bucket, IpHash> relay_buckets_;
};

}  // namespace uconnect::server
