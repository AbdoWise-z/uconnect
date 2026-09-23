#pragma once
// A simulated network for driving the punch state machine.
//
// This exists because hole punching cannot be debugged against the real
// internet: you cannot reproduce a symmetric NAT on demand, you cannot force
// the exact packet loss that breaks a retransmit schedule, and you cannot
// rewind time. Here all four NAT behaviours, loss, reordering and latency are
// parameters, and a full 8-second punch attempt runs in microseconds.
//
// NAT behaviours modelled (the standard RFC 3489 taxonomy):
//
//   FullCone        one mapping per internal socket; anyone may use it
//   RestrictedCone  one mapping; only hosts we have sent to may reply
//   PortRestricted  one mapping; only host:port we have sent to may reply
//   Symmetric       a NEW external port per destination -- defeats punching,
//                   because the port the rendezvous server saw is not the port
//                   the peer must hit
//
// Hairpinning is off by default, which is the realistic setting: many consumer
// routers will not loop a packet addressed to their own external IP back
// inside. That is what makes host candidates load-bearing for same-NAT peers.

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <utility>
#include <vector>

#include "uconnect/types.hpp"

namespace netsim {

using namespace uconnect;
using namespace std::chrono_literals;

enum class NatType { None, FullCone, RestrictedCone, PortRestricted, Symmetric };

inline Endpoint ep4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port) {
    return Endpoint{IpAddr::v4(a, b, c, d), port};
}

struct Packet {
    Endpoint             from;
    Endpoint             to;
    std::vector<uint8_t> data;
    Instant              deliver_at;
    uint64_t             seq = 0;  // tiebreaker so ordering is deterministic
    // True when both endpoints sit behind the same NAT and the destination is
    // the peer's private address. Such traffic never reaches the router at all,
    // which is exactly why host candidates work for same-NAT peers even when
    // hairpinning does not.
    bool lan = false;
};

// One NAT box with one public IP.
class Nat {
public:
    Nat(NatType type, IpAddr public_ip, bool hairpin = false)
        : type_(type), public_ip_(public_ip), hairpin_(hairpin) {}

    NatType       type() const { return type_; }
    const IpAddr& public_ip() const { return public_ip_; }
    bool          hairpins() const { return hairpin_; }

    // Outbound: returns the external address the packet appears to come from,
    // creating or reusing a mapping and recording the permission.
    Endpoint translate_out(const Endpoint& internal, const Endpoint& dst, Instant now) {
        if (type_ == NatType::None) return internal;

        MapKey key{internal, {}};
        if (type_ == NatType::Symmetric) {
            // The defining behaviour: a distinct external port per destination.
            key.dst = dst;
        }

        auto it = mappings_.find(key);
        if (it == mappings_.end()) {
            Endpoint ext{public_ip_, next_port_++};
            it = mappings_.emplace(key, Mapping{ext, now}).first;
            reverse_[ext] = internal;
        }
        it->second.last_used = now;

        // Record who we are allowed to hear back from.
        auto& perm = permissions_[it->second.external];
        if (type_ == NatType::RestrictedCone) {
            perm.ips.insert(dst.ip.bytes);
        } else if (type_ == NatType::PortRestricted || type_ == NatType::Symmetric) {
            perm.endpoints.insert(dst);
        }
        return it->second.external;
    }

    // Inbound: returns the internal address to deliver to, or nullopt if the
    // NAT drops it (no mapping, or no permission for this source).
    std::optional<Endpoint> translate_in(const Endpoint& src, const Endpoint& dst,
                                         Instant now) {
        if (type_ == NatType::None) return dst;

        auto rit = reverse_.find(dst);
        if (rit == reverse_.end()) return std::nullopt;  // no mapping: dropped

        auto pit = permissions_.find(dst);
        if (pit != permissions_.end()) {
            const auto& perm = pit->second;
            if (type_ == NatType::RestrictedCone && !perm.ips.count(src.ip.bytes)) {
                return std::nullopt;
            }
            if ((type_ == NatType::PortRestricted || type_ == NatType::Symmetric) &&
                !perm.endpoints.count(src)) {
                return std::nullopt;
            }
        }
        (void)now;
        return rit->second;
    }

    bool owns_public(const IpAddr& ip) const { return ip == public_ip_; }

private:
    struct MapKey {
        Endpoint             internal;
        std::optional<Endpoint> dst;
        bool operator<(const MapKey& o) const {
            auto tup = [](const Endpoint& e) {
                return std::tuple(static_cast<int>(e.ip.family), e.ip.bytes, e.port);
            };
            if (tup(internal) != tup(o.internal)) return tup(internal) < tup(o.internal);
            if (dst.has_value() != o.dst.has_value()) return !dst.has_value();
            if (!dst) return false;
            return tup(*dst) < tup(*o.dst);
        }
    };
    struct Mapping {
        Endpoint external;
        Instant  last_used;
    };
    struct Perm {
        std::set<std::array<uint8_t, 16>> ips;
        std::set<Endpoint, bool (*)(const Endpoint&, const Endpoint&)> endpoints{
            [](const Endpoint& a, const Endpoint& b) {
                return std::tuple(static_cast<int>(a.ip.family), a.ip.bytes, a.port) <
                       std::tuple(static_cast<int>(b.ip.family), b.ip.bytes, b.port);
            }};
    };
    struct EndpointLess {
        bool operator()(const Endpoint& a, const Endpoint& b) const {
            return std::tuple(static_cast<int>(a.ip.family), a.ip.bytes, a.port) <
                   std::tuple(static_cast<int>(b.ip.family), b.ip.bytes, b.port);
        }
    };

    NatType  type_;
    IpAddr   public_ip_;
    bool     hairpin_;
    uint16_t next_port_ = 40000;

    std::map<MapKey, Mapping>                     mappings_;
    std::map<Endpoint, Endpoint, EndpointLess>    reverse_;
    std::map<Endpoint, Perm, EndpointLess>        permissions_;
};

// A host sitting behind (optionally) a NAT.
struct Host {
    Endpoint local;   // its private address
    Nat*     nat = nullptr;
};

// Declared at namespace scope, not nested: a nested class's default member
// initializers are not usable inside the enclosing class definition, so
// `Network(Config = {})` would not compile.
struct NetConfig {
    Duration latency{20ms};
    Duration jitter{5ms};
    double   loss = 0.0;  // fraction of packets dropped
    uint64_t seed = 1;
};

// The network itself: routes packets, applies NAT translation, loss, latency
// and reordering.
class Network {
public:
    using Config = NetConfig;

    explicit Network(NetConfig cfg = {}) : cfg_(cfg), rng_(cfg.seed) {}

    void add_host(const std::string& name, Endpoint local, Nat* nat = nullptr) {
        hosts_[name] = Host{local, nat};
    }

    // Send from a named host. Applies the sender's NAT, then queues delivery.
    void send(const std::string& from, const Endpoint& dst, std::vector<uint8_t> data,
              Instant now) {
        auto hit = hosts_.find(from);
        if (hit == hosts_.end()) return;
        Host& h = hit->second;

        // LAN shortcut: a packet to a peer's private address behind the same
        // NAT is switched locally and never hits the router, so no translation
        // and no hairpin requirement.
        const bool lan = is_same_lan(h, dst);

        Endpoint src = h.local;
        if (h.nat && !lan) src = h.nat->translate_out(h.local, dst, now);

        if (loss_roll()) {
            ++dropped_;
            return;
        }

        Packet p;
        p.from       = src;
        p.to         = dst;
        p.data       = std::move(data);
        p.deliver_at = now + latency_roll();
        p.seq        = next_seq_++;
        p.lan        = lan;
        queue_.push_back(std::move(p));
        ++sent_;
    }

    // Deliver everything due by `now`. Returns (recipient name, from, bytes).
    struct Delivery {
        std::string          to;
        Endpoint             from;
        std::vector<uint8_t> data;
    };

    std::vector<Delivery> advance(Instant now) {
        // Sort by delivery time so out-of-order latency produces genuine
        // reordering rather than FIFO.
        std::sort(queue_.begin(), queue_.end(), [](const Packet& a, const Packet& b) {
            if (a.deliver_at != b.deliver_at) return a.deliver_at < b.deliver_at;
            return a.seq < b.seq;
        });

        std::vector<Delivery> out;
        auto                  it = queue_.begin();
        while (it != queue_.end() && it->deliver_at <= now) {
            auto d = route(*it, now);
            if (d) out.push_back(std::move(*d));
            it = queue_.erase(it);
        }
        return out;
    }

    bool idle() const { return queue_.empty(); }

    std::optional<Instant> next_delivery() const {
        std::optional<Instant> soonest;
        for (const auto& p : queue_) {
            if (!soonest || p.deliver_at < *soonest) soonest = p.deliver_at;
        }
        return soonest;
    }

    uint64_t sent() const { return sent_; }
    uint64_t dropped() const { return dropped_; }
    uint64_t nat_blocked() const { return nat_blocked_; }

private:
    // True if `dst` is the private address of another host behind the same NAT.
    bool is_same_lan(const Host& sender, const Endpoint& dst) const {
        if (!sender.nat) return false;
        for (const auto& [name, h] : hosts_) {
            (void)name;
            if (h.nat == sender.nat && h.local == dst) return true;
        }
        return false;
    }

    std::optional<Delivery> route(const Packet& p, Instant now) {
        // LAN traffic is switched directly to the private address.
        if (p.lan) {
            for (auto& [name, h] : hosts_) {
                if (h.local == p.to) return Delivery{name, p.from, p.data};
            }
            ++nat_blocked_;
            return std::nullopt;
        }

        for (auto& [name, h] : hosts_) {
            if (h.nat) {
                if (!h.nat->owns_public(p.to.ip)) continue;
                // Same-NAT traffic addressed to the NAT's own public IP needs
                // hairpinning, which many routers do not do.
                bool from_inside = h.nat->owns_public(p.from.ip);
                if (from_inside && !h.nat->hairpins()) {
                    ++nat_blocked_;
                    return std::nullopt;
                }
                auto internal = h.nat->translate_in(p.from, p.to, now);
                if (!internal) continue;
                if (!(*internal == h.local)) continue;
                return Delivery{name, p.from, p.data};
            }
            if (h.local == p.to) return Delivery{name, p.from, p.data};
        }
        ++nat_blocked_;
        return std::nullopt;
    }

    bool loss_roll() {
        if (cfg_.loss <= 0.0) return false;
        std::uniform_real_distribution<double> d(0.0, 1.0);
        return d(rng_) < cfg_.loss;
    }

    Duration latency_roll() {
        if (cfg_.jitter.count() == 0) return cfg_.latency;
        std::uniform_int_distribution<int64_t> d(-cfg_.jitter.count(), cfg_.jitter.count());
        auto ms = cfg_.latency.count() + d(rng_);
        return Duration{ms < 0 ? 0 : ms};
    }

    NetConfig                    cfg_;
    std::mt19937_64              rng_;
    std::map<std::string, Host>  hosts_;
    std::vector<Packet>          queue_;
    uint64_t                     next_seq_    = 0;
    uint64_t                     sent_        = 0;
    uint64_t                     dropped_     = 0;
    uint64_t                     nat_blocked_ = 0;
};

}  // namespace netsim
