#pragma once
// Control protocol v2 on the server side: decode a message from a control
// connection, act on the Registry, and say what to send where. Sans-IO like
// the Registry beneath it -- connections are keys, and the runtime
// (rendezvous.hpp) owns the sockets.
//
// Most replies go back on the connection a request came in on. Two do not:
// a CONNECT is delivered to the target's connection as Relayed, and a relay
// allocation is offered to the peer's connection as RelayOffer. That is the
// whole reason a node keeps one connection open: the server can reach it
// whenever someone wants to.

#include <span>
#include <unordered_map>
#include <vector>

#include "registry.hpp"

namespace uconnect::server {

struct ControlConfig {
    // Per-connection budget, in bytes of requests. TCP means no reply can be
    // aimed at a spoofed address, so this is about CPU and fairness only; a
    // connection that runs through it is closed rather than slowed.
    size_t rate_bytes_per_sec = 256 * 1024;
    size_t rate_burst_bytes   = 1024 * 1024;

    // UDP (WhoAmI, relay binds, relayed datagrams), per source IP.
    size_t udp_bytes_per_sec = 4 * 1024 * 1024;
    size_t udp_burst_bytes   = 8 * 1024 * 1024;
};

// Framed bytes, ready to write to a connection.
struct Framed {
    ConnKey              to = 0;
    std::vector<uint8_t> bytes;
};

struct UdpOut {
    Endpoint             to{};
    std::vector<uint8_t> data;
};

class ControlService {
public:
    // What one control message costs against its connection's budget, beyond
    // its own bytes. A burst smaller than one largest frame plus this would
    // disconnect any node that sent one.
    static constexpr size_t kMessageOverhead = 64;

    explicit ControlService(Registry&, ControlConfig = {});

    // A control connection from `peer` -- its observed TCP address -- is up.
    void on_open(ConnKey, const Endpoint& peer, Instant now);

    struct Result {
        std::vector<Framed> out;
        bool                close = false;  // drop the connection: malformed, or over budget
    };
    // One complete message from a control connection.
    Result on_message(ConnKey, std::span<const uint8_t> msg, Instant now);

    // The connection is gone; so is everything it owned.
    void on_close(ConnKey);

    // One UDP datagram: WhoAmI, UdpRelayBind or RelayData.
    std::vector<UdpOut> on_udp(const Endpoint& from, std::span<const uint8_t> dgram, Instant now);

    void tick(Instant now);

    size_t          connections() const { return conns_.size(); }
    Registry&       registry() { return reg_; }
    const Registry& registry() const { return reg_; }

private:
    struct Bucket {
        double  tokens = 0;
        Instant last{};
    };
    struct Conn {
        Endpoint peer{};
        Bucket   budget{};
    };

    static bool take(Bucket&, size_t bytes, size_t rate, size_t burst, Instant now);

    Registry&     reg_;
    ControlConfig cfg_;
    std::unordered_map<ConnKey, Conn> conns_;
    std::unordered_map<std::array<uint8_t, 16>, Bucket, ArrayHash> udp_buckets_;
    uint64_t rej_rate_limited_ = 0;
};

}  // namespace uconnect::server
