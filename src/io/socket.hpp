#pragma once
// UDP socket and interface enumeration. This is the ONLY place in the library
// that touches a socket -- everything below it takes bytes and a clock reading
// as parameters. If a lower layer ever needs to include this header, a layering
// violation has happened.

#include <optional>
#include <span>
#include <string>
#include <vector>

#include "uconnect/types.hpp"

namespace uconnect::io {

// Resolve "host:port" to an endpoint. Returns nullopt on failure.
std::optional<Endpoint> resolve(const std::string& host_port);

std::string to_string(const Endpoint&);
std::string to_string(const IpAddr&);

// Every usable local address, for host candidates. Loopback is excluded; link
// local and ULA IPv6 are kept, because two devices on the same LAN frequently
// have working IPv6 when IPv4 is double-NATed.
std::vector<IpAddr> local_addresses();

class UdpSocket {
public:
    UdpSocket();
    ~UdpSocket();
    UdpSocket(const UdpSocket&)            = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;
    UdpSocket(UdpSocket&&) noexcept;
    UdpSocket& operator=(UdpSocket&&) noexcept;

    // Binds a dual-stack v6 socket when possible so one socket serves both
    // families; falls back to v4. port 0 picks an ephemeral port.
    //
    // bind_host empty means "all interfaces", which is right almost everywhere.
    // Some hosts require binding a specific address instead -- Fly.io routes UDP
    // only to `fly-global-services`, and a multi-homed box may want one NIC.
    bool open(uint16_t port, const std::string& bind_host = {});
    void close();

    bool     is_open() const { return fd_ >= 0 || fd_ == kInvalid + 1; }
    uint16_t local_port() const { return local_port_; }

    bool send_to(const Endpoint&, std::span<const uint8_t>);

    struct Received {
        Endpoint from;
        size_t   len = 0;
    };
    // Non-blocking. Returns nullopt when there is nothing to read.
    std::optional<Received> recv_from(std::span<uint8_t> buf);

    // Blocks until readable or the timeout elapses. Negative means wait
    // indefinitely.
    bool wait_readable(std::chrono::milliseconds timeout);

    std::string last_error() const { return err_; }

private:
    static constexpr long long kInvalid = -1;

    long long   fd_ = kInvalid;
    uint16_t    local_port_ = 0;
    bool        v6_ = false;
    std::string err_;
};

// One-time platform init (WSAStartup on Windows). Safe to call repeatedly.
bool init_networking();

}  // namespace uconnect::io
