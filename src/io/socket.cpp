#include "socket.hpp"

#include <cstring>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
// ws2tcpip.h and iphlpapi.h must follow winsock2.h
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <iphlpapi.h>
#ifndef SIO_UDP_CONNRESET
// Not declared by every MinGW-w64 header set.
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
using socklen_type = int;
#define UC_CLOSE closesocket
#define UC_INVALID INVALID_SOCKET
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
using socklen_type = socklen_t;
#define UC_CLOSE ::close
#define UC_INVALID (-1)
#endif

namespace uconnect::io {
namespace {

// Convert a sockaddr to our Endpoint. IPv4-mapped IPv6 addresses (::ffff:a.b.c.d)
// are unwrapped to plain v4, so a dual-stack socket does not report every v4
// peer as a v6 one -- which would break same-NAT detection and candidate
// comparison.
std::optional<Endpoint> from_sockaddr(const sockaddr_storage& ss) {
    Endpoint ep;
    if (ss.ss_family == AF_INET) {
        const auto* a = reinterpret_cast<const sockaddr_in*>(&ss);
        ep.ip.family  = IpAddr::Family::V4;
        std::memcpy(ep.ip.bytes.data(), &a->sin_addr, 4);
        ep.port = ntohs(a->sin_port);
        return ep;
    }
    if (ss.ss_family == AF_INET6) {
        const auto* a = reinterpret_cast<const sockaddr_in6*>(&ss);
        const auto* b = reinterpret_cast<const uint8_t*>(&a->sin6_addr);
        static const uint8_t kV4Mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
        if (std::memcmp(b, kV4Mapped, 12) == 0) {
            ep.ip.family = IpAddr::Family::V4;
            std::memcpy(ep.ip.bytes.data(), b + 12, 4);
        } else {
            ep.ip.family = IpAddr::Family::V6;
            std::memcpy(ep.ip.bytes.data(), b, 16);
        }
        ep.port = ntohs(a->sin6_port);
        return ep;
    }
    return std::nullopt;
}

// Build a sockaddr for sending. When the socket is dual-stack v6, a v4 target
// must be encoded as an IPv4-mapped v6 address.
socklen_type to_sockaddr(const Endpoint& ep, bool socket_is_v6, sockaddr_storage& out) {
    std::memset(&out, 0, sizeof(out));
    if (ep.ip.family == IpAddr::Family::V4 && !socket_is_v6) {
        auto* a = reinterpret_cast<sockaddr_in*>(&out);
        a->sin_family = AF_INET;
        a->sin_port   = htons(ep.port);
        std::memcpy(&a->sin_addr, ep.ip.bytes.data(), 4);
        return sizeof(sockaddr_in);
    }
    auto* a = reinterpret_cast<sockaddr_in6*>(&out);
    a->sin6_family = AF_INET6;
    a->sin6_port   = htons(ep.port);
    if (ep.ip.family == IpAddr::Family::V4) {
        auto* b = reinterpret_cast<uint8_t*>(&a->sin6_addr);
        std::memset(b, 0, 10);
        b[10] = 0xFF;
        b[11] = 0xFF;
        std::memcpy(b + 12, ep.ip.bytes.data(), 4);
    } else {
        std::memcpy(&a->sin6_addr, ep.ip.bytes.data(), 16);
    }
    return sizeof(sockaddr_in6);
}

}  // namespace

bool init_networking() {
#if defined(_WIN32)
    static bool done = false;
    static bool ok   = false;
    if (done) return ok;
    WSADATA wsa;
    ok   = WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
    done = true;
    return ok;
#else
    return true;
#endif
}

std::string to_string(const IpAddr& ip) {
    char buf[INET6_ADDRSTRLEN] = {};
    if (ip.family == IpAddr::Family::V4) {
        inet_ntop(AF_INET, ip.bytes.data(), buf, sizeof(buf));
    } else {
        inet_ntop(AF_INET6, ip.bytes.data(), buf, sizeof(buf));
    }
    return buf;
}

std::string to_string(const Endpoint& ep) {
    if (ep.ip.family == IpAddr::Family::V6) {
        return "[" + to_string(ep.ip) + "]:" + std::to_string(ep.port);
    }
    return to_string(ep.ip) + ":" + std::to_string(ep.port);
}

std::optional<Endpoint> resolve(const std::string& host_port) {
    init_networking();

    std::string host;
    std::string port;
    if (!host_port.empty() && host_port.front() == '[') {  // [v6]:port
        auto close_bracket = host_port.find(']');
        if (close_bracket == std::string::npos) return std::nullopt;
        host = host_port.substr(1, close_bracket - 1);
        if (close_bracket + 2 > host_port.size()) return std::nullopt;
        port = host_port.substr(close_bracket + 2);
    } else {
        auto colon = host_port.rfind(':');
        if (colon == std::string::npos) return std::nullopt;
        host = host_port.substr(0, colon);
        port = host_port.substr(colon + 1);
    }

    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res) return std::nullopt;

    // Prefer IPv4 when both are offered: the rendezvous protocol works either
    // way, but a v4 srflx is comparable with the v4 candidates most peers have.
    std::optional<Endpoint> v4, v6;
    for (auto* p = res; p; p = p->ai_next) {
        sockaddr_storage ss{};
        std::memcpy(&ss, p->ai_addr, static_cast<size_t>(p->ai_addrlen));
        auto ep = from_sockaddr(ss);
        if (!ep) continue;
        if (ep->ip.family == IpAddr::Family::V4 && !v4) v4 = ep;
        if (ep->ip.family == IpAddr::Family::V6 && !v6) v6 = ep;
    }
    freeaddrinfo(res);
    return v4 ? v4 : v6;
}

std::vector<IpAddr> local_addresses() {
    init_networking();
    std::vector<IpAddr> out;

#if defined(_WIN32)
    ULONG size = 15000;
    std::vector<uint8_t> buf(size);
    auto* addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG rc    = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, addrs, &size);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buf.resize(size);
        addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
        rc    = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, addrs, &size);
    }
    if (rc != NO_ERROR) return out;

    for (auto* a = addrs; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            sockaddr_storage ss{};
            std::memcpy(&ss, u->Address.lpSockaddr,
                        static_cast<size_t>(u->Address.iSockaddrLength));
            auto ep = from_sockaddr(ss);
            if (!ep || ep->ip.is_loopback()) continue;
            out.push_back(ep->ip);
        }
    }
#else
    ifaddrs* ifa = nullptr;
    if (getifaddrs(&ifa) != 0) return out;
    for (auto* p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr) continue;
        if (!(p->ifa_flags & IFF_UP)) continue;
        if (p->ifa_flags & IFF_LOOPBACK) continue;
        if (p->ifa_addr->sa_family != AF_INET && p->ifa_addr->sa_family != AF_INET6) continue;
        sockaddr_storage ss{};
        std::memcpy(&ss, p->ifa_addr,
                    p->ifa_addr->sa_family == AF_INET ? sizeof(sockaddr_in)
                                                      : sizeof(sockaddr_in6));
        auto ep = from_sockaddr(ss);
        if (!ep || ep->ip.is_loopback()) continue;
        out.push_back(ep->ip);
    }
    freeifaddrs(ifa);
#endif
    return out;
}

// ---------------------------------------------------------------------------
// UdpSocket
// ---------------------------------------------------------------------------
UdpSocket::UdpSocket() { init_networking(); }
UdpSocket::~UdpSocket() { close(); }

UdpSocket::UdpSocket(UdpSocket&& o) noexcept
    : fd_(o.fd_), local_port_(o.local_port_), v6_(o.v6_), err_(std::move(o.err_)) {
    o.fd_ = kInvalid;
}

UdpSocket& UdpSocket::operator=(UdpSocket&& o) noexcept {
    if (this != &o) {
        close();
        fd_         = o.fd_;
        local_port_ = o.local_port_;
        v6_         = o.v6_;
        err_        = std::move(o.err_);
        o.fd_       = kInvalid;
    }
    return *this;
}

bool UdpSocket::open(uint16_t port) {
    close();

    // Try dual-stack v6 first so a single socket serves both families -- which
    // matters because the whole design assumes ONE socket carries signaling,
    // probes and data.
    auto s = ::socket(AF_INET6, SOCK_DGRAM, 0);
    v6_    = true;
    if (s == UC_INVALID) {
        s   = ::socket(AF_INET, SOCK_DGRAM, 0);
        v6_ = false;
    }
    if (s == UC_INVALID) {
        err_ = "socket() failed";
        return false;
    }

    if (v6_) {
        int off = 0;
        ::setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&off),
                     sizeof(off));
    }

    sockaddr_storage ss{};
    socklen_type     len;
    if (v6_) {
        auto* a        = reinterpret_cast<sockaddr_in6*>(&ss);
        a->sin6_family = AF_INET6;
        a->sin6_addr   = in6addr_any;
        a->sin6_port   = htons(port);
        len            = sizeof(sockaddr_in6);
    } else {
        auto* a          = reinterpret_cast<sockaddr_in*>(&ss);
        a->sin_family    = AF_INET;
        a->sin_addr.s_addr = INADDR_ANY;
        a->sin_port      = htons(port);
        len              = sizeof(sockaddr_in);
    }

    if (::bind(s, reinterpret_cast<sockaddr*>(&ss), len) != 0) {
        err_ = "bind() failed";
        UC_CLOSE(s);
        return false;
    }

#if defined(_WIN32)
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    // Windows returns WSAECONNRESET on a UDP socket when a previous send drew
    // an ICMP port-unreachable. During hole punching that is normal and
    // expected -- without this, recv would fail spuriously mid-punch.
    BOOL    behavior = FALSE;
    DWORD   bytes    = 0;
    WSAIoctl(s, SIO_UDP_CONNRESET, &behavior, sizeof(behavior), nullptr, 0, &bytes, nullptr,
             nullptr);
#else
    int fl = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, fl | O_NONBLOCK);
#endif

    sockaddr_storage bound{};
    socklen_type     blen = sizeof(bound);
    if (::getsockname(s, reinterpret_cast<sockaddr*>(&bound), &blen) == 0) {
        auto ep = from_sockaddr(bound);
        if (ep) local_port_ = ep->port;
    }

    fd_ = static_cast<long long>(s);
    return true;
}

void UdpSocket::close() {
    if (fd_ == kInvalid) return;
#if defined(_WIN32)
    UC_CLOSE(static_cast<SOCKET>(fd_));
#else
    UC_CLOSE(static_cast<int>(fd_));
#endif
    fd_ = kInvalid;
}

bool UdpSocket::send_to(const Endpoint& to, std::span<const uint8_t> data) {
    if (fd_ == kInvalid) return false;
    sockaddr_storage ss{};
    socklen_type     len = to_sockaddr(to, v6_, ss);
#if defined(_WIN32)
    int n = ::sendto(static_cast<SOCKET>(fd_), reinterpret_cast<const char*>(data.data()),
                     static_cast<int>(data.size()), 0, reinterpret_cast<sockaddr*>(&ss), len);
#else
    auto n = ::sendto(static_cast<int>(fd_), data.data(), data.size(), 0,
                      reinterpret_cast<sockaddr*>(&ss), len);
#endif
    return n >= 0;
}

std::optional<UdpSocket::Received> UdpSocket::recv_from(std::span<uint8_t> buf) {
    if (fd_ == kInvalid) return std::nullopt;
    sockaddr_storage ss{};
    socklen_type     slen = sizeof(ss);
#if defined(_WIN32)
    int n = ::recvfrom(static_cast<SOCKET>(fd_), reinterpret_cast<char*>(buf.data()),
                       static_cast<int>(buf.size()), 0, reinterpret_cast<sockaddr*>(&ss), &slen);
#else
    auto n = ::recvfrom(static_cast<int>(fd_), buf.data(), buf.size(), 0,
                        reinterpret_cast<sockaddr*>(&ss), &slen);
#endif
    if (n < 0) return std::nullopt;
    auto from = from_sockaddr(ss);
    if (!from) return std::nullopt;
    return Received{*from, static_cast<size_t>(n)};
}

bool UdpSocket::wait_readable(std::chrono::milliseconds timeout) {
    if (fd_ == kInvalid) return false;
    fd_set rd;
    FD_ZERO(&rd);
#if defined(_WIN32)
    FD_SET(static_cast<SOCKET>(fd_), &rd);
    int nfds = 0;
#else
    FD_SET(static_cast<int>(fd_), &rd);
    int nfds = static_cast<int>(fd_) + 1;
#endif
    timeval  tv{};
    timeval* ptv = nullptr;
    if (timeout.count() >= 0) {
        tv.tv_sec  = static_cast<long>(timeout.count() / 1000);
        tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);
        ptv        = &tv;
    }
    return ::select(nfds, &rd, nullptr, nullptr, ptv) > 0;
}

}  // namespace uconnect::io
