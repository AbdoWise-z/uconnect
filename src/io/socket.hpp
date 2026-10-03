#pragma once
// UDP and TCP sockets, readiness polling, and interface enumeration. This is the
// ONLY place in the library that touches a socket -- everything below it takes
// bytes and a clock reading as parameters. If a lower layer ever needs to
// include this header, a layering violation has happened.

#include <chrono>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "uconnect/types.hpp"

namespace uconnect::io {

// A socket as the OS knows it: a SOCKET on Windows, an int elsewhere, carried
// in one type wide enough for both.
using NativeSocket = long long;
inline constexpr NativeSocket kInvalidSocket = -1;

// Resolve "host:port" to an endpoint. Returns nullopt on failure.
std::optional<Endpoint> resolve(const std::string& host_port);

std::string to_string(const Endpoint&);
std::string to_string(const IpAddr&);

// Every usable local address, for host candidates. ULA and global IPv6 are
// kept, because two devices on the same LAN frequently have working IPv6 when
// IPv4 is double-NATed.
//
// Loopback and link-local are excluded. A link-local IPv6 address cannot be
// dialed without an interface scope id, which a candidate does not carry --
// and would be the sender's interface, meaningless to the peer. Advertising
// one also got every registration reset on at least one real network: a
// middlebox there resets any TCP flow whose first segment carries an fe80::
// address, so a node publishing before its control connection was up never
// connected at all.
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

    NativeSocket native() const { return fd_; }

private:
    static constexpr long long kInvalid = -1;

    long long   fd_ = kInvalid;
    uint16_t    local_port_ = 0;
    bool        v6_ = false;
    std::string err_;
};

// A TCP socket. Non-blocking throughout: nothing here ever waits, which is what
// lets one thread drive a listener, a server connection and every peer
// connection at once. Readiness comes from io::poll().
class TcpSocket {
public:
    TcpSocket();
    ~TcpSocket();
    TcpSocket(const TcpSocket&)            = delete;
    TcpSocket& operator=(const TcpSocket&) = delete;
    TcpSocket(TcpSocket&&) noexcept;
    TcpSocket& operator=(TcpSocket&&) noexcept;

    // Create the socket and bind it to `port` (0 = ephemeral) with address
    // reuse on. A node's listener, its connection to the rendezvous server and
    // every punch attempt share ONE local port: the NAT mapping that port gets
    // is the address peers are told to dial, so an attempt from any other
    // port would present an address nobody knows. Every socket sharing a port
    // must be opened the same way, so `v6` defaults to the dual-stack IPv6
    // socket that also reaches IPv4.
    bool open(uint16_t port, bool v6 = true);

    // Connections the kernel holds for accept(). A burst beyond it is not
    // refused: Linux drops the handshake's last packet and retransmits on a
    // backoff, so the overflow arrives seconds late. A node that dials many
    // peers at once gets such a burst back, hence the room.
    bool listen(int backlog = 128);

    // A waiting inbound connection, or nullopt if there is none right now.
    std::optional<TcpSocket> accept();

    // Start a non-blocking connect. False means it failed at once; otherwise
    // watch state() -- or poll() for writability -- to see how it ends.
    bool connect(const Endpoint& to);

    enum class State : uint8_t { Idle, Connecting, Connected, Failed };
    // Advances Connecting to Connected or Failed once the outcome is known.
    State state();

    // Bytes moved; 0 means the call would block. Nullopt means the connection
    // is over -- closed by the peer, or failed -- and the socket should go.
    std::optional<size_t> send(std::span<const uint8_t>);
    std::optional<size_t> recv(std::span<uint8_t>);

    void close();
    // Abandon a failed connection with a reset, discarding unsent bytes. This
    // permits reconnecting from the same local port without a graceful-close
    // TIME_WAIT interval. Use only when the connection is already unusable.
    void abort();

    bool                    is_open() const { return fd_ != kInvalidSocket; }
    uint16_t                local_port() const { return local_port_; }
    std::optional<Endpoint> remote() const;
    NativeSocket            native() const { return fd_; }
    std::string             last_error() const { return err_; }

private:
    explicit TcpSocket(NativeSocket accepted, bool v6);
    void set_connected_options();

    NativeSocket fd_         = kInvalidSocket;
    uint16_t     local_port_ = 0;
    bool         v6_         = false;
    State        state_      = State::Idle;
    std::string  err_;
};

// One socket's interest and, after poll(), its readiness.
struct PollItem {
    NativeSocket fd         = kInvalidSocket;
    bool         want_read  = false;
    bool         want_write = false;

    bool readable = false;
    bool writable = false;
    bool failed   = false;  // error or hang-up; a recv/send will say which
};

// Wait until at least one item is ready or `timeout` passes, then report on
// every item. Built on poll()/WSAPoll rather than select(), which on Windows
// stops at 64 sockets -- fewer than a busy node can hold. False on error.
bool poll(std::span<PollItem> items, std::chrono::milliseconds timeout);

// One-time platform init (WSAStartup on Windows). Safe to call repeatedly.
bool init_networking();

}  // namespace uconnect::io
