#pragma once
// The rendezvous server's runtime: the sockets around ControlService.
//
// One TCP listener and one UDP socket, on the same port number. Every TCP
// connection's first frame decides what it is:
//
//   RelayJoin  -> one leg of a TCP relay. It waits for the other leg; once both
//                 have joined, each gets RelayJoinOk and from then on the
//                 server splices raw bytes between them, charging the binding.
//   anything   -> a node's control connection, handed to ControlService for
//   else          as long as it stays open.
//
// poll_once() does one round of waiting and work; the binary loops on it, and
// tests drive it from a thread of their own. With threads > 1 the server also
// runs workers beside that loop: once a relay pair is spliced it moves to a
// worker, which carries it alone from then on, and every thread -- the loop
// and the workers -- reads the one UDP socket. The registry and control
// service are shared, under a lock held only for the bookkeeping, never
// across a socket call.

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "control_service.hpp"
#include "socket.hpp"

namespace uconnect::server {

// The largest UDP datagram the server reads whole; anything longer is cut.
inline constexpr size_t kMaxUdpDatagram = 2048;

struct RendezvousConfig {
    uint16_t    port = 4433;  // 0 = ephemeral; TCP and UDP get the same number
    std::string bind_host;    // UDP only; empty = all interfaces. TCP listens on all.

    RegistryConfig registry;
    ControlConfig  control;

    size_t max_connections        = 20000;
    size_t max_connections_per_ip = 64;

    // A control connection that says nothing this long is closed, and its
    // records with it. Nodes send a keepalive every 20s.
    std::chrono::seconds idle_timeout{90};
    // A new connection must say what it is within this.
    std::chrono::seconds first_frame_timeout{10};
    // A relay leg waits this long for its partner.
    std::chrono::seconds relay_join_timeout{20};
    // A spliced relay pair that carries nothing either way this long is
    // closed. Its nodes send a keepalive every 20s, so only a pair whose ends
    // have both vanished without closing -- power lost, NAT mapping gone --
    // goes this quiet; nothing else would ever end it.
    std::chrono::seconds relay_idle_timeout{90};

    // Bytes a splice holds for a slow receiver before it stops reading from
    // the sender -- backpressure, not buffering without bound.
    size_t splice_buffer = 256 * 1024;

    // Threads carrying traffic: 1 is poll_once()'s loop alone; each one more
    // is a worker beside it. Relayed traffic is what they share -- TCP relay
    // pairs are spread across the workers, and all threads read UDP -- so
    // beyond the cores the relays can use, more only adds switching.
    size_t threads = 1;
};

class Rendezvous {
public:
    explicit Rendezvous(RendezvousConfig cfg);
    ~Rendezvous();
    Rendezvous(const Rendezvous&)            = delete;
    Rendezvous& operator=(const Rendezvous&) = delete;

    // Bind the listener and the UDP socket, and start the workers. False, with
    // error(), on failure.
    bool        open();
    uint16_t    port() const { return port_; }
    std::string error() const { return err_; }

    // Wait up to `timeout` for activity, then deal with all of it.
    void poll_once(std::chrono::milliseconds timeout);

    // Unlocked, for a single-threaded server between poll_once() calls --
    // what the tests do. With workers running, use the two below.
    ControlService& service() { return service_; }
    RegistryStats   stats(Instant now);
    size_t          control_connections();

    // Every TCP connection, the workers' included.
    size_t open_connections() const;

    // Test hook: every incoming control message and UDP datagram is offered
    // to this first; returning true drops it, as a lossy path would.
    std::function<bool(std::span<const uint8_t>)> drop_filter;

private:
    enum class Mode : uint8_t { New, Control, RelayWaiting, Splice };

    struct Conn {
        ConnKey                    key = 0;
        io::TcpSocket              sock;
        Endpoint                   peer{};
        wire::ctl::FrameReader     reader;
        std::vector<uint8_t>       relay_early; // bounded raw input before pairing
        std::vector<uint8_t>       out;  // bytes waiting to be written
        Mode                       mode = Mode::New;
        wire::RelayId              relay_id = 0;
        int                        relay_side = -1;
        ConnKey                    partner = 0;
        Instant                    opened{};
        Instant                    last_rx{};
        bool                       read_done = false;  // a splice survivor that stopped sending
        bool                       dead = false;
    };

    using ConnMap = std::unordered_map<ConnKey, Conn>;
    struct Worker;

    void accept_all(Instant now);
    void read_from(Conn&, Instant now);
    void on_frame(Conn&, std::span<const uint8_t> msg, Instant now);
    void on_relay_join(Conn&, std::span<const uint8_t> msg, Instant now);
    void splice_read(Conn&, ConnMap&, Instant now);
    void flush(Conn&);
    void deliver(const Framed&);
    void kill(Conn&);
    void reap(Instant now);
    bool splice_idle(const Conn&, const ConnMap&, Instant now) const;
    void read_udp(Instant now);

    // Shared with the workers.
    bool charge(wire::RelayId, size_t bytes, Instant now);  // relay_charge, locked
    void release(const Conn&);  // a closed connection leaves its address's count
    void hand_off();            // spliced pairs from conns_ to the workers
    void worker_loop(Worker&);

    RendezvousConfig cfg_;
    Registry         registry_;
    ControlService   service_;
    io::TcpSocket    listener_;
    io::UdpSocket    udp_;
    uint16_t         port_ = 0;
    std::string      err_;

    ConnMap                                                        conns_;  // the loop's own
    std::unordered_map<std::array<uint8_t, 16>, size_t, ArrayHash> per_ip_;
    // A relay leg waiting for its partner, by relay id and side.
    std::unordered_map<wire::RelayId, ConnKey> waiting_[2];
    ConnKey next_key_ = 1;
    Instant last_tick_{};

    std::mutex service_mu_;  // registry_ and service_
    std::mutex ip_mu_;       // per_ip_
    std::vector<std::pair<ConnKey, ConnKey>> spliced_;  // pairs to hand off this round
    std::vector<std::unique_ptr<Worker>>     workers_;
    size_t                                   next_worker_ = 0;
    std::atomic<bool>                        stop_{false};
};

}  // namespace uconnect::server
