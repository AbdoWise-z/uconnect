// Node and Topic: the public API, and the only place where the sans-IO layers
// are driven by real sockets and a real clock.
//
// Sockets, all on the node's ONE local TCP port P unless noted:
//
//   listener      accepts peers punching in to us
//   control       the persistent connection to the rendezvous server; all
//                 signaling runs over it, and the server reaches us through it
//   dials         outgoing punch attempts to a peer's candidates
//   relay legs    connections to the server's relay (ephemeral port)
//   sessions      one TcpSession per connected peer, on whichever connection
//                 won
//
// Connecting to a peer. The side that decides to connect sends CONNECT with a
// fresh attempt nonce and its candidates; the server delivers it to the peer
// as Relayed. Both then dial each other's candidates from P while accepting
// on P, so the two SYNs cross the NATs and open them. The first connection to
// come up carries the Noise handshake, bound to the attempt nonce; the smaller
// dev_id is the Noise initiator whichever side dialed. If nothing connects
// within punch_timeout, both fall back to a relay allocated through the
// server.
//
// Identifying a connection. A responder that dialed opens with a hello --
// 'U' 'C' and the attempt nonce -- so an initiator holding a connection it
// accepted knows which peer is calling. An initiator's first frame names the
// attempt too, so a responder can identify inbound connections from that.
// Relay legs need neither: both ends already know the attempt.
//
// Datagrams. One UDP socket, opened the first time a channel needs it, on P's
// number when that is free. A channel is opened over the TCP session: each
// side sends an offer -- the channel's epoch and its UDP candidates, including
// the reflexive address the server's WhoAmI reported -- and both punch with
// probes tagged by the channel's probe key. The epoch picks the keys
// (TcpSession::datagram_keys), so a reopened channel never reuses a nonce.
// Where punching fails, each side applies its own fallback: datagrams over
// the TCP session, the server's UDP relay, or none.

#include "uconnect/uconnect.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <utility>

#include "control.hpp"
#include "kdf.hpp"
#include "primitives.hpp"
#include "punch.hpp"
#include "session.hpp"
#include "socket.hpp"
#include "tcp_session.hpp"

namespace uconnect {
namespace {

using namespace std::chrono_literals;
namespace ctl = wire::ctl;
using session::AttemptNonce;
using session::TcpSession;

constexpr auto kDiscoveryInterval = 5s;   // auto-connect LOOKUP cadence
constexpr auto kRedial            = 500ms;
constexpr auto kRelayBackupDelay  = 2s;   // the non-designated side waits this long for an offer
constexpr auto kRelayWindow       = 20s;  // after punching gives up, time allowed for a relay
constexpr auto kInboundIdentify   = 10s;  // an unidentified connection must speak by then
constexpr auto kLiveSession       = 30s;  // a session heard from this recently is never replaced
constexpr auto kIntroWait         = 2s;   // an inbound connection may beat its introduction here
constexpr auto kHandshakeRetry    = 1s;   // after a failed handshake, a fresh introduction
constexpr int  kMaxHandshakeRetries = 2;
constexpr auto kReconnectMin      = 500ms;
constexpr auto kReconnectMax      = 30s;

// Bytes allowed to queue for one peer before send() refuses more: a peer that
// reads slowly must not grow our memory without bound.
constexpr size_t kMaxQueued = 16u << 20;

// Record kinds on a TcpSession that belong to this layer.
constexpr uint8_t kMessageRecord = 0x10;  // an application message
constexpr uint8_t kDgramOffer    = 0x11;  // epoch(4) | UDP candidates: open or answer a channel
constexpr uint8_t kDgramOverTcp  = 0x12;  // one datagram, when UDP could not be had
constexpr uint8_t kDgramClose    = 0x13;  // epoch(4): that channel is closed

// Datagram channels.
constexpr auto kGatherWait    = 1500ms;  // wait this long for our UDP srflx before offering without it
constexpr auto kWhoAmIEvery   = 500ms;
constexpr auto kUdpBindEvery  = 500ms;
constexpr auto kUdpRelayWait  = 10s;     // to allocate and bind the UDP relay

namespace close_reason {
constexpr uint16_t kGoingAway = 1;  // application closed this connection
constexpr uint16_t kShutdown  = 2;  // the whole node is exiting
}  // namespace close_reason

struct ArrayHash {
    template <size_t N>
    size_t operator()(const std::array<uint8_t, N>& a) const noexcept {
        uint64_t h = 1469598103934665603ULL;
        for (uint8_t b : a) {
            h ^= b;
            h *= 1099511628211ULL;
        }
        return static_cast<size_t>(h);
    }
};

struct TopicIdLess {
    bool operator()(const TopicId& a, const TopicId& b) const {
        return std::memcmp(a.data(), b.data(), a.size()) < 0;
    }
};

// The peer supplies only the reason code; the cause is our own account, so a
// hostile peer cannot dress its disappearance up as our idle timer.
PeerGone peer_gone_from(session::CloseCause cause, uint16_t peer_reason) {
    switch (cause) {
        case session::CloseCause::Local:    return PeerGone::Local;
        case session::CloseCause::TimedOut: return PeerGone::TimedOut;
        case session::CloseCause::PeerNotice:
            switch (peer_reason) {
                case close_reason::kGoingAway: return PeerGone::GoingAway;
                case close_reason::kShutdown:  return PeerGone::ShuttingDown;
                default:                       return PeerGone::Unspecified;
            }
    }
    return PeerGone::Unspecified;
}

bool smaller(const DevId& a, const DevId& b) { return std::memcmp(a.data(), b.data(), kDevIdLen) < 0; }

// The CONNECT payload: which topic, which attempt, and where to dial us. Opaque
// to the server, which only relays it.
std::vector<uint8_t> encode_intro(const TopicId& topic, const AttemptNonce& attempt,
                                  const std::vector<Candidate>& cands) {
    std::vector<uint8_t> buf(wire::kMaxRelayPayload);
    wire::Writer         w{buf};
    w.array(topic);
    w.array(attempt);
    const size_t n = std::min<size_t>(cands.size(), wire::kMaxCandidates);
    w.u8(static_cast<uint8_t>(n));
    for (size_t i = 0; i < n; ++i) w.candidate(cands[i]);
    if (!w.ok()) return {};
    buf.resize(w.size());
    return buf;
}

bool decode_intro(std::span<const uint8_t> p, TopicId& topic, AttemptNonce& attempt,
                  std::vector<Candidate>& cands) {
    wire::Reader r{p};
    topic          = r.array<kTopicIdLen>();
    attempt        = r.array<session::kAttemptLen>();
    const size_t n = r.u8();
    if (!r.ok() || n > wire::kMaxCandidates) return false;
    for (size_t i = 0; i < n; ++i) cands.push_back(r.candidate());
    return r.ok();
}


std::vector<uint8_t> encode_dgram_offer(uint32_t epoch, const std::vector<Candidate>& cands) {
    std::vector<uint8_t> buf(512);
    wire::Writer         w{buf};
    w.u32(epoch);
    const size_t n = std::min<size_t>(cands.size(), wire::kMaxCandidates);
    w.u8(static_cast<uint8_t>(n));
    for (size_t i = 0; i < n; ++i) w.candidate(cands[i]);
    buf.resize(w.size());
    return buf;
}

bool decode_dgram_offer(std::span<const uint8_t> p, uint32_t& epoch, std::vector<Candidate>& cands) {
    wire::Reader r{p};
    epoch          = r.u32();
    const size_t n = r.u8();
    if (!r.ok() || n > wire::kMaxCandidates) return false;
    for (size_t i = 0; i < n; ++i) cands.push_back(r.candidate());
    return r.ok();
}

std::vector<uint8_t> encode_u32(uint32_t v) {
    return {static_cast<uint8_t>(v >> 24), static_cast<uint8_t>(v >> 16),
            static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v)};
}

std::optional<uint32_t> decode_u32(std::span<const uint8_t> p) {
    if (p.size() < 4) return std::nullopt;
    return static_cast<uint32_t>(p[0]) << 24 | static_cast<uint32_t>(p[1]) << 16 |
           static_cast<uint32_t>(p[2]) << 8 | p[3];
}

}  // namespace

const char* to_string(DatagramPath p) {
    switch (p) {
        case DatagramPath::None:    return "none";
        case DatagramPath::Opening: return "opening";
        case DatagramPath::Direct:  return "direct";
        case DatagramPath::Relayed: return "relayed";
        case DatagramPath::Tcp:     return "tcp";
        case DatagramPath::Failed:  return "failed";
    }
    return "?";
}

const char* to_string(PeerGone g) {
    switch (g) {
        case PeerGone::Local:        return "local";
        case PeerGone::TimedOut:     return "timed-out";
        case PeerGone::GoingAway:    return "going-away";
        case PeerGone::ShuttingDown: return "shutting-down";
        case PeerGone::Unspecified:  return "unspecified";
    }
    return "unspecified";
}

const char* to_string(PeerState s) {
    switch (s) {
        case PeerState::Unknown:     return "unknown";
        case PeerState::Probing:     return "probing";
        case PeerState::Handshaking: return "handshaking";
        case PeerState::Connected:   return "connected";
        case PeerState::Failed:      return "failed";
        case PeerState::Closed:      return "closed";
    }
    return "?";
}

// ---------------------------------------------------------------------------
// TopicCreds
// ---------------------------------------------------------------------------
TopicCreds TopicCreds::generate_keyed() {
    TopicCreds c;
    crypto::random_bytes(c.id);
    Key k{};
    crypto::random_bytes(k);
    c.key = k;
    return c;
}

TopicCreds TopicCreds::generate_open() {
    TopicCreds c;
    crypto::random_bytes(c.id);
    return c;
}

std::optional<TopicCreds> TopicCreds::parse(std::string_view uri) {
    constexpr std::string_view kScheme = "uconn://";
    if (uri.substr(0, kScheme.size()) != kScheme) return std::nullopt;
    uri.remove_prefix(kScheme.size());

    std::string_view id_hex = uri;
    std::string_view key_hex;
    if (auto hash = uri.find('#'); hash != std::string_view::npos) {
        id_hex  = uri.substr(0, hash);
        key_hex = uri.substr(hash + 1);
    }

    TopicCreds c;
    if (!from_hex(id_hex, c.id.data(), c.id.size())) return std::nullopt;
    if (!key_hex.empty()) {
        Key k{};
        if (!from_hex(key_hex, k.data(), k.size())) return std::nullopt;
        c.key = k;
    }
    return c;
}

std::string TopicCreds::to_uri() const {
    std::string s = "uconn://" + to_hex(id);
    if (key) s += "#" + to_hex(*key);
    return s;
}

// ---------------------------------------------------------------------------
// Internal structures
// ---------------------------------------------------------------------------
namespace {

// A TCP connection to a peer that no session owns yet.
struct PendingConn {
    enum class Kind : uint8_t {
        Dial,      // we are punching out to one of the peer's candidates
        Inbound,   // accepted on our port; peer unknown until it speaks
        RelayLeg,  // our side of a relay, joining at the server
    };

    Kind          kind = Kind::Dial;
    io::TcpSocket sock;
    Instant       started{};
    bool          dead = false;

    // Known from the start for Dial and RelayLeg; learned for Inbound.
    bool         known = false;
    TopicId      topic{};
    DevId        peer{};
    AttemptNonce attempt{};

    Endpoint             target{};  // Dial
    std::vector<uint8_t> in;        // bytes read before a session took over
    std::vector<uint8_t> out;       // bytes still to write: a hello, a RelayJoin
    bool                 greeted = false;

    // RelayLeg
    wire::RelayId          relay_id = 0;
    ctl::RelayToken        token{};
    ctl::FrameReader       reader;
    bool                   joined = false;
};

// A peer's UDP datagram channel, beside its TCP session.
struct Dgram {
    uint32_t                          epoch    = 0;
    DatagramFallback                  fallback = DatagramFallback::Tcp;
    DatagramPath                      path     = DatagramPath::Opening;
    crypto::SymKey                    probe_key{};
    uint32_t                          conn_id = 0;
    Instant                           opened{};

    bool                                  offered = false;  // ours, sent
    std::optional<std::vector<Candidate>> remote;           // theirs, received
    std::optional<path::PunchSession>     punch;
    std::optional<Endpoint>               direct;           // the punched path, once there is one
    // Created with the channel and never replaced: its counter is the nonce,
    // and a second Session under these keys would start it again from zero.
    std::optional<session::Session>       sess;

    // The UDP relay: taken when punching fails and the fallback says so, and
    // bound whenever the peer offers one, so its relayed datagrams reach us.
    bool                          relaying    = false;  // falling back to it
    bool                          relay_asked = false;
    Instant                       relay_backup_at{};
    Instant                       relay_deadline{};
    std::optional<wire::RelayId>  relay_id;
    ctl::RelayToken               relay_token{};
    bool                          relay_bound = false;
    Instant                       next_bind{};
};

struct Peer {
    DevId                  dev_id{};
    std::vector<Candidate> cands;
    PeerState              state = PeerState::Unknown;

    // The introduction in progress, if any.
    std::optional<AttemptNonce> attempt;
    Instant                     attempt_started{};
    Instant                     punch_deadline{};
    Instant                     next_redial{};
    Instant                     relay_backup_at{};
    bool                        relay_asked = false;
    bool                        relay_joining = false;

    // A handshake that failed is retried with a new introduction, not the old
    // one: the peer may have completed its side and spent that nonce.
    Instant retry_at{};
    int     retries = 0;

    // The session, and the connection it runs on.
    std::optional<TcpSession> sess;
    io::TcpSocket             sock;
    std::vector<uint8_t>      out;
    bool                      relayed = false;
    bool                      closing = false;  // flush `out`, then close

    // The datagram channel, if one is open, and the highest epoch used on
    // this TCP session -- a new channel must go above it.
    std::optional<Dgram> dgram;
    uint32_t             dgram_epoch = 0;

    LinkInfo link{};
};

// A request to the server awaiting its reply.
struct Request {
    wire::MsgType        expect{};
    bool                 done  = false;
    ErrorCode            error = ErrorCode::None;
    std::vector<uint8_t> reply;  // the whole reply message, for blocking callers

    // Issued by the loop for itself; the reply handler applies it.
    std::optional<TopicId>                   keepalive_for;
    bool                                     conn_keepalive = false;  // no record: the connection itself
    std::optional<TopicId>                   register_for;
    std::optional<TopicId>                   discover_for;
    std::optional<std::pair<TopicId, DevId>> relay_for;
    std::optional<std::pair<TopicId, DevId>> dgram_relay_for;  // a UDP relay
    uint32_t                                 dgram_epoch = 0;
    bool                                     loop_owned = false;
};

}  // namespace

// ---------------------------------------------------------------------------
struct Topic::Impl {
    Node::Impl*       node = nullptr;
    TopicCreds        creds;
    crypto::TopicKeys keys;
    bool              keyed = false;

    std::optional<DevId> self;
    bool                 published     = false;
    bool                 unlisted      = false;
    bool                 reregistering = false;
    std::vector<uint8_t> meta;
    Instant              next_keepalive{};
    Instant              next_discovery{};

    std::unordered_map<DevId, Peer, ArrayHash> peers;
    size_t                                     max_peers    = 8;
    bool                                       auto_connect = false;

    std::function<void(DevId, PeerState)>                on_peer;
    std::function<void(DevId, std::span<const uint8_t>)> on_data;
    std::function<void(DevId, PeerGone)>                 on_peer_closed;
    std::function<void(DevId, std::span<const uint8_t>)> on_datagram;
    std::function<void(DevId, DatagramPath)>             on_datagram_path;

    const crypto::SymKey* psk() const { return keyed ? &keys.psk : nullptr; }
};

struct Node::Impl {
    Node::Config cfg;
    Endpoint     server{};

    io::TcpSocket listener;
    uint16_t      port = 0;

    // --- control connection -------------------------------------------------
    enum class Ctl : uint8_t { Down, Connecting, Up };
    io::TcpSocket        control;
    Ctl                  ctl_state = Ctl::Down;
    ctl::FrameReader     ctl_reader;
    std::vector<uint8_t> ctl_out;
    Instant              next_reconnect{};
    Instant              next_ctl_keepalive{};
    std::chrono::milliseconds reconnect_backoff = kReconnectMin;

    std::vector<Candidate>  host_cands;
    std::optional<Endpoint> srflx;

    // --- UDP, for datagram channels ----------------------------------------
    io::UdpSocket           udp;
    bool                    udp_ready = false;
    bool                    udp_tried = false;
    std::optional<Endpoint> udp_srflx;  // as the server's WhoAmI saw us
    uint64_t                whoami_nonce = 0;
    Instant                 next_whoami{};

    mutable std::mutex      mu;
    std::condition_variable cv;

    std::map<TopicId, std::unique_ptr<Topic>, TopicIdLess> topics;
    std::unordered_map<uint32_t, Request>                  requests;
    uint32_t                                               next_txn = 1;

    std::vector<std::unique_ptr<PendingConn>> pending;
    // Outstanding attempts, so an inbound connection naming one can be tied to
    // its topic and peer. Each is spent by the session it admits.
    std::unordered_map<AttemptNonce, std::pair<TopicId, DevId>, ArrayHash> attempts;

    std::vector<std::function<void()>> deferred;

    std::thread       thread;
    std::thread::id   loop_thread_id{}; // guarded by mu, including caller-owned run()
    std::mutex        join_mu;
    std::atomic<bool> running{false};
    std::atomic<bool> stop{false};

    // --- helpers -----------------------------------------------------------
    Instant now() const { return std::chrono::steady_clock::now(); }
    bool on_loop_thread() const { return loop_thread_id == std::this_thread::get_id(); }
    uint32_t alloc_txn() { return next_txn++; }

    session::TcpSessionConfig session_cfg() const { return {}; }

    // Queue a control message; returns its txn.
    template <typename T>
    uint32_t request(wire::MsgType type, wire::MsgType expect, const T& body, Request r = {},
                     uint8_t flags = 0) {
        const uint32_t txn = alloc_txn();
        auto           f   = ctl::frame(ctl::message(type, txn, body, flags));
        ctl_out.insert(ctl_out.end(), f.begin(), f.end());
        r.expect      = expect;
        requests[txn] = std::move(r);
        return txn;
    }
    uint32_t request_empty(wire::MsgType type, wire::MsgType expect) {
        const uint32_t txn = alloc_txn();
        auto           f   = ctl::frame(ctl::empty_message(type, txn));
        ctl_out.insert(ctl_out.end(), f.begin(), f.end());
        Request r;
        r.expect      = expect;
        requests[txn] = std::move(r);
        return txn;
    }
    // A message that expects no reply.
    template <typename T>
    void notify(wire::MsgType type, const T& body) {
        auto f = ctl::frame(ctl::message(type, alloc_txn(), body));
        ctl_out.insert(ctl_out.end(), f.begin(), f.end());
    }

    // Wait, with `lk` held on `mu`, for request `txn` to finish.
    bool wait_for(std::unique_lock<std::mutex>& lk, uint32_t txn,
                  std::chrono::steady_clock::time_point deadline) {
        while (std::chrono::steady_clock::now() < deadline) {
            auto it = requests.find(txn);
            if (it == requests.end()) return false;
            if (it->second.done) return true;
            cv.wait_for(lk, 20ms);
        }
        return false;
    }

    std::vector<Candidate> my_candidates() const {
        std::vector<Candidate> c;
        if (srflx) c.push_back(Candidate{Candidate::Kind::Srflx, *srflx});
        for (const auto& h : host_cands) {
            if (c.size() >= wire::kMaxCandidates) break;
            c.push_back(h);
        }
        return c;
    }

    void gather_host_candidates();
    void loop();
    void finish_shutdown(); // with mu held, after the loop stops using sockets
    void tick(Instant now);

    // control
    void drive_control(Instant now);
    void on_control_down(Instant now, const char* why);
    void on_control_message(std::span<const uint8_t> msg, Instant now);
    void on_relayed(const wire::Relayed&, Instant now);
    void on_relay_offer(const ctl::RelayOffer&, Instant now);
    void send_register(Topic::Impl&, const TopicId&, bool loop_owned);
    void send_conn_keepalive(Instant now);

    // peers
    void begin_connect(Topic::Impl&, const TopicId&, const DevId&, Instant now);
    void adopt_attempt(Topic::Impl&, const TopicId&, Peer&, const AttemptNonce&, Instant now);
    void dial_all(const TopicId&, Peer&, Instant now);
    void request_relay(Topic::Impl&, const TopicId&, Peer&);
    void join_relay(const TopicId&, const DevId&, const AttemptNonce&, wire::RelayId,
                    const ctl::RelayToken&, Instant now);
    void drive_pending(PendingConn&, Instant now);
    void start_session(PendingConn&, Instant now);
    void drive_peer(Topic::Impl&, const TopicId&, Peer&, Instant now);
    void flush_peer(Peer&);
    void disconnect_peer(Topic::Impl&, Peer&, uint16_t reason);
    void end_attempt(Peer&);
    void set_peer_state(Topic::Impl&, Peer&, PeerState);
    bool send_record(Peer&, uint8_t kind, std::span<const uint8_t> body);

    // datagrams
    bool ensure_udp();
    std::vector<Candidate> udp_candidates() const;
    void read_udp(Instant now);
    void on_udp(const Endpoint& from, std::span<const uint8_t> dgram, Instant now);
    void on_udp_from_server(std::span<const uint8_t> dgram, Instant now);
    bool dgram_open(Topic::Impl&, Peer&, uint32_t epoch, DatagramFallback, Instant now);
    void dgram_on_offer(Topic::Impl&, Peer&, std::span<const uint8_t> body, Instant now);
    void dgram_drop(Topic::Impl&, Peer&);
    void dgram_fall_back(Topic::Impl&, Peer&, Instant now);
    void dgram_set_path(Topic::Impl&, Peer&, DatagramPath);
    void drive_dgram(Topic::Impl&, const TopicId&, Peer&, Instant now);
    void flush_dgram(Peer&);
    void dgram_relay_granted(Peer&, wire::RelayId, const ctl::RelayToken&, Instant now);
    Topic::Impl* topic_impl(const TopicId&);
    size_t       live_peer_count(const Topic::Impl&) const;
    size_t       total_peer_count() const;
    bool         can_admit(const Topic::Impl&, const Peer*) const;
};

// ---------------------------------------------------------------------------
// Candidates and the loop
// ---------------------------------------------------------------------------
void Node::Impl::gather_host_candidates() {
    host_cands.clear();
    for (const auto& ip : io::local_addresses()) {
        if (host_cands.size() >= wire::kMaxCandidates - 1) break;  // leave room for srflx
        host_cands.push_back(Candidate{Candidate::Kind::Host, Endpoint{ip, port}});
    }
}

Topic::Impl* Node::Impl::topic_impl(const TopicId& id) {
    auto it = topics.find(id);
    return it == topics.end() ? nullptr : it->second->impl_.get();
}

void Node::Impl::loop() {
    {
        std::lock_guard<std::mutex> lk(mu);
        if (running || stop) return;
        loop_thread_id = std::this_thread::get_id();
        running = true;
        cv.notify_all();
    }
    std::vector<uint8_t> buf(64 * 1024);

    while (!stop) {
        // Build the poll set under the lock, wait without it.
        std::vector<io::PollItem> items;
        {
            std::lock_guard<std::mutex> lk(mu);
            io::PollItem li;
            li.fd        = listener.native();
            li.want_read = true;
            items.push_back(li);
            if (udp_ready) {
                io::PollItem ui;
                ui.fd        = udp.native();
                ui.want_read = true;
                items.push_back(ui);
            }
            if (ctl_state != Ctl::Down) {
                io::PollItem ci;
                ci.fd         = control.native();
                ci.want_read  = ctl_state == Ctl::Up;
                ci.want_write = ctl_state == Ctl::Connecting || !ctl_out.empty();
                items.push_back(ci);
            }
            for (const auto& p : pending) {
                if (p->dead) continue;
                io::PollItem pi;
                pi.fd         = p->sock.native();
                pi.want_read  = true;
                pi.want_write = !p->out.empty() ||
                                p->sock.state() == io::TcpSocket::State::Connecting;
                items.push_back(pi);
            }
            for (auto& [tid, t] : topics) {
                (void)tid;
                for (auto& [dev, peer] : t->impl_->peers) {
                    (void)dev;
                    if (!peer.sess || !peer.sock.is_open()) continue;
                    io::PollItem si;
                    si.fd         = peer.sock.native();
                    si.want_read  = true;
                    si.want_write = !peer.out.empty();
                    items.push_back(si);
                }
            }
        }
        io::poll(items, 20ms);

        std::vector<std::function<void()>> callbacks;
        {
            std::lock_guard<std::mutex> lk(mu);
            tick(now());
            callbacks.swap(deferred);
        }
        // Invoked with the lock released, so a callback may call straight back
        // into the library -- send a reply or disconnect someone. Synchronous
        // queries reject loop-thread calls before queuing a request.
        for (auto& fn : callbacks) fn();
    }
    // Callbacks may request shutdown themselves. Finish their queued notices
    // on this same thread before releasing topics and sockets.
    std::vector<std::function<void()>> callbacks;
    {
        std::lock_guard<std::mutex> lk(mu);
        callbacks.swap(deferred);
    }
    for (auto& fn : callbacks) fn();
    std::lock_guard<std::mutex> lk(mu);
    finish_shutdown();
    loop_thread_id = {};
    running = false;
    cv.notify_all();
}

void Node::Impl::finish_shutdown() {
    topics.clear();
    pending.clear();
    attempts.clear();
    requests.clear();
    deferred.clear();
    ctl_out.clear();
    control.close();
    ctl_state = Ctl::Down;
    listener.close();
    udp.close();
    udp_ready = false;
}

void Node::Impl::tick(Instant now) {
    // Inbound connections: identified once they speak.
    for (int i = 0; i < 64; ++i) {
        auto s = listener.accept();
        if (!s) break;
        auto pc     = std::make_unique<PendingConn>();
        pc->kind    = PendingConn::Kind::Inbound;
        pc->sock    = std::move(*s);
        pc->started = now;
        pending.push_back(std::move(pc));
    }

    drive_control(now);
    read_udp(now);

    // Index-based: driving a connection can add more (a relay leg).
    for (size_t i = 0; i < pending.size(); ++i) {
        if (!pending[i]->dead) drive_pending(*pending[i], now);
    }
    std::erase_if(pending, [](const auto& p) { return p->dead; });

    // Topic keepalives hold the connection open too; with nothing published,
    // it needs its own.
    if (ctl_state == Ctl::Up && now >= next_ctl_keepalive) {
        const bool any_published = std::any_of(topics.begin(), topics.end(), [](const auto& kv) {
            return kv.second->impl_->published && kv.second->impl_->self;
        });
        if (any_published) next_ctl_keepalive = now + cfg.keepalive;
        else send_conn_keepalive(now);
    }

    for (auto& [tid, t] : topics) {
        auto& ti = *t->impl_;

        if (ti.published && ti.self && ctl_state == Ctl::Up && now >= ti.next_keepalive) {
            Request r;
            r.keepalive_for = tid;
            r.loop_owned    = true;
            request(wire::MsgType::Keepalive, wire::MsgType::KeepaliveOk, ctl::DevRef{*ti.self}, r);
            ti.next_keepalive = now + cfg.keepalive;
        }

        // Auto-connect: one LOOKUP per interval, driven here rather than by the
        // application polling peers() in a loop.
        if (ti.auto_connect && ti.published && ti.self && ctl_state == Ctl::Up &&
            now >= ti.next_discovery) {
            ti.next_discovery = now + kDiscoveryInterval;
            if (live_peer_count(ti) < ti.max_peers) {
                Request r;
                r.discover_for = tid;
                r.loop_owned   = true;
                ctl::Lookup l;
                l.id  = tid;
                l.max = wire::kLookupDefault;
                request(wire::MsgType::Lookup, wire::MsgType::LookupOk, l, r);
            }
        }

        for (auto& [dev, peer] : ti.peers) {
            (void)dev;
            drive_peer(ti, tid, peer, now);
            if (peer.dgram) drive_dgram(ti, tid, peer, now);
        }
    }

    // Our UDP mapping, for as long as a channel is still gathering it.
    if (udp_ready && !udp_srflx && now >= next_whoami) {
        bool gathering = false;
        for (auto& [tid, t] : topics) {
            (void)tid;
            for (auto& [dev, peer] : t->impl_->peers) {
                (void)dev;
                if (peer.dgram && !peer.dgram->offered) gathering = true;
            }
        }
        if (gathering) {
            if (whoami_nonce == 0) {
                auto n = crypto::random_array<8>();
                for (uint8_t b : n) whoami_nonce = whoami_nonce << 8 | b;
            }
            udp.send_to(server, ctl::message(wire::MsgType::WhoAmI, 0, ctl::WhoAmI{whoami_nonce}));
            next_whoami = now + kWhoAmIEvery;
        }
    }
}

// ---------------------------------------------------------------------------
// The control connection
// ---------------------------------------------------------------------------
void Node::Impl::drive_control(Instant now) {
    if (ctl_state == Ctl::Down) {
        if (now < next_reconnect) return;
        // From our own port, so the server observes -- and tells peers -- the
        // mapping our punches will use.
        if (!control.open(port) || !control.connect(server)) {
            control.close();
            next_reconnect    = now + reconnect_backoff;
            reconnect_backoff = std::min<std::chrono::milliseconds>(reconnect_backoff * 2, kReconnectMax);
            return;
        }
        ctl_state = Ctl::Connecting;
        return;
    }

    if (ctl_state == Ctl::Connecting) {
        auto st = control.state();
        if (st == io::TcpSocket::State::Failed) {
            on_control_down(now, "connect");
            return;
        }
        if (st != io::TcpSocket::State::Connected) return;
        ctl_state         = Ctl::Up;
        reconnect_backoff = kReconnectMin;
        ctl_reader        = ctl::FrameReader{};
        if (cfg.verbose) std::fprintf(stderr, "[uconnect] control connection up\n");
        // Say something at once: the server closes a connection that does not
        // identify itself, and the reply tells us our reflexive address.
        send_conn_keepalive(now);
        // Everything this connection's predecessor registered went with it.
        // Register again; the reply restores self.
        for (auto& [tid, t] : topics) {
            auto& ti = *t->impl_;
            if (ti.published && !ti.reregistering) {
                ti.reregistering = true;
                send_register(ti, tid, /*loop_owned=*/true);
            }
        }
    }

    // Up: read everything, then write what is queued.
    std::vector<uint8_t> buf(16 * 1024);
    for (int round = 0; round < 32; ++round) {
        auto got = control.recv(buf);
        if (!got) {
            on_control_down(now, "recv");
            return;
        }
        if (*got == 0) break;
        if (!ctl_reader.feed(std::span(buf).first(*got))) {
            on_control_down(now, "malformed frame");
            return;
        }
        while (auto msg = ctl_reader.next()) on_control_message(*msg, now);
    }
    while (!ctl_out.empty()) {
        auto n = control.send(ctl_out);
        if (!n) {
            on_control_down(now, "send");
            return;
        }
        if (*n == 0) break;
        ctl_out.erase(ctl_out.begin(), ctl_out.begin() + static_cast<ptrdiff_t>(*n));
    }
}

void Node::Impl::on_control_down(Instant now, const char* why) {
    if (cfg.verbose) {
        std::fprintf(stderr, "[uconnect] control connection down (%s: %s)\n", why,
                     control.last_error().c_str());
    }
    control.close();
    ctl_state = Ctl::Down;
    ctl_out.clear();
    next_reconnect    = now + reconnect_backoff;
    reconnect_backoff = std::min<std::chrono::milliseconds>(reconnect_backoff * 2, kReconnectMax);

    // Every request in flight went with the connection. Blocking callers learn
    // at once rather than waiting out their timeout; the loop's own are
    // simply forgotten -- keepalives and discovery run again on schedule.
    for (auto it = requests.begin(); it != requests.end();) {
        if (it->second.loop_owned) {
            if (it->second.register_for) {
                if (auto* ti = topic_impl(*it->second.register_for)) ti->reregistering = false;
            }
            it = requests.erase(it);
        } else {
            it->second.done  = true;
            it->second.error = ErrorCode::NotFound;
            ++it;
        }
    }
    cv.notify_all();
}

void Node::Impl::send_conn_keepalive(Instant now) {
    const uint32_t txn = alloc_txn();
    auto           f   = ctl::frame(ctl::empty_message(wire::MsgType::Keepalive, txn));
    ctl_out.insert(ctl_out.end(), f.begin(), f.end());
    Request r;
    r.expect         = wire::MsgType::KeepaliveOk;
    r.conn_keepalive = true;
    r.loop_owned     = true;
    requests[txn]    = std::move(r);
    next_ctl_keepalive = now + cfg.keepalive;
}

void Node::Impl::send_register(Topic::Impl& ti, const TopicId& tid, bool loop_owned) {
    ctl::Register m;
    m.id         = tid;
    m.mode       = ti.keyed ? TopicMode::Keyed : TopicMode::Open;
    m.unlisted   = ti.unlisted;
    m.host_cands = host_cands;
    m.meta       = ti.meta;
    Request r;
    if (loop_owned) {
        r.register_for = tid;
        r.loop_owned   = true;
    }
    request(wire::MsgType::Register, wire::MsgType::RegisterOk, m, r,
            ti.unlisted ? wire::flags::kUnlisted : uint8_t{0});
}

void Node::Impl::on_control_message(std::span<const uint8_t> msg, Instant now) {
    wire::Reader r{msg};
    auto         h = wire::Header::decode(r, ctl::kVersion);
    if (!h) return;

    // Pushed by the server, not replies to anything we asked.
    if (h->type == wire::MsgType::Relayed) {
        if (auto rel = wire::Relayed::decode(r)) on_relayed(*rel, now);
        return;
    }
    if (h->type == wire::MsgType::RelayOffer) {
        if (auto off = ctl::RelayOffer::decode(r)) on_relay_offer(*off, now);
        return;
    }

    auto it = requests.find(h->txn_id);
    if (it == requests.end()) {
        // An error for a message nobody waits on -- a CONNECT, say. Nothing to
        // resolve, but worth seeing: otherwise a refused introduction is silent.
        if (cfg.verbose && h->type == wire::MsgType::Error) {
            auto e = wire::Error::decode(r);
            std::fprintf(stderr, "[uconnect] server error txn=%u: %s\n", h->txn_id,
                         to_string(e ? e->code : ErrorCode::BadRequest));
        }
        return;
    }
    Request& req = it->second;

    if (h->type == wire::MsgType::Error) {
        auto e    = wire::Error::decode(r);
        req.error = e ? e->code : ErrorCode::BadRequest;
        if (cfg.verbose) {
            std::fprintf(stderr, "[uconnect] server error txn=%u: %s\n", h->txn_id,
                         to_string(req.error));
        }
        if (req.keepalive_for &&
            (req.error == ErrorCode::NotFound || req.error == ErrorCode::BadAuth)) {
            // The server no longer holds our record: register again.
            if (auto* ti = topic_impl(*req.keepalive_for); ti && ti->published && !ti->reregistering) {
                ti->reregistering = true;
                const TopicId tid = *req.keepalive_for;
                requests.erase(it);
                send_register(*ti, tid, true);
                return;
            }
        }
        if (req.register_for) {
            if (auto* ti = topic_impl(*req.register_for)) ti->reregistering = false;
        }
        if (req.dgram_relay_for) {
            if (auto* ti = topic_impl(req.dgram_relay_for->first)) {
                auto pit = ti->peers.find(req.dgram_relay_for->second);
                if (pit != ti->peers.end() && pit->second.dgram &&
                    pit->second.dgram->epoch == req.dgram_epoch && pit->second.dgram->relaying) {
                    pit->second.dgram->relaying = false;
                    dgram_set_path(*ti, pit->second, DatagramPath::Failed);
                }
            }
        }
        if (req.relay_for) {
            // A refused relay is a definitive answer: report the peer rather
            // than leave it dialing forever.
            if (auto* ti = topic_impl(req.relay_for->first)) {
                auto pit = ti->peers.find(req.relay_for->second);
                if (pit != ti->peers.end() && !pit->second.sess) {
                    end_attempt(pit->second);
                    set_peer_state(*ti, pit->second, PeerState::Failed);
                }
            }
        }
        if (req.loop_owned) {
            requests.erase(it);
            return;
        }
        req.done = true;
        cv.notify_all();
        return;
    }

    if (h->type != req.expect) return;

    // Loop-owned replies are applied here and forgotten.
    if (req.loop_owned) {
        if (req.keepalive_for || req.conn_keepalive) {
            if (auto ok = ctl::KeepaliveOk::decode(r)) srflx = ok->srflx;
        } else if (req.register_for) {
            if (auto ok = ctl::RegisterOk::decode(r)) {
                srflx = ok->srflx;
                if (auto* ti = topic_impl(*req.register_for)) {
                    ti->reregistering = false;
                    if (ti->published) {
                        ti->self           = ok->dev_id;
                        ti->next_keepalive = now + cfg.keepalive;
                    }
                }
            }
        } else if (req.discover_for) {
            auto ok = ctl::LookupOk::decode(r);
            auto* ti = topic_impl(*req.discover_for);
            if (ok && ti) {
                const TopicId tid = *req.discover_for;
                for (auto& e : ok->entries) {
                    if (ti->self && e.dev_id == *ti->self) continue;  // never dial ourselves
                    auto& peer  = ti->peers[e.dev_id];
                    peer.dev_id = e.dev_id;
                    peer.cands  = e.cands;
                    if (!e.stale) begin_connect(*ti, tid, e.dev_id, now);
                }
            }
        } else if (req.dgram_relay_for) {
            auto  ok = ctl::RelayAllocOk::decode(r);
            auto* ti = topic_impl(req.dgram_relay_for->first);
            if (ok && ti) {
                auto pit = ti->peers.find(req.dgram_relay_for->second);
                if (pit != ti->peers.end() && pit->second.dgram &&
                    pit->second.dgram->epoch == req.dgram_epoch) {
                    dgram_relay_granted(pit->second, ok->relay_id, ok->token, now);
                }
            }
        } else if (req.relay_for) {
            auto ok = ctl::RelayAllocOk::decode(r);
            auto* ti = topic_impl(req.relay_for->first);
            if (ok && ti) {
                auto pit = ti->peers.find(req.relay_for->second);
                if (pit != ti->peers.end() && pit->second.attempt && !pit->second.sess &&
                    !pit->second.relay_joining) {
                    pit->second.relay_joining = true;
                    join_relay(req.relay_for->first, pit->second.dev_id, *pit->second.attempt,
                               ok->relay_id, ok->token, now);
                }
            }
        }
        requests.erase(it);
        return;
    }

    req.reply.assign(msg.begin(), msg.end());
    req.done = true;
    cv.notify_all();
}

// ---------------------------------------------------------------------------
// Introductions and relays
// ---------------------------------------------------------------------------
void Node::Impl::on_relayed(const wire::Relayed& rel, Instant now) {
    TopicId                topic{};
    AttemptNonce           attempt{};
    std::vector<Candidate> cands;
    if (!decode_intro(rel.payload, topic, attempt, cands)) return;
    auto* ti = topic_impl(topic);
    if (!ti || !ti->self) return;
    if (cfg.verbose) {
        std::fprintf(stderr, "[uconnect] introduced to %s (%zu candidates)\n",
                     to_hex(rel.from_dev).substr(0, 8).c_str(), cands.size());
    }

    auto existing = ti->peers.find(rel.from_dev);
    if (!can_admit(*ti, existing == ti->peers.end() ? nullptr : &existing->second)) return;
    auto& peer  = ti->peers[rel.from_dev];
    peer.dev_id = rel.from_dev;
    peer.cands  = cands;

    // A live session is never given up for an introduction: the claim that it
    // is the same peer proves nothing, and a working connection is worth more
    // than a new one. A session gone quiet -- the peer restarted -- may be.
    if (peer.sess) {
        const bool live = peer.sess->state() == TcpSession::State::Established &&
                          now - peer.sess->last_received() < kLiveSession;
        if (live || peer.sess->state() == TcpSession::State::Handshaking) return;
    }

    // Both sides may have introduced themselves at once, each with its own
    // nonce. They must end on one: the smaller dev_id's wins.
    if (peer.attempt && smaller(*ti->self, peer.dev_id)) return;  // keep ours
    adopt_attempt(*ti, topic, peer, attempt, now);
}

void Node::Impl::adopt_attempt(Topic::Impl& ti, const TopicId& tid, Peer& peer,
                               const AttemptNonce& attempt, Instant now) {
    if (peer.attempt) attempts.erase(*peer.attempt);
    peer.attempt         = attempt;
    peer.attempt_started = now;
    peer.punch_deadline  = cfg.force_relay ? now : now + cfg.punch_timeout;
    peer.relay_asked     = false;
    peer.relay_joining   = false;
    peer.relay_backup_at = Instant{};
    attempts[attempt]    = {tid, peer.dev_id};
    set_peer_state(ti, peer, PeerState::Probing);
    if (!cfg.force_relay) dial_all(tid, peer, now);
}

void Node::Impl::begin_connect(Topic::Impl& ti, const TopicId& tid, const DevId& dev,
                               Instant now) {
    if (!ti.self || ctl_state != Ctl::Up) return;
    auto it = ti.peers.find(dev);
    if (it == ti.peers.end() || it->second.cands.empty()) return;
    Peer& peer = it->second;
    if (peer.sess || peer.attempt) return;
    if (!can_admit(ti, &peer)) return;

    AttemptNonce attempt{};
    crypto::random_bytes(attempt);
    if (cfg.verbose) {
        std::fprintf(stderr, "[uconnect] connect %s\n", to_hex(dev).substr(0, 8).c_str());
    }

    ctl::Connect c;
    c.from_dev = *ti.self;
    c.to_dev   = dev;
    c.payload  = encode_intro(tid, attempt, my_candidates());
    notify(wire::MsgType::Connect, c);
    adopt_attempt(ti, tid, peer, attempt, now);
}

void Node::Impl::dial_all(const TopicId& tid, Peer& peer, Instant now) {
    for (const auto& c : peer.cands) {
        // A peer's loopback host address is never ours to reach; a loopback
        // srflx means we share a machine, which is exactly local testing.
        if (c.kind == Candidate::Kind::Host && c.ep.ip.is_loopback()) continue;
        if (c.ep.port == 0) continue;
        auto pc     = std::make_unique<PendingConn>();
        pc->kind    = PendingConn::Kind::Dial;
        pc->started = now;
        pc->known   = true;
        pc->topic   = tid;
        pc->peer    = peer.dev_id;
        pc->attempt = *peer.attempt;
        pc->target  = c.ep;
        if (!pc->sock.open(port) || !pc->sock.connect(c.ep)) continue;
        pending.push_back(std::move(pc));
    }
    peer.next_redial = now + kRedial;
}

void Node::Impl::request_relay(Topic::Impl& ti, const TopicId& tid, Peer& peer) {
    if (peer.relay_asked || !ti.self || ctl_state != Ctl::Up) return;
    peer.relay_asked = true;
    Request r;
    r.relay_for  = std::make_pair(tid, peer.dev_id);
    r.loop_owned = true;
    request(wire::MsgType::RelayAlloc, wire::MsgType::RelayAllocOk,
            ctl::RelayAlloc{*ti.self, peer.dev_id, ctl::RelayKind::Tcp}, r);
}

void Node::Impl::on_relay_offer(const ctl::RelayOffer& off, Instant now) {
    auto* ti = topic_impl(off.topic);
    if (!ti) return;
    auto pit = ti->peers.find(off.from_dev);
    if (pit == ti->peers.end()) return;
    Peer& peer = pit->second;
    if (off.kind == ctl::RelayKind::Udp) {
        // The peer is relaying its datagrams: bind our side, or they have
        // nowhere to go.
        if (peer.dgram) dgram_relay_granted(peer, off.relay_id, off.token, now);
        return;
    }
    if (peer.sess || !peer.attempt || peer.relay_joining) return;
    peer.relay_joining = true;
    join_relay(off.topic, peer.dev_id, *peer.attempt, off.relay_id, off.token, now);
}

void Node::Impl::join_relay(const TopicId& tid, const DevId& dev, const AttemptNonce& attempt,
                            wire::RelayId relay_id, const ctl::RelayToken& token, Instant now) {
    auto pc      = std::make_unique<PendingConn>();
    pc->kind     = PendingConn::Kind::RelayLeg;
    pc->started  = now;
    pc->known    = true;
    pc->topic    = tid;
    pc->peer     = dev;
    pc->attempt  = attempt;
    pc->relay_id = relay_id;
    pc->token    = token;
    // An ephemeral port: this leg goes to the server, not through a NAT hole.
    if (!pc->sock.open(0) || !pc->sock.connect(server)) return;
    auto join = ctl::frame(ctl::message(wire::MsgType::RelayJoin, 0, ctl::RelayJoin{relay_id, token}));
    pc->out.insert(pc->out.end(), join.begin(), join.end());
    if (cfg.verbose) std::fprintf(stderr, "[uconnect] joining relay for %s\n", to_hex(dev).substr(0, 8).c_str());
    pending.push_back(std::move(pc));
}

// ---------------------------------------------------------------------------
// Connections that no session owns yet
// ---------------------------------------------------------------------------
void Node::Impl::drive_pending(PendingConn& pc, Instant now) {
    // A dial or relay leg that has not connected yet.
    const auto st = pc.sock.state();
    if (st == io::TcpSocket::State::Failed) {
        pc.dead = true;
        return;
    }
    if (st == io::TcpSocket::State::Connecting) return;

    // Stale: the attempt it belonged to is over, or it never said who it is.
    if (pc.known && !attempts.count(pc.attempt)) {
        pc.dead = true;
        return;
    }
    if (pc.kind == PendingConn::Kind::Inbound && !pc.known && now - pc.started > kInboundIdentify) {
        pc.dead = true;
        return;
    }

    // Read what has arrived.
    std::vector<uint8_t> buf(4096);
    for (int i = 0; i < 8; ++i) {
        auto got = pc.sock.recv(buf);
        if (!got) {
            pc.dead = true;
            return;
        }
        if (*got == 0) break;
        if (pc.kind == PendingConn::Kind::RelayLeg && !pc.joined) {
            if (!pc.reader.feed(std::span(buf).first(*got))) {
                pc.dead = true;
                return;
            }
        } else {
            pc.in.insert(pc.in.end(), buf.begin(), buf.begin() + static_cast<ptrdiff_t>(*got));
        }
    }

    if (pc.kind == PendingConn::Kind::RelayLeg && !pc.joined) {
        if (auto m = pc.reader.next()) {
            if (wire::peek_type(*m) != wire::MsgType::RelayJoinOk) {
                pc.dead = true;
                return;
            }
            pc.joined = true;
            pc.in     = pc.reader.take_rest();
        }
    }

    // Write what is queued: a RelayJoin, or a hello.
    while (!pc.out.empty()) {
        auto n = pc.sock.send(pc.out);
        if (!n) {
            pc.dead = true;
            return;
        }
        if (*n == 0) break;
        pc.out.erase(pc.out.begin(), pc.out.begin() + static_cast<ptrdiff_t>(*n));
    }
    if (pc.kind == PendingConn::Kind::RelayLeg && !pc.joined) return;

    // Identify an inbound connection from what it says.
    if (!pc.known) {
        auto a = TcpSession::peek_hello(pc.in);
        if (!a) a = TcpSession::peek_attempt(pc.in);
        if (!a) {
            // A hello or first frame that does not parse will not start to.
            if (pc.in.size() >= 2 + session::kAttemptLen) pc.dead = true;
            return;
        }
        auto at = attempts.find(*a);
        if (at == attempts.end()) {
            // The introduction may still be on its way: a peer close by can
            // dial us faster than the server, further off, can tell us it
            // will. Hold on briefly before deciding it names nothing of ours.
            if (now - pc.started < kIntroWait) return;
            pc.dead = true;  // no introduction of ours names it
            if (cfg.verbose) std::fprintf(stderr, "[uconnect] dropped a connection naming no attempt of ours\n");
            return;
        }
        pc.known   = true;
        pc.attempt = *a;
        pc.topic   = at->second.first;
        pc.peer    = at->second.second;
    }

    auto* ti = topic_impl(pc.topic);
    if (!ti || !ti->self) {
        pc.dead = true;
        return;
    }
    auto pit = ti->peers.find(pc.peer);
    if (pit == ti->peers.end()) {
        pc.dead = true;
        return;
    }
    Peer& peer = pit->second;
    // Another connection already carries this peer's session.
    if (peer.sess) {
        pc.dead = true;
        return;
    }

    const bool initiator = smaller(*ti->self, peer.dev_id);
    if (initiator) {
        // We speak first, on the first connection to come up. The session
        // itself skips the responder's hello, whenever that arrives.
        start_session(pc, now);
        return;
    }

    // Responder: a connection we dialed opens with a hello, so an initiator
    // that accepted it knows who is calling; then wait for message 1.
    if (pc.kind == PendingConn::Kind::Dial && !pc.greeted) {
        auto h = TcpSession::hello(pc.attempt);
        pc.out.insert(pc.out.end(), h.begin(), h.end());
        pc.greeted = true;
        drive_pending(pc, now);  // flush it now
        return;
    }
    // On every kind of connection, relay legs included, the responder waits
    // for the initiator to speak: that way both ends are on the same one.
    if (TcpSession::peek_attempt(pc.in)) start_session(pc, now);
}

void Node::Impl::start_session(PendingConn& pc, Instant now) {
    auto* ti = topic_impl(pc.topic);
    if (!ti) return;
    Peer& peer = ti->peers[pc.peer];

    const bool initiator = smaller(*ti->self, peer.dev_id);
    peer.sess = initiator
                    ? TcpSession::initiate(session_cfg(), pc.topic, 0, ti->psk(), *ti->self,
                                           peer.dev_id, pc.attempt, now)
                    : TcpSession::respond(session_cfg(), pc.topic, 0, ti->psk(), *ti->self,
                                          peer.dev_id, pc.attempt, now);
    peer.sock    = std::move(pc.sock);
    peer.relayed = pc.kind == PendingConn::Kind::RelayLeg;
    peer.out.clear();
    peer.closing = false;
    peer.link    = LinkInfo{};
    // A datagram channel is keyed from the session it runs beside; a new
    // session starts the epochs again under keys of its own.
    if (peer.dgram) dgram_drop(*ti, peer);
    peer.dgram_epoch = 0;
    pc.dead      = true;
    set_peer_state(*ti, peer, PeerState::Handshaking);
    if (!pc.in.empty()) peer.sess->on_bytes(pc.in, now);
    drive_peer(*ti, pc.topic, peer, now);
}

// ---------------------------------------------------------------------------
// Peers
// ---------------------------------------------------------------------------
void Node::Impl::end_attempt(Peer& peer) {
    if (peer.attempt) attempts.erase(*peer.attempt);
    peer.attempt       = std::nullopt;
    peer.relay_asked   = false;
    peer.relay_joining = false;
}

void Node::Impl::drive_peer(Topic::Impl& ti, const TopicId& tid, Peer& peer, Instant now) {
    // A failed handshake's fresh introduction, once its delay is up.
    if (!peer.sess && !peer.attempt && peer.retry_at != Instant{} && now >= peer.retry_at) {
        peer.retry_at = Instant{};
        begin_connect(ti, tid, peer.dev_id, now);
        if (!peer.attempt) set_peer_state(ti, peer, PeerState::Failed);  // could not even ask
    }

    // Dialing: keep punching until the deadline, then fall back to a relay.
    if (peer.attempt && !peer.sess) {
        const bool designated = ti.self && smaller(*ti.self, peer.dev_id);
        if (now < peer.punch_deadline) {
            if (now >= peer.next_redial) dial_all(tid, peer, now);
        } else if (designated) {
            request_relay(ti, tid, peer);
        } else if (!peer.relay_asked) {
            // The designated side asks first; if its offer has not come,
            // ask too -- the server hands both the same binding.
            if (peer.relay_backup_at == Instant{}) peer.relay_backup_at = peer.punch_deadline + kRelayBackupDelay;
            if (now >= peer.relay_backup_at) request_relay(ti, tid, peer);
        }
        if (now >= peer.punch_deadline + kRelayWindow) {
            end_attempt(peer);
            set_peer_state(ti, peer, PeerState::Failed);
        }
        return;
    }
    if (!peer.sess) return;

    // Read.
    std::vector<uint8_t> buf(64 * 1024);
    for (int i = 0; i < 16 && peer.sess->state() != TcpSession::State::Closed; ++i) {
        auto got = peer.sock.recv(buf);
        if (!got) {
            peer.sess->on_eof(now);
            break;
        }
        if (*got == 0) break;
        peer.sess->on_bytes(std::span(buf).first(*got), now);
    }
    peer.sess->on_timeout(now);

    while (auto e = peer.sess->poll_event()) {
        switch (e->kind) {
            case session::TcpEvent::Kind::Established:
                end_attempt(peer);
                peer.retries  = 0;
                peer.retry_at = Instant{};
                if (cfg.verbose) {
                    std::fprintf(stderr, "[uconnect] connected %s (%s)\n",
                                 to_hex(peer.dev_id).substr(0, 8).c_str(),
                                 peer.relayed ? "relayed" : "direct");
                }
                set_peer_state(ti, peer, PeerState::Connected);
                break;
            case session::TcpEvent::Kind::Record:
                if (e->record_kind == kMessageRecord) {
                    ++peer.link.messages_received;
                    peer.link.bytes_received += e->body.size();
                    if (ti.on_data) {
                        deferred.push_back([cb = ti.on_data, dev = peer.dev_id,
                                            body = std::move(e->body)] { cb(dev, body); });
                    }
                } else if (e->record_kind == kDgramOffer) {
                    dgram_on_offer(ti, peer, e->body, now);
                } else if (e->record_kind == kDgramOverTcp) {
                    // Accepted whatever our own path is: which way the peer
                    // sends is its fallback, not ours.
                    if (e->body.size() <= Topic::max_datagram()) {
                        ++peer.link.datagrams_received;
                        if (ti.on_datagram) {
                            deferred.push_back([cb = ti.on_datagram, dev = peer.dev_id,
                                                body = std::move(e->body)] { cb(dev, body); });
                        }
                    }
                } else if (e->record_kind == kDgramClose) {
                    auto epoch = decode_u32(e->body);
                    if (epoch && peer.dgram && peer.dgram->epoch == *epoch) dgram_drop(ti, peer);
                }
                break;
            case session::TcpEvent::Kind::Closed: {
                const bool was_up = peer.state == PeerState::Connected;
                const PeerGone why = peer_gone_from(e->cause, e->peer_reason);
                if (cfg.verbose) {
                    std::fprintf(stderr, "[uconnect] session closed %s: %s\n",
                                 to_hex(peer.dev_id).substr(0, 8).c_str(), to_string(why));
                }
                peer.closing = true;  // flush a Close record, if one was queued
                if (peer.dgram) dgram_drop(ti, peer);  // its keys went with the session
                if (was_up && ti.on_peer_closed) {
                    deferred.push_back([cb = ti.on_peer_closed, dev = peer.dev_id, why] { cb(dev, why); });
                }
                // A handshake that failed while the attempt still has time left
                // goes back to dialing; anything else is over.
                // A connection that simply went away mid-handshake -- the
                // peer dropped it, perhaps before its introduction arrived --
                // is dialed again under the same attempt.
                //
                // A handshake that FAILED goes round again with a NEW
                // introduction instead. Redialing under the old nonce can never
                // work if the peer completed its side and spent it -- which is
                // how a handshake fails on one end only.
                const bool gone = e->cause == session::CloseCause::TimedOut;
                if (!was_up && peer.attempt && gone && now < peer.punch_deadline + kRelayWindow) {
                    set_peer_state(ti, peer, PeerState::Probing);
                    break;
                }
                const bool retry = !was_up && peer.attempt && peer.retries < kMaxHandshakeRetries;
                end_attempt(peer);
                if (retry) {
                    ++peer.retries;
                    peer.retry_at = now + kHandshakeRetry;
                    set_peer_state(ti, peer, PeerState::Probing);
                } else {
                    set_peer_state(ti, peer, was_up ? PeerState::Closed : PeerState::Failed);
                }
                break;
            }
        }
    }

    auto bytes = peer.sess->take_output();
    peer.out.insert(peer.out.end(), bytes.begin(), bytes.end());
    flush_peer(peer);

    if (peer.sess->state() == TcpSession::State::Closed && (peer.out.empty() || !peer.sock.is_open())) {
        peer.sock.close();
        peer.sess.reset();
        peer.out.clear();
        peer.closing = false;
    }
}

void Node::Impl::flush_peer(Peer& peer) {
    while (!peer.out.empty() && peer.sock.is_open()) {
        auto n = peer.sock.send(peer.out);
        if (!n) {
            peer.sock.close();
            if (peer.sess) peer.sess->on_eof(now());
            return;
        }
        if (*n == 0) return;
        peer.out.erase(peer.out.begin(), peer.out.begin() + static_cast<ptrdiff_t>(*n));
    }
}

void Node::Impl::set_peer_state(Topic::Impl& ti, Peer& peer, PeerState s) {
    if (peer.state == s) return;
    peer.state = s;
    // Deferred: the natural thing to do from on_peer is call back into the
    // library, which would deadlock on the non-recursive mutex held here.
    if (ti.on_peer) {
        deferred.push_back([cb = ti.on_peer, dev = peer.dev_id, s] { cb(dev, s); });
    }
}

size_t Node::Impl::live_peer_count(const Topic::Impl& ti) const {
    size_t n = 0;
    for (const auto& [dev, peer] : ti.peers) {
        (void)dev;
        if (peer.sess || peer.attempt) ++n;
    }
    return n;
}

size_t Node::Impl::total_peer_count() const {
    size_t n = 0;
    for (const auto& [id, t] : topics) {
        (void)id;
        n += live_peer_count(*t->impl_);
    }
    return n;
}

bool Node::Impl::can_admit(const Topic::Impl& ti, const Peer* peer) const {
    // Glare resolution and replacing an existing attempt use its occupied
    // slot. New introductions must pass the same caps as outgoing connects,
    // before allocating peer state, sockets, or handshake work.
    if (peer && (peer->sess || peer->attempt)) return true;
    return live_peer_count(ti) < ti.max_peers && total_peer_count() < cfg.max_total_peers;
}

bool Node::Impl::send_record(Peer& peer, uint8_t kind, std::span<const uint8_t> body) {
    if (kind == kMessageRecord || kind == kDgramOverTcp) {
        // Both application APIs consume the same queue, including the length,
        // kind and AEAD tag. Check before sealing so rejection spends no nonce.
        // Small protocol notices (offers and close) can still be sent at capacity.
        constexpr size_t overhead = 4 + 1 + crypto::kTagLen;
        if (body.size() > kMaxQueued - overhead ||
            peer.out.size() > kMaxQueued - overhead - body.size()) return false;
    }
    if (!peer.sess || !peer.sess->send(kind, body, now())) return false;
    auto bytes = peer.sess->take_output();
    peer.out.insert(peer.out.end(), bytes.begin(), bytes.end());
    flush_peer(peer);
    return true;
}

// ---------------------------------------------------------------------------
// Datagram channels
// ---------------------------------------------------------------------------
bool Node::Impl::ensure_udp() {
    if (udp_ready) return true;
    if (udp_tried) return false;
    udp_tried = true;
    // The TCP port's number when it is free, so both channels share one
    // number in firewall rules and logs; any port otherwise.
    udp_ready = udp.open(port) || udp.open(0);
    if (!udp_ready && cfg.verbose) {
        std::fprintf(stderr, "[uconnect] no UDP socket: %s\n", udp.last_error().c_str());
    }
    return udp_ready;
}

std::vector<Candidate> Node::Impl::udp_candidates() const {
    std::vector<Candidate> c;
    if (udp_srflx) c.push_back(Candidate{Candidate::Kind::Srflx, *udp_srflx});
    for (const auto& h : host_cands) {
        if (c.size() >= wire::kMaxCandidates) break;
        c.push_back(Candidate{Candidate::Kind::Host, Endpoint{h.ep.ip, udp.local_port()}});
    }
    return c;
}

void Node::Impl::read_udp(Instant now) {
    if (!udp_ready) return;
    std::vector<uint8_t> buf(2048);
    for (int i = 0; i < 256; ++i) {
        auto got = udp.recv_from(buf);
        if (!got) break;
        on_udp(got->from, std::span(buf).first(got->len), now);
    }
}

void Node::Impl::on_udp(const Endpoint& from, std::span<const uint8_t> dgram, Instant now) {
    if (dgram.size() < 2) return;
    // The server speaks the control protocol's version; peers speak v1. Only
    // the server's own address is heard in v2.
    if (dgram[1] == ctl::kVersion) {
        if (from == server) on_udp_from_server(dgram, now);
        return;
    }

    auto type = wire::peek_type(dgram);
    if (!type) return;

    // Each channel below is only ever looked at through its own keys.
    auto each_channel = [&](auto&& fn) {
        for (auto& [tid, t] : topics) {
            (void)tid;
            for (auto& [dev, peer] : t->impl_->peers) {
                (void)dev;
                if (peer.dgram && fn(*t->impl_, peer, *peer.dgram)) return;
            }
        }
    };

    switch (*type) {
        case wire::MsgType::Probe:
            // Answered once, by the channel whose probe key made the tag:
            // nobody else can elicit a reply at all.
            each_channel([&](Topic::Impl&, Peer&, Dgram& d) {
                auto reply = path::PunchSession::answer_probe(from, dgram, &d.probe_key, 0);
                if (!reply) return false;
                udp.send_to(reply->to, reply->data);
                if (d.punch) d.punch->on_peer_probe(from, now);
                return true;
            });
            return;
        case wire::MsgType::ProbeOk:
            each_channel([&](Topic::Impl&, Peer&, Dgram& d) {
                if (d.punch) d.punch->on_datagram(from, dgram, now);
                return false;  // each checks the txn against its own
            });
            return;
        case wire::MsgType::Transport:
        case wire::MsgType::Close: {
            if (dgram.size() < wire::Header::kSize + 4) return;
            const auto cid = *decode_u32(dgram.subspan(wire::Header::kSize, 4));
            each_channel([&](Topic::Impl&, Peer&, Dgram& d) {
                if (!d.sess || d.conn_id != cid) return false;
                d.sess->on_datagram(from, dgram, now);
                return true;
            });
            return;
        }
        default:
            return;
    }
}

void Node::Impl::on_udp_from_server(std::span<const uint8_t> dgram, Instant now) {
    wire::Reader r{dgram};
    auto         h = wire::Header::decode(r, ctl::kVersion);
    if (!h) return;

    auto by_relay = [&](wire::RelayId id, auto&& fn) {
        for (auto& [tid, t] : topics) {
            (void)tid;
            for (auto& [dev, peer] : t->impl_->peers) {
                (void)dev;
                if (peer.dgram && peer.dgram->relay_id == id) {
                    fn(*t->impl_, peer, *peer.dgram);
                    return;
                }
            }
        }
    };

    switch (h->type) {
        case wire::MsgType::WhoAmIOk: {
            auto ok = ctl::WhoAmIOk::decode(r);
            if (ok && ok->nonce == whoami_nonce && whoami_nonce != 0) udp_srflx = ok->mapped;
            return;
        }
        case wire::MsgType::UdpRelayBindOk: {
            auto ok = ctl::UdpRelayBindOk::decode(r);
            if (!ok) return;
            by_relay(ok->relay_id, [&](Topic::Impl& ti, Peer& peer, Dgram& d) {
                d.relay_bound = true;
                if (d.relaying && d.sess) {
                    d.relaying = false;
                    d.sess->set_path(server, now);
                    dgram_set_path(ti, peer, DatagramPath::Relayed);
                }
            });
            return;
        }
        case wire::MsgType::RelayData: {
            auto rd = wire::RelayData::decode(r);
            if (!rd) return;
            // The payload is the peer's sealed packet; its keys decide whether
            // it is genuine, not the wrapper.
            by_relay(rd->relay_id, [&](Topic::Impl&, Peer&, Dgram& d) {
                if (d.sess) d.sess->on_datagram(server, rd->payload, now);
            });
            return;
        }
        default:
            return;
    }
}

// Record the channel's path and tell the application. With no channel -- it
// was just dropped -- only the telling is left to do.
void Node::Impl::dgram_set_path(Topic::Impl& ti, Peer& peer, DatagramPath p) {
    if (peer.dgram) {
        if (peer.dgram->path == p) return;
        peer.dgram->path = p;
    }
    if (cfg.verbose) {
        std::fprintf(stderr, "[uconnect] datagrams %s: %s\n",
                     to_hex(peer.dev_id).substr(0, 8).c_str(), to_string(p));
    }
    if (ti.on_datagram_path) {
        deferred.push_back([cb = ti.on_datagram_path, dev = peer.dev_id, p] { cb(dev, p); });
    }
}

bool Node::Impl::dgram_open(Topic::Impl& ti, Peer& peer, uint32_t epoch, DatagramFallback fb,
                            Instant now) {
    auto keys = peer.sess->datagram_keys(epoch);
    if (!keys) return false;
    Dgram d;
    d.epoch    = epoch;
    d.fallback = fb;
    d.probe_key = keys->probe;
    d.conn_id   = keys->conn_id;
    d.opened   = now;
    session::SessionConfig scfg;
    scfg.rekey_shift = cfg.rekey_shift;
    d.sess.emplace(scfg, peer.dev_id, Endpoint{}, keys->send, keys->recv, keys->conn_id, now);
    d.path           = DatagramPath::None;  // so the move to Opening is reported
    peer.dgram       = std::move(d);
    peer.dgram_epoch = std::max(peer.dgram_epoch, epoch);
    ensure_udp();
    dgram_set_path(ti, peer, DatagramPath::Opening);
    return true;
}

void Node::Impl::dgram_on_offer(Topic::Impl& ti, Peer& peer, std::span<const uint8_t> body,
                                Instant now) {
    uint32_t               epoch = 0;
    std::vector<Candidate> cands;
    if (!decode_dgram_offer(body, epoch, cands)) return;

    if (peer.dgram && epoch < peer.dgram->epoch) return;  // an older channel's, overtaken
    if (!peer.dgram || epoch > peer.dgram->epoch) {
        // A channel we have not used yet -- never one at or below an epoch we
        // already keyed, or our counter would start again under used keys.
        if (epoch <= peer.dgram_epoch) return;
        const auto fb = peer.dgram ? peer.dgram->fallback : cfg.datagram_fallback;
        if (!dgram_open(ti, peer, epoch, fb, now)) return;
    }
    peer.dgram->remote = std::move(cands);
}

void Node::Impl::dgram_drop(Topic::Impl& ti, Peer& peer) {
    if (!peer.dgram) return;
    peer.dgram.reset();
    dgram_set_path(ti, peer, DatagramPath::None);
}

void Node::Impl::dgram_fall_back(Topic::Impl& ti, Peer& peer, Instant now) {
    Dgram& d = *peer.dgram;
    d.punch.reset();
    switch (d.fallback) {
        case DatagramFallback::Tcp:
            dgram_set_path(ti, peer, DatagramPath::Tcp);
            return;
        case DatagramFallback::None:
            dgram_set_path(ti, peer, DatagramPath::Failed);
            return;
        case DatagramFallback::Relay:
            d.relaying = true;
            d.relay_deadline  = now + kUdpRelayWait;
            d.relay_backup_at = now + kRelayBackupDelay;
            // Already bound for the peer's sake: nothing to wait for.
            if (d.relay_bound && d.sess) {
                d.relaying = false;
                d.sess->set_path(server, now);
                dgram_set_path(ti, peer, DatagramPath::Relayed);
            }
            return;
    }
}

void Node::Impl::dgram_relay_granted(Peer& peer, wire::RelayId id, const ctl::RelayToken& token,
                                     Instant now) {
    Dgram& d = *peer.dgram;
    if (d.relay_id == id) return;
    d.relay_id    = id;
    d.relay_token = token;
    d.relay_bound = false;
    d.next_bind   = now;
}

void Node::Impl::flush_dgram(Peer& peer) {
    Dgram& d = *peer.dgram;
    if (!d.sess || !udp_ready) return;
    while (auto o = d.sess->poll_transmit()) {
        if (o->to.port == 0) continue;  // no path yet
        if (o->to == server) {
            if (!d.relay_id) continue;
            wire::RelayData rd;
            rd.relay_id = *d.relay_id;
            rd.payload  = std::move(o->data);
            udp.send_to(server, ctl::message(wire::MsgType::RelayData, 0, rd));
        } else {
            udp.send_to(o->to, o->data);
        }
    }
}

void Node::Impl::drive_dgram(Topic::Impl& ti, const TopicId& tid, Peer& peer, Instant now) {
    if (!peer.sess || peer.sess->state() != TcpSession::State::Established) return;
    Dgram& d = *peer.dgram;

    // Our offer: once we know our UDP mapping, or have waited long enough.
    if (!d.offered && (udp_srflx || !udp_ready || now - d.opened >= kGatherWait)) {
        send_record(peer, kDgramOffer, encode_dgram_offer(d.epoch, udp_ready ? udp_candidates()
                                                                             : std::vector<Candidate>{}));
        d.offered = true;
    }

    // Both offers exchanged: punch, unless there is nothing to punch with.
    if (d.path == DatagramPath::Opening && !d.relaying && d.offered && d.remote && !d.punch) {
        if (cfg.force_relay || !udp_ready || d.remote->empty()) {
            dgram_fall_back(ti, peer, now);
        } else {
            path::PunchConfig pc;
            pc.total_timeout = cfg.punch_timeout;
            d.punch.emplace(pc, peer.dev_id, *d.remote, path::LocalView{udp_srflx}, &d.probe_key);
            d.punch->begin(now);
        }
    }

    if (d.punch) {
        d.punch->on_timeout(now);
        while (auto o = d.punch->poll_transmit()) udp.send_to(o->to, o->data);
        while (auto e = d.punch->poll_event()) {
            if (e->kind == path::PunchEvent::Kind::Nominated && d.path == DatagramPath::Opening) {
                d.direct = e->path;
                d.sess->set_path(e->path, now);
                dgram_set_path(ti, peer, DatagramPath::Direct);
            } else if (e->kind == path::PunchEvent::Kind::Failed &&
                       d.path == DatagramPath::Opening) {
                dgram_fall_back(ti, peer, now);
                break;  // the punch session is gone
            }
        }
        if (d.punch && d.punch->state() != path::PunchState::Probing && !d.punch->next_timeout()) {
            d.punch.reset();
        }
    }

    // The UDP relay: the smaller dev_id asks first; the other asks too if no
    // offer has come -- the server hands both the same binding.
    if (d.relaying) {
        const bool designated = ti.self && smaller(*ti.self, peer.dev_id);
        if (!d.relay_asked && !d.relay_id && ctl_state == Ctl::Up && ti.self &&
            (designated || now >= d.relay_backup_at)) {
            d.relay_asked = true;
            Request r;
            r.dgram_relay_for = std::make_pair(tid, peer.dev_id);
            r.dgram_epoch     = d.epoch;
            r.loop_owned      = true;
            request(wire::MsgType::RelayAlloc, wire::MsgType::RelayAllocOk,
                    ctl::RelayAlloc{*ti.self, peer.dev_id, ctl::RelayKind::Udp}, r);
        }
        if (now >= d.relay_deadline) {
            d.relaying = false;
            dgram_set_path(ti, peer, DatagramPath::Failed);
        }
    }
    if (d.relay_id && !d.relay_bound && now >= d.next_bind && udp_ready) {
        udp.send_to(server, ctl::message(wire::MsgType::UdpRelayBind, 0,
                                         ctl::UdpRelayBind{*d.relay_id, d.relay_token}));
        d.next_bind = now + kUdpBindEvery;
    }

    // The channel itself.
    if (!d.sess) return;
    if (d.path == DatagramPath::Direct || d.path == DatagramPath::Relayed) d.sess->on_timeout(now);
    while (auto e = d.sess->poll_event()) {
        switch (e->kind) {
            case session::SessionEvent::Kind::Data:
                ++peer.link.datagrams_received;
                if (ti.on_datagram) {
                    deferred.push_back([cb = ti.on_datagram, dev = peer.dev_id,
                                        body = std::move(e->data)] { cb(dev, body); });
                }
                break;
            case session::SessionEvent::Kind::PathChanged:
                // The peer reached us over a path of its own finding. A direct
                // one -- a punch that came through late -- is an upgrade
                // whatever we chose. The relay is not: it spends the server's
                // budget, so we use it only if our own fallback says so, and
                // otherwise keep sending the way we were.
                if (!(e->path == server)) {
                    d.direct = e->path;
                    d.punch.reset();
                    d.relaying = false;
                    dgram_set_path(ti, peer, DatagramPath::Direct);
                } else if (d.fallback == DatagramFallback::Relay) {
                    d.punch.reset();
                    d.relaying = false;
                    dgram_set_path(ti, peer, DatagramPath::Relayed);
                } else if (d.direct) {
                    d.sess->set_path(*d.direct, now);
                }
                break;
            case session::SessionEvent::Kind::Closed:
                // The path went quiet for the whole idle timeout. The keys are
                // gone with it; what is left is the fallback over TCP, if any.
                dgram_set_path(ti, peer, d.fallback == DatagramFallback::Tcp ? DatagramPath::Tcp
                                                                            : DatagramPath::Failed);
                break;
        }
    }
    flush_dgram(peer);
}

// ---------------------------------------------------------------------------
// Topic public API
// ---------------------------------------------------------------------------
Topic::Topic(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
Topic::~Topic() = default;

const TopicId& Topic::id() const { return impl_->creds.id; }
bool           Topic::is_authenticated() const { return impl_->keyed; }

bool Topic::publish(std::span<const uint8_t> meta, bool unlisted) {
    auto&                        n = *impl_->node;
    std::unique_lock<std::mutex> lk(n.mu);
    if (n.on_loop_thread()) return false;
    impl_->meta.assign(meta.begin(), meta.end());
    impl_->unlisted = unlisted;

    ctl::Register m;
    m.id         = impl_->creds.id;
    m.mode       = impl_->keyed ? TopicMode::Keyed : TopicMode::Open;
    m.unlisted   = unlisted;
    m.host_cands = n.host_cands;
    m.meta       = impl_->meta;
    const uint32_t txn = n.request(wire::MsgType::Register, wire::MsgType::RegisterOk, m, {},
                                   unlisted ? wire::flags::kUnlisted : uint8_t{0});

    // Waits out the control connection coming up, too.
    const bool finished = n.wait_for(lk, txn, std::chrono::steady_clock::now() + 5s);
    auto       it       = n.requests.find(txn);
    std::optional<ctl::RegisterOk> ok;
    if (finished && it != n.requests.end() && it->second.error == ErrorCode::None) {
        wire::Reader r{it->second.reply};
        if (wire::Header::decode(r, ctl::kVersion)) ok = ctl::RegisterOk::decode(r);
    }
    if (it != n.requests.end()) n.requests.erase(it);
    if (!ok) return false;

    impl_->self           = ok->dev_id;
    impl_->published      = true;
    impl_->reregistering  = false;
    impl_->next_keepalive = std::chrono::steady_clock::now() + n.cfg.keepalive;
    n.srflx               = ok->srflx;
    return true;
}

void Topic::unpublish() {
    auto&                       n = *impl_->node;
    std::lock_guard<std::mutex> lk(n.mu);
    if (impl_->self && n.ctl_state == Node::Impl::Ctl::Up) {
        n.notify(wire::MsgType::Unregister, ctl::DevRef{*impl_->self});
    }
    impl_->published = false;
    impl_->self.reset();
}

std::optional<DevId> Topic::self() const {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    return impl_->self;
}

std::vector<PeerInfo> Topic::peers(uint8_t max, bool want_meta, std::chrono::milliseconds timeout) {
    auto&                        n = *impl_->node;
    std::unique_lock<std::mutex> lk(n.mu);
    if (n.on_loop_thread()) return {};
    ctl::Lookup                  l;
    l.id        = impl_->creds.id;
    l.max       = max;
    l.want_meta = want_meta;
    const uint32_t txn = n.request(wire::MsgType::Lookup, wire::MsgType::LookupOk, l, {},
                                   want_meta ? wire::flags::kWantMeta : uint8_t{0});
    n.wait_for(lk, txn, std::chrono::steady_clock::now() + timeout);

    std::vector<PeerInfo> out;
    auto                  it = n.requests.find(txn);
    if (it == n.requests.end()) return out;
    if (it->second.done && it->second.error == ErrorCode::None) {
        wire::Reader r{it->second.reply};
        std::optional<ctl::LookupOk> ok;
        if (wire::Header::decode(r, ctl::kVersion)) ok = ctl::LookupOk::decode(r);
        if (ok) {
            for (auto& e : ok->entries) {
                // Never return ourselves: our own record is in the topic too.
                if (impl_->self && e.dev_id == *impl_->self) continue;
                auto& peer  = impl_->peers[e.dev_id];  // remember where to dial
                peer.dev_id = e.dev_id;
                peer.cands  = e.cands;
                out.push_back(PeerInfo{e.dev_id, std::chrono::seconds(e.age_secs), e.stale, e.meta});
            }
        }
    }
    n.requests.erase(it);
    return out;
}

std::optional<PeerInfo> Topic::resolve(const DevId& dev, std::chrono::milliseconds timeout) {
    auto&                        n = *impl_->node;
    std::unique_lock<std::mutex> lk(n.mu);
    if (n.on_loop_thread()) return std::nullopt;
    const uint32_t txn = n.request(wire::MsgType::Resolve, wire::MsgType::ResolveOk, ctl::Resolve{dev});
    n.wait_for(lk, txn, std::chrono::steady_clock::now() + timeout);

    std::optional<PeerInfo> out;
    auto                    it = n.requests.find(txn);
    if (it == n.requests.end()) return out;
    if (it->second.done && it->second.error == ErrorCode::None) {
        wire::Reader r{it->second.reply};
        std::optional<wire::ResolveOk> ok;
        if (wire::Header::decode(r, ctl::kVersion)) ok = wire::ResolveOk::decode(r);
        // A record in some other topic is not a peer of this one. Ours is
        // remembered as somewhere to dial, as peers() does, so connect()
        // works on a resolved peer without a LOOKUP happening to sample it.
        if (ok && ok->found && ok->topic == impl_->creds.id) {
            if (!impl_->self || ok->entry.dev_id != *impl_->self) {  // never dial ourselves
                auto& peer  = impl_->peers[ok->entry.dev_id];
                peer.dev_id = ok->entry.dev_id;
                peer.cands  = ok->entry.cands;
            }
            out = PeerInfo{ok->entry.dev_id, std::chrono::seconds(ok->entry.age_secs),
                           ok->entry.stale, ok->entry.meta};
        }
    }
    n.requests.erase(it);
    return out;
}

void Topic::connect(const DevId& dev) {
    auto&                       n = *impl_->node;
    std::lock_guard<std::mutex> lk(n.mu);
    n.begin_connect(*impl_, impl_->creds.id, dev, n.now());
}

void Topic::connect_all(size_t max_peers) {
    auto   list    = peers(static_cast<uint8_t>(std::min<size_t>(max_peers * 2, 100)));
    size_t started = 0;
    for (const auto& pi : list) {
        if (started >= max_peers) break;
        if (pi.stale) continue;
        connect(pi.dev_id);
        ++started;
    }
}

void Node::Impl::disconnect_peer(Topic::Impl& ti, Peer& peer, uint16_t reason) {
    const bool was_up = peer.state == PeerState::Connected;
    const bool live   = was_up || peer.state == PeerState::Probing ||
                        peer.state == PeerState::Handshaking;
    if (peer.sess) {
        // Queue the notice and get it onto the wire before the socket goes.
        peer.sess->close(reason, now());
        auto bytes = peer.sess->take_output();
        peer.out.insert(peer.out.end(), bytes.begin(), bytes.end());
        flush_peer(peer);
        peer.sock.close();
    }
    end_attempt(peer);

    // The caller erases the peer next, so drive_peer never polls the Closed
    // event the session just queued. Tell the application here instead, as
    // drive_peer would have.
    if (peer.dgram) dgram_drop(ti, peer);
    if (was_up && ti.on_peer_closed) {
        deferred.push_back([cb = ti.on_peer_closed, dev = peer.dev_id] { cb(dev, PeerGone::Local); });
    }
    if (live) set_peer_state(ti, peer, PeerState::Closed);
}

void Topic::disconnect(const DevId& dev) {
    auto&                       n = *impl_->node;
    std::lock_guard<std::mutex> lk(n.mu);
    auto                        it = impl_->peers.find(dev);
    if (it == impl_->peers.end()) return;
    n.disconnect_peer(*impl_, it->second, close_reason::kGoingAway);
    impl_->peers.erase(it);
}

void Topic::disconnect_all() { disconnect_all_with_reason(close_reason::kGoingAway); }

void Topic::disconnect_all_with_reason(uint16_t reason) {
    auto&                       n = *impl_->node;
    std::lock_guard<std::mutex> lk(n.mu);
    for (auto& [dev, peer] : impl_->peers) {
        (void)dev;
        n.disconnect_peer(*impl_, peer, reason);
    }
    impl_->peers.clear();
}

std::vector<DevId> Topic::connected() const {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    std::vector<DevId>          out;
    for (const auto& [dev, peer] : impl_->peers) {
        if (peer.state == PeerState::Connected) out.push_back(dev);
    }
    return out;
}

PeerState Topic::state(const DevId& dev) const {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    auto                        it = impl_->peers.find(dev);
    return it == impl_->peers.end() ? PeerState::Unknown : it->second.state;
}

std::optional<LinkInfo> Topic::link(const DevId& dev) const {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    auto                        it = impl_->peers.find(dev);
    if (it == impl_->peers.end() || !it->second.sess ||
        it->second.sess->state() != TcpSession::State::Established) {
        return std::nullopt;
    }
    LinkInfo li = it->second.link;
    li.relayed  = it->second.relayed;
    return li;
}

bool Topic::send(const DevId& dev, std::span<const uint8_t> payload) {
    auto&                       n = *impl_->node;
    std::lock_guard<std::mutex> lk(n.mu);
    auto                        it = impl_->peers.find(dev);
    if (it == impl_->peers.end() || !it->second.sess) return false;
    if (payload.size() > max_message()) return false;
    Peer& peer = it->second;
    if (!n.send_record(peer, kMessageRecord, payload)) return false;
    ++peer.link.messages_sent;
    peer.link.bytes_sent += payload.size();
    return true;
}

size_t Topic::broadcast(std::span<const uint8_t> payload) {
    size_t sent = 0;
    for (const auto& d : connected()) {
        if (send(d, payload)) ++sent;
    }
    return sent;
}

bool Topic::open_datagrams(const DevId& dev, DatagramFallback fb) {
    auto&                       n = *impl_->node;
    std::lock_guard<std::mutex> lk(n.mu);
    auto                        it = impl_->peers.find(dev);
    if (it == impl_->peers.end() || !it->second.sess ||
        it->second.sess->state() != TcpSession::State::Established) {
        return false;
    }
    Peer& peer = it->second;
    if (peer.dgram && peer.dgram->path != DatagramPath::Failed) {
        peer.dgram->fallback = fb;  // already open, or opening: just the policy
        return true;
    }
    if (peer.dgram_epoch == UINT32_MAX) return false;
    return n.dgram_open(*impl_, peer, peer.dgram_epoch + 1, fb, n.now());
}

void Topic::close_datagrams(const DevId& dev) {
    auto&                       n = *impl_->node;
    std::lock_guard<std::mutex> lk(n.mu);
    auto                        it = impl_->peers.find(dev);
    if (it == impl_->peers.end() || !it->second.dgram) return;
    Peer& peer = it->second;
    n.send_record(peer, kDgramClose, encode_u32(peer.dgram->epoch));
    n.dgram_drop(*impl_, peer);
}

DatagramPath Topic::datagram_path(const DevId& dev) const {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    auto                        it = impl_->peers.find(dev);
    if (it == impl_->peers.end() || !it->second.dgram) return DatagramPath::None;
    return it->second.dgram->path;
}

bool Topic::send_datagram(const DevId& dev, std::span<const uint8_t> payload) {
    auto&                       n = *impl_->node;
    std::lock_guard<std::mutex> lk(n.mu);
    if (payload.size() > max_datagram()) return false;
    auto it = impl_->peers.find(dev);
    if (it == impl_->peers.end() || !it->second.dgram || !it->second.sess) return false;
    Peer&  peer = it->second;
    Dgram& d    = *peer.dgram;
    switch (d.path) {
        case DatagramPath::Direct:
        case DatagramPath::Relayed:
            if (!d.sess || !d.sess->send(payload, n.now())) return false;
            n.flush_dgram(peer);  // straight out, not on the next loop tick
            break;
        case DatagramPath::Tcp:
            if (!n.send_record(peer, kDgramOverTcp, payload)) return false;
            break;
        default:
            return false;
    }
    ++peer.link.datagrams_sent;
    return true;
}

void Topic::on_peer(std::function<void(DevId, PeerState)> cb) {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    impl_->on_peer = std::move(cb);
}

void Topic::on_data(std::function<void(DevId, std::span<const uint8_t>)> cb) {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    impl_->on_data = std::move(cb);
}

void Topic::on_peer_closed(std::function<void(DevId, PeerGone)> cb) {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    impl_->on_peer_closed = std::move(cb);
}

void Topic::on_datagram(std::function<void(DevId, std::span<const uint8_t>)> cb) {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    impl_->on_datagram = std::move(cb);
}

void Topic::on_datagram_path(std::function<void(DevId, DatagramPath)> cb) {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    impl_->on_datagram_path = std::move(cb);
}

void Topic::set_max_peers(size_t n) {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    impl_->max_peers = n;
}

void Topic::set_auto_connect(bool on) {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    impl_->auto_connect = on;
}

std::optional<std::string> Topic::sas(const DevId& dev) const {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    auto                        it = impl_->peers.find(dev);
    if (it == impl_->peers.end() || !it->second.sess ||
        it->second.sess->state() != TcpSession::State::Established) {
        return std::nullopt;
    }
    return it->second.sess->sas();
}

std::optional<std::array<uint8_t, 32>> Topic::channel_binding(const DevId& dev) const {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    auto                        it = impl_->peers.find(dev);
    if (it == impl_->peers.end() || !it->second.sess ||
        it->second.sess->state() != TcpSession::State::Established) {
        return std::nullopt;
    }
    return it->second.sess->handshake_hash();
}

// ---------------------------------------------------------------------------
// Node public API
// ---------------------------------------------------------------------------
Node::Node(Config cfg) : impl_(std::make_unique<Impl>()) {
    // Validated before anything touches the network. A generation must span
    // more than the 64-packet replay window (a shift of at least 7), or a
    // reordered packet can be two generations old and is dropped without a
    // word; at 64 or more the shift is undefined behaviour.
    if (cfg.rekey_shift < 7 || cfg.rekey_shift > 63) {
        throw std::invalid_argument("uconnect: rekey_shift must be in 7..63, got " +
                                    std::to_string(cfg.rekey_shift));
    }

    impl_->cfg = std::move(cfg);
    io::init_networking();

    if (!impl_->listener.open(impl_->cfg.bind_port) || !impl_->listener.listen()) {
        throw std::runtime_error("uconnect: failed to listen on TCP port " +
                                 std::to_string(impl_->cfg.bind_port) + ": " +
                                 impl_->listener.last_error());
    }
    impl_->port = impl_->listener.local_port();

    auto server = io::resolve(impl_->cfg.server);
    if (!server) {
        throw std::runtime_error("uconnect: cannot resolve server address: " + impl_->cfg.server);
    }
    impl_->server = *server;

    // Start from a random txn so replies are not trivially predictable.
    auto seed = crypto::random_array<4>();
    std::memcpy(&impl_->next_txn, seed.data(), sizeof(impl_->next_txn));
    impl_->gather_host_candidates();
}

Node::Node(std::string server) : Node(Config{std::move(server)}) {}

Node::~Node() { shutdown(); }

Topic& Node::join(const TopicCreds& creds) {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto                        it = impl_->topics.find(creds.id);
    if (it != impl_->topics.end()) return *it->second;

    auto ti   = std::make_unique<Topic::Impl>();
    ti->node  = impl_.get();
    ti->creds = creds;
    ti->keyed = creds.is_keyed();
    if (ti->keyed) ti->keys = crypto::TopicKeys::derive(*creds.key);

    std::unique_ptr<Topic> t{new Topic(std::move(ti))};
    auto [pos, _] = impl_->topics.emplace(creds.id, std::move(t));
    return *pos->second;
}

Topic& Node::create(bool keyed) {
    return join(keyed ? TopicCreds::generate_keyed() : TopicCreds::generate_open());
}

void Node::leave(const TopicId& id) {
    std::unique_ptr<Topic> owned;
    {
        std::lock_guard<std::mutex> lk(impl_->mu);
        auto                        it = impl_->topics.find(id);
        if (it == impl_->topics.end()) return;
        owned = std::move(it->second);
        impl_->topics.erase(it);
    }
    owned->unpublish();
    owned->disconnect_all();
}

std::vector<TopicId> Node::topics() const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    std::vector<TopicId>        out;
    for (const auto& [id, t] : impl_->topics) {
        (void)t;
        out.push_back(id);
    }
    return out;
}

const TopicCreds* Node::creds(const TopicId& id) const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto                        it = impl_->topics.find(id);
    return it == impl_->topics.end() ? nullptr : &it->second->impl_->creds;
}

std::vector<TopicSummary> Node::explore(uint32_t cursor, size_t limit,
                                        std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lk(impl_->mu);
    if (impl_->on_loop_thread()) return {};
    const auto                   deadline = std::chrono::steady_clock::now() + timeout;

    // One TOPICS request carries at most 255. Follow next_cursor until `limit`
    // is met or the listing ends.
    std::vector<TopicSummary> out;
    uint32_t                  at = cursor;
    while (out.size() < limit) {
        ctl::Topics q;
        q.cursor           = at;
        q.limit            = static_cast<uint8_t>(std::min<size_t>(limit - out.size(), 255));
        const uint32_t txn = impl_->request(wire::MsgType::Topics, wire::MsgType::TopicsOk, q);
        const bool     ok  = impl_->wait_for(lk, txn, deadline);

        auto it = impl_->requests.find(txn);
        if (it == impl_->requests.end()) break;
        std::optional<ctl::TopicsOk> page;
        if (ok && it->second.error == ErrorCode::None) {
            wire::Reader r{it->second.reply};
            if (wire::Header::decode(r, ctl::kVersion)) page = ctl::TopicsOk::decode(r);
        }
        impl_->requests.erase(it);
        if (!page) break;
        for (const auto& t : page->topics) {
            if (out.size() >= limit) break;
            out.push_back(TopicSummary{t.id, t.mode, t.peers, t.fresh_peers});
        }
        if (page->next_cursor == 0 || page->topics.empty()) break;
        at = page->next_cursor;
    }
    return out;
}

std::optional<ServerStats> Node::stats(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lk(impl_->mu);
    if (impl_->on_loop_thread()) return std::nullopt;
    const uint32_t txn = impl_->request_empty(wire::MsgType::Stats, wire::MsgType::StatsOk);
    const bool     ok  = impl_->wait_for(lk, txn, std::chrono::steady_clock::now() + timeout);

    std::optional<ServerStats> out;
    auto                       it = impl_->requests.find(txn);
    if (it == impl_->requests.end()) return out;
    if (ok && it->second.error == ErrorCode::None) {
        wire::Reader r{it->second.reply};
        std::optional<ctl::StatsOk> s;
        if (wire::Header::decode(r, ctl::kVersion)) s = ctl::StatsOk::decode(r);
        if (s) {
            ServerStats st;
            st.topics_total     = s->topics_total;
            st.topics_listed    = s->topics_listed;
            st.entries_total    = s->entries_total;
            st.entries_fresh    = s->entries_fresh;
            st.registers        = s->registers;
            st.lookups          = s->lookups;
            st.connects         = s->connects;
            st.expired          = s->expired;
            st.rej_quota        = s->rej_quota;
            st.rej_rate_limited = s->rej_rate_limited;
            st.relays_open      = s->relays_open;
            st.relays_allocated = s->relays_allocated;
            st.relay_bytes      = s->relay_bytes;
            st.connections      = s->connections;
            out                 = st;
        }
    }
    impl_->requests.erase(it);
    return out;
}

void Node::run() { impl_->loop(); }

void Node::run_in_background() {
    std::unique_lock<std::mutex> lk(impl_->mu);
    if (impl_->running || impl_->stop || impl_->thread.joinable()) return;
    impl_->thread = std::thread([this] { impl_->loop(); });
    impl_->cv.wait(lk, [this] { return impl_->running || impl_->stop; });
}

void Node::shutdown() {
    if (!impl_) return;

    bool on_loop = false;
    {
        std::lock_guard<std::mutex> lk(impl_->mu);
        on_loop = impl_->loop_thread_id == std::this_thread::get_id();
        if (!impl_->stop.exchange(true)) {
            for (auto& [id, t] : impl_->topics) {
                (void)id;
                auto& ti = *t->impl_;
                if (ti.self && impl_->ctl_state == Impl::Ctl::Up) {
                    impl_->notify(wire::MsgType::Unregister, ctl::DevRef{*ti.self});
                }
                ti.published = false;
                ti.self.reset();
                for (auto& [dev, peer] : ti.peers) {
                    (void)dev;
                    impl_->disconnect_peer(ti, peer, close_reason::kShutdown);
                }
                ti.peers.clear();
            }
            // Nonblocking best effort; closing the control socket also removes
            // its registrations. No loop-thread sleep is needed to flush it.
            while (impl_->ctl_state == Impl::Ctl::Up && !impl_->ctl_out.empty()) {
                auto n = impl_->control.send(impl_->ctl_out);
                if (!n || *n == 0) break;
                impl_->ctl_out.erase(impl_->ctl_out.begin(),
                                    impl_->ctl_out.begin() + static_cast<ptrdiff_t>(*n));
            }
        }
    }
    if (on_loop) return; // the loop completes cleanup after this callback returns
    std::lock_guard<std::mutex> join_lock(impl_->join_mu);
    if (impl_->thread.joinable()) impl_->thread.join();
    std::unique_lock<std::mutex> lk(impl_->mu);
    impl_->cv.wait(lk, [this] { return !impl_->running; }); // caller-owned run()
    impl_->finish_shutdown(); // also handles nodes whose loop was never started
}

bool     Node::is_running() const { return impl_->running; }
uint16_t Node::local_port() const { return impl_->port; }

std::optional<Endpoint> Node::reflexive() const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    return impl_->srflx;
}

bool Node::server_connected() const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    return impl_->ctl_state == Impl::Ctl::Up;
}

size_t Node::pending_requests() const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    return impl_->requests.size();
}

}  // namespace uconnect
