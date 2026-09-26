// Node and Topic: the public API, and the only place where the sans-IO layers
// are driven by a real socket and a real clock.
//
// Datagram routing, which is the crux of running everything on one socket:
//
//   0x01-0x1F signaling  -> from the server: correlate by txn_id
//   0x20-0x2F probe      -> answer it (that is what opens our NAT), and feed
//                           any matching punch attempt
//   0x30-0x3F handshake  -> HandshakeInit is gated on a probe_txn WE issued and
//                           answered recently; HandshakeResp matches conn_id
//   0x40-0x4F transport  -> conn_id -> session (not the 4-tuple, so a NAT
//                           rebind does not lose the session)

#include "uconnect/uconnect.hpp"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <condition_variable>
#include <cstring>
#include <map>
#include <stdexcept>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <utility>

#include "kdf.hpp"
#include "messages.hpp"
#include "noise.hpp"
#include "primitives.hpp"
#include "punch.hpp"
#include "connection.hpp"
#include "session.hpp"
#include "socket.hpp"

namespace uconnect {
namespace {

using namespace std::chrono_literals;

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

// How long the non-designated peer waits for the other end to offer a relay
// before asking for one itself.
constexpr auto kRelayBackupDelay = 2s;

// How often auto-connect asks the server who else is in the topic.
constexpr auto kDiscoveryInterval = 5s;

constexpr auto kProbeMemory = 30s;  // how long an answered probe_txn stays usable

// One byte at the front of every session payload says which of the two
// transports it belongs to.
//
// Both share the session, so without a discriminator a raw application
// datagram gets handed to the stream layer, parsed as frames, and dropped as
// malformed -- which is exactly what happened the first time these were wired
// together: peers connected and no message ever arrived.
// The peer supplies only the reason code; the cause is our own account, so a
// hostile peer cannot dress its disappearance up as our idle timer.
PeerGone peer_gone_from(session::CloseCause cause, uint16_t peer_reason) {
    switch (cause) {
        case session::CloseCause::Local:    return PeerGone::Local;
        case session::CloseCause::TimedOut: return PeerGone::TimedOut;
        case session::CloseCause::PeerNotice:
            switch (peer_reason) {
                case wire::close_reason::kGoingAway: return PeerGone::GoingAway;
                case wire::close_reason::kShutdown:  return PeerGone::ShuttingDown;
                default:                             return PeerGone::Unspecified;
            }
    }
    return PeerGone::Unspecified;
}

namespace payload_kind {
inline constexpr uint8_t kDatagram = 0x00;  // unreliable, delivered as-is
inline constexpr uint8_t kStream   = 0x01;  // stream frames
}  // namespace payload_kind

}  // namespace

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

struct Peer {
    DevId                             dev_id{};
    std::vector<Candidate>            cands;
    std::optional<path::PunchSession> punch;
    std::optional<session::Session>   sess;
    PeerState                         state = PeerState::Unknown;

    // Relay fallback. When punching fails -- which in practice means symmetric
    // NAT on both ends -- datagrams for this peer are wrapped in RelayData and
    // sent to the rendezvous server, which forwards them. The session above is
    // unchanged and unaware: it still sees an opaque path, and the relay still
    // cannot read a byte of what it carries.
    bool          relayed     = false;
    wire::RelayId relay_id    = 0;
    bool          relay_asked = false;
    // When the non-designated peer should stop waiting for the other end to
    // offer a relay and ask for its own. Zero means "not waiting".
    Instant       relay_backup_at{};

    // Reliable, ordered, congestion-controlled streams over this peer's
    // session. Created once the handshake completes.
    std::optional<stream::StreamConnection> streams;
};

// A pending server request awaiting its reply.
struct Pending {
    wire::MsgType expect{};
    // Rebuilds the request with a Retry cookie, so address validation costs one
    // extra round trip and no bookkeeping at the call site.
    std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)> rebuild;

    // Retransmission. A single UDP datagram is lost often enough on a real
    // internet path that a one-shot request makes discovery flaky: one drop and
    // peers() returns nothing with no indication why.
    Instant  last_sent{};
    int      attempts = 0;

    bool done = false;
    std::vector<PeerInfo>     peers;
    uint16_t                  total = 0;
    TopicMode                 mode  = TopicMode::Open;
    uint8_t                   parts_seen = 0, parts_total = 1;
    std::vector<TopicSummary> summaries;
    std::optional<PeerInfo>   one;
    std::optional<ServerStats> stats;
    std::optional<DevId>      dev_id;
    wire::LeaseToken          lease{};
    Endpoint                  srflx{};
    ErrorCode                 error = ErrorCode::None;

    // Which (topic, peer) a RelayAlloc was for.
    //
    // Without this the reply has to be matched by scanning every peer in every
    // topic for one that is waiting -- which applies the first RelayAllocOk to
    // ALL of them, so two concurrent allocations both end up on one binding.
    // It also gives a rejection somewhere to be reported, instead of the peer
    // hanging in Probing forever.
    std::optional<std::pair<TopicId, DevId>> relay_for;

    // Set on a LOOKUP issued by auto-connect, so its result can drive
    // connections rather than being handed back to a waiting caller.
    std::optional<TopicId> auto_discover;
};

struct AnsweredProbe {
    Endpoint               from{};
    Instant                when{};
    std::optional<TopicId> topic;  // known only for keyed topics
};

}  // namespace

// ---------------------------------------------------------------------------
struct Topic::Impl {
    Node::Impl*       node = nullptr;
    TopicCreds        creds;
    crypto::TopicKeys keys;
    bool              keyed = false;

    std::optional<DevId> self;
    wire::LeaseToken     lease{};
    uint64_t             seq       = 0;
    bool                 published = false;
    bool                 unlisted  = false;
    std::vector<uint8_t> meta;
    Instant              next_keepalive{};
    Instant              next_discovery{};

    std::unordered_map<DevId, Peer, ArrayHash> peers;
    size_t                                     max_peers    = 8;
    bool                                       auto_connect = false;

    std::function<void(DevId, PeerState)>                on_peer;
    std::function<void(DevId, std::span<const uint8_t>)> on_data;
    std::function<void(DevId, uint64_t)>                 on_stream;
    std::function<void(DevId, uint64_t)>                 on_stream_readable;
    std::function<void(DevId, uint64_t)>                 on_stream_finished;
    std::function<void(DevId, uint64_t)>                 on_stream_writable;
    std::function<void(DevId, uint64_t, uint64_t)>       on_stream_reset;
    std::function<void(DevId, uint64_t)>                 on_stream_closed;
    std::function<void(DevId, PeerGone)>                 on_peer_closed;

    const crypto::SymKey* psk() const { return keyed ? &keys.psk : nullptr; }
    const crypto::SymKey* probe_key() const { return keyed ? &keys.probe : nullptr; }
};

struct Node::Impl {
    Node::Config  cfg;
    io::UdpSocket sock;
    Endpoint      server{};

    std::vector<Candidate>  host_cands;
    std::optional<Endpoint> srflx;
    std::vector<uint8_t>    cookie;

    mutable std::mutex      mu;
    std::condition_variable cv;

    std::map<TopicId, std::unique_ptr<Topic>, TopicIdLess> topics;

    uint32_t                                 next_txn = 1;
    std::unordered_map<uint32_t, Pending>    pending;
    std::unordered_map<wire::ProbeTxn, AnsweredProbe, ArrayHash> answered;
    std::unordered_map<wire::ConnId, std::pair<TopicId, DevId>>  conns;

    // Callbacks queued while `mu` is held, invoked after it is released.
    std::vector<std::function<void()>> deferred;

    std::thread       thread;
    std::atomic<bool> running{false};
    std::atomic<bool> stop{false};

    // --- helpers ----------------------------------------------------------
    void send_raw(const Endpoint& to, std::span<const uint8_t> d) {
        sock.send_to(to, d);
    }

    uint32_t alloc_txn() { return next_txn++; }

    void     gather_host_candidates();
    void     loop();
    void     pump(Instant now);
    void     dispatch(const Endpoint& from, std::span<const uint8_t> dgram, Instant now);
    void     on_signaling(const Endpoint& from, std::span<const uint8_t>, Instant now);
    void     on_probe_dgram(const Endpoint& from, std::span<const uint8_t>, Instant now);
    void     on_handshake_dgram(const Endpoint& from, std::span<const uint8_t>, Instant now);
    void     on_transport_dgram(const Endpoint& from, std::span<const uint8_t>, Instant now);

    void     drive_topic(Topic::Impl&, const TopicId&, Instant now);
    void     drive_peer(Topic::Impl&, const TopicId&, Peer&, Instant now);
    void     drive_streams(Topic::Impl&, const TopicId&, Peer&, Instant now);
    void     begin_connect(Topic::Impl&, const TopicId&, const DevId&, Instant now);
    void     discover(Topic::Impl&, const TopicId&, Instant now);
    size_t   connected_count(const Topic::Impl&) const;
    size_t   total_peer_count() const;

    // Sends to a peer, wrapping in RelayData when that peer is on the relay
    // path. Every peer-bound datagram goes through here so the relay decision
    // lives in exactly one place.
    void     send_to_peer(Peer&, const Endpoint& to, std::span<const uint8_t> d);
    void     request_relay(Topic::Impl&, const TopicId&, Peer&, Instant now);
    void     start_relay_session(Topic::Impl&, const TopicId&, Peer&, Instant now);
    void     set_peer_state(Topic::Impl&, Peer&, PeerState);
    void     start_punch(Topic::Impl&, const TopicId&, Peer&, Instant now);
    void     send_connect_relay(Topic::Impl&, const TopicId&, const DevId& to, Instant now);
    void     send_keepalive(Topic::Impl&, Instant now);
    void     send_register(Topic::Impl&, const TopicId&, Instant now);

};

namespace {

wire::Mac compute_mac(const wire::LeaseToken& token, std::span<const uint8_t> prefix) {
    auto      h = crypto::Blake2s::mac(token, prefix);
    wire::Mac m{};
    std::memcpy(m.data(), h.data(), wire::kMacLen);
    return m;
}

// Relay payload: topic_id so the receiver knows which topic is punching it,
// then the sender's candidates so it can punch back immediately.
// The CONNECT relay payload: which topic is punching you, the sender's
// candidates so you can punch back, and -- when punching has already failed --
// the relay binding to use instead.
//
// A nonzero relay_id is how the far side learns to stop probing and switch to
// the relay. It travels inside a CONNECT, which is MAC'd with the sender's
// lease token, so the id is not something a bystander can inject.
std::vector<uint8_t> encode_relay_payload(const TopicId& topic,
                                          const std::vector<Candidate>& cands,
                                          wire::RelayId relay_id) {
    std::vector<uint8_t> buf(wire::kMaxRelayPayload);
    wire::Writer         w{buf};
    w.array(topic);
    w.u64(relay_id);
    size_t n = std::min<size_t>(cands.size(), wire::kMaxCandidates);
    w.u8(static_cast<uint8_t>(n));
    for (size_t i = 0; i < n; ++i) w.candidate(cands[i]);
    if (!w.ok()) return {};
    buf.resize(w.size());
    return buf;
}

bool decode_relay_payload(std::span<const uint8_t> p, TopicId& topic,
                          std::vector<Candidate>& cands, wire::RelayId& relay_id) {
    wire::Reader r{p};
    topic    = r.array<kTopicIdLen>();
    relay_id = r.u64();
    size_t n = r.u8();
    if (!r.ok() || n > wire::kMaxCandidates) return false;
    for (size_t i = 0; i < n; ++i) cands.push_back(r.candidate());
    return r.ok();
}

}  // namespace

// ---------------------------------------------------------------------------
// Node::Impl -- candidates and the loop
// ---------------------------------------------------------------------------
void Node::Impl::gather_host_candidates() {
    host_cands.clear();
    for (const auto& ip : io::local_addresses()) {
        if (host_cands.size() >= wire::kMaxCandidates) break;
        Candidate c;
        c.kind    = Candidate::Kind::Host;
        c.ep.ip   = ip;
        c.ep.port = sock.local_port();
        host_cands.push_back(c);
    }
}

void Node::Impl::loop() {
    running = true;
    std::vector<uint8_t> buf(2048);

    while (!stop) {
        sock.wait_readable(20ms);

        std::vector<std::function<void()>> callbacks;
        {
            std::lock_guard<std::mutex> lk(mu);
            for (int i = 0; i < 256; ++i) {
                auto got = sock.recv_from(buf);
                if (!got) break;
                dispatch(got->from, std::span(buf).first(got->len),
                         std::chrono::steady_clock::now());
            }
            pump(std::chrono::steady_clock::now());
            callbacks.swap(deferred);
        }

        // Invoked with the lock released, so a callback may call straight back
        // into the library -- send a reply, look up peers, disconnect someone --
        // which is the natural thing to want to do and would otherwise deadlock.
        for (auto& fn : callbacks) fn();
    }
    running = false;
}

void Node::Impl::pump(Instant now) {
    for (auto& [tid, topic] : topics) drive_topic(*topic->impl_, tid, now);

    // Retransmit unanswered requests. One lost datagram otherwise makes peers()
    // silently return nothing, which looks like "no peers in the topic" rather
    // than "the question never arrived".
    constexpr auto kRetransmit  = 400ms;
    constexpr int  kMaxAttempts = 4;
    for (auto& [txn, p] : pending) {
        (void)txn;
        if (p.done || !p.rebuild) continue;
        if (p.attempts >= kMaxAttempts) continue;

        // The request was already sent directly by whoever created it; this is
        // the first time the loop has seen it. Record when, and wait.
        //
        // Without this the default-constructed timestamp read as "never sent"
        // and every request went out a second time within ~20ms. For REGISTER
        // that was quietly destructive: the server registered twice and issued
        // a fresh lease token for the second one, while the client kept the
        // first -- so every MAC afterwards failed with bad auth. It stayed
        // hidden because punching does not depend on those MACs.
        if (p.last_sent == Instant{}) {
            p.last_sent = now;
            continue;
        }

        if (now - p.last_sent < kRetransmit) continue;
        auto again = p.rebuild(cookie);
        if (again.empty()) continue;
        send_raw(server, again);
        p.last_sent = now;
        ++p.attempts;
    }

    // Forget stale answered probes so the map does not grow without bound.
    for (auto it = answered.begin(); it != answered.end();) {
        if (now - it->second.when > kProbeMemory) it = answered.erase(it);
        else ++it;
    }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------
void Node::Impl::dispatch(const Endpoint& from, std::span<const uint8_t> dgram, Instant now) {
    auto type = wire::peek_type(dgram);
    if (!type) return;

    switch (wire::classify(static_cast<uint8_t>(*type))) {
        case wire::MsgClass::Signaling: on_signaling(from, dgram, now); break;
        case wire::MsgClass::Probe:     on_probe_dgram(from, dgram, now); break;
        case wire::MsgClass::Handshake: on_handshake_dgram(from, dgram, now); break;
        case wire::MsgClass::Transport: on_transport_dgram(from, dgram, now); break;
        case wire::MsgClass::Unknown:   break;
    }
}

void Node::Impl::on_signaling(const Endpoint& from, std::span<const uint8_t> dgram,
                              Instant now) {
    wire::Reader r{dgram};
    auto         h = wire::Header::decode(r);
    if (!h) return;

    // A relayed datagram: unwrap and dispatch exactly as though it had arrived
    // directly. The session demultiplexes on conn_id rather than the 4-tuple,
    // so it neither knows nor cares that the bytes came via the server.
    if (h->type == wire::MsgType::RelayData) {
        auto rd = wire::RelayData::decode(r);
        if (!rd || rd->payload.empty()) return;
        dispatch(server, rd->payload, now);
        return;
    }

    // Relayed arrives from the server but is not a reply to anything we sent.
    if (h->type == wire::MsgType::Relayed) {
        auto rel = wire::Relayed::decode(r);
        if (!rel) return;

        TopicId                topic{};
        std::vector<Candidate> cands;
        wire::RelayId          offered_relay = 0;
        if (!decode_relay_payload(rel->payload, topic, cands, offered_relay)) return;

        auto tit = topics.find(topic);
        if (tit == topics.end()) return;
        auto& ti = *tit->second->impl_;

        auto& peer  = ti.peers[rel->from_dev];
        peer.dev_id = rel->from_dev;
        if (!peer.cands.empty()) peer.cands.clear();
        peer.cands = cands;

        if (offered_relay != 0) {
            // The peer gave up on punching and opened a relay. Stop probing
            // and meet it there -- it is the designated initiator, so it will
            // drive the handshake and we only need the binding recorded.
            peer.relayed  = true;
            peer.relay_id = offered_relay;
            peer.punch.reset();
            if (!peer.sess) {
                // Record the transaction the initiator will bind its handshake
                // to, derived from the relay id so both ends compute the same
                // value without another round trip.
                wire::ProbeTxn txn{};
                for (size_t i = 0; i < 8; ++i) {
                    txn[i]     = static_cast<uint8_t>(offered_relay >> (8 * (7 - i)));
                    txn[i + 8] = txn[i];
                }
                answered[txn] = AnsweredProbe{server, now,
                                              ti.keyed ? std::optional<TopicId>(topic)
                                                       : std::nullopt};
                set_peer_state(ti, peer, PeerState::Handshaking);
            }
            return;
        }

        // The peer is about to punch us. Punch back now -- this is the
        // simultaneity the whole thing depends on.
        if (!peer.punch && !peer.sess) start_punch(ti, topic, peer, now);
        return;
    }

    auto pit = pending.find(h->txn_id);
    if (pit == pending.end()) return;
    auto& p = pit->second;

    switch (h->type) {
        case wire::MsgType::Retry: {
            auto retry = wire::Retry::decode(r);
            if (!retry) return;
            cookie = retry->cookie;
            if (p.rebuild) {
                auto again = p.rebuild(cookie);
                if (!again.empty()) send_raw(server, again);
            }
            return;
        }

        case wire::MsgType::Error: {
            auto e = wire::Error::decode(r);
            p.error = e ? e->code : ErrorCode::BadRequest;
            if (cfg.verbose) {
                std::fprintf(stderr, "[uconnect] server error txn=%u: %s\n", h->txn_id,
                             to_string(p.error));
            }

            // A refused relay allocation is a definitive answer -- the quota is
            // full, or the operator disabled relaying. Report it against the
            // peer rather than leaving it in Probing forever waiting for a
            // reply that has already arrived and said no.
            if (p.relay_for) {
                auto tit = topics.find(p.relay_for->first);
                if (tit != topics.end()) {
                    auto& ti2 = *tit->second->impl_;
                    auto  target = ti2.peers.find(p.relay_for->second);
                    if (target != ti2.peers.end() && !target->second.relayed) {
                        target->second.relay_asked = false;  // allow a later attempt
                        set_peer_state(ti2, target->second, PeerState::Failed);
                    }
                }
            }

            p.done  = true;
            cv.notify_all();
            return;
        }

        case wire::MsgType::RelayAllocOk: {
            auto ok = wire::RelayAllocOk::decode(r);
            if (!ok) return;

            // Apply it to the one peer it was requested for.
            //
            // This used to scan every topic for any peer that was waiting,
            // which meant two concurrent allocations both landed on whichever
            // relay id arrived first -- one pair silently talking over the
            // other pair's binding.
            if (!p.relay_for) return;
            auto tit = topics.find(p.relay_for->first);
            if (tit == topics.end()) return;
            auto& ti2 = *tit->second->impl_;
            auto  target = ti2.peers.find(p.relay_for->second);
            if (target == ti2.peers.end()) return;

            auto& peer = target->second;
            if (!peer.relayed) {
                peer.relayed  = true;
                peer.relay_id = ok->relay_id;
                // Tell the peer which binding to use, then handshake across it.
                send_connect_relay(ti2, p.relay_for->first, peer.dev_id, now);
                start_relay_session(ti2, p.relay_for->first, peer, now);
            }
            p.done = true;
            cv.notify_all();
            return;
        }

        case wire::MsgType::RegisterOk: {
            auto ok = wire::RegisterOk::decode(r);
            if (!ok) return;
            p.dev_id = ok->dev_id;
            p.lease  = ok->lease_token;
            p.srflx  = ok->srflx;
            srflx    = ok->srflx;
            p.done   = true;
            cv.notify_all();
            return;
        }

        case wire::MsgType::KeepaliveOk:
        case wire::MsgType::UpdateOk:
        case wire::MsgType::UnregisterOk: {
            auto ok = wire::KeepaliveOk::decode(r);
            if (ok) srflx = ok->srflx;
            p.done = true;
            cv.notify_all();
            return;
        }

        case wire::MsgType::LookupOk: {
            auto ok = wire::LookupOk::decode(r);
            if (!ok) return;
            p.total       = ok->total;
            p.mode        = ok->mode;
            p.parts_total = ok->parts;
            ++p.parts_seen;
            for (auto& e : ok->entries) {
                PeerInfo pi;
                pi.dev_id = e.dev_id;
                pi.age    = std::chrono::seconds(e.age_secs);
                pi.stale  = e.stale;
                pi.meta   = e.meta;
                p.peers.push_back(std::move(pi));

                // Stash candidates for the connect path.
                for (auto& [tid, topic] : topics) {
                    (void)tid;
                    auto& ti = *topic->impl_;
                    auto  pe = ti.peers.find(e.dev_id);
                    if (pe != ti.peers.end() || ok->id == tid) {
                        auto& peer  = ti.peers[e.dev_id];
                        peer.dev_id = e.dev_id;
                        peer.cands  = e.cands;
                    }
                }
            }
            if (p.parts_seen >= p.parts_total) {
                // An auto-connect lookup drives connections itself rather than
                // handing the list back: nobody is waiting on it, the loop
                // issued it.
                if (p.auto_discover) {
                    auto tit2 = topics.find(*p.auto_discover);
                    if (tit2 != topics.end()) {
                        auto& ti2 = *tit2->second->impl_;
                        for (const auto& pi : p.peers) {
                            // Never punch at our own record.
                            if (ti2.self && pi.dev_id == *ti2.self) continue;
                            if (pi.stale) continue;
                            begin_connect(ti2, *p.auto_discover, pi.dev_id, now);
                        }
                    }
                }
                p.done = true;
                cv.notify_all();
            }
            return;
        }

        case wire::MsgType::ResolveOk: {
            auto ok = wire::ResolveOk::decode(r);
            if (ok && ok->found) {
                PeerInfo pi;
                pi.dev_id = ok->entry.dev_id;
                pi.age    = std::chrono::seconds(ok->entry.age_secs);
                pi.stale  = ok->entry.stale;
                pi.meta   = ok->entry.meta;
                p.one     = pi;
            }
            p.done = true;
            cv.notify_all();
            return;
        }

        case wire::MsgType::TopicsOk: {
            auto ok = wire::TopicsOk::decode(r);
            if (!ok) return;
            p.parts_total = ok->parts;
            ++p.parts_seen;
            for (auto& t : ok->topics) {
                p.summaries.push_back(TopicSummary{t.id, t.mode, t.peers, t.fresh_peers});
            }
            if (p.parts_seen >= p.parts_total) {
                p.done = true;
                cv.notify_all();
            }
            return;
        }

        case wire::MsgType::StatsOk: {
            ServerStats s;
            s.topics_total     = r.u64();
            s.topics_listed    = r.u64();
            s.entries_total    = r.u64();
            s.entries_fresh    = r.u64();
            s.registers        = r.u64();
            s.keepalives       = r.u64();
            s.lookups          = r.u64();
            s.connects         = r.u64();
            s.rebinds          = r.u64();
            s.expired          = r.u64();
            s.rej_bad_auth     = r.u64();
            s.rej_quota        = r.u64();
            s.rej_rate_limited = r.u64();
            s.relays_open      = r.u64();
            s.relays_allocated = r.u64();
            s.relay_bytes      = r.u64();
            if (r.ok()) p.stats = s;
            p.done = true;
            cv.notify_all();
            return;
        }

        default:
            (void)from;
            return;
    }
}

void Node::Impl::on_probe_dgram(const Endpoint& from, std::span<const uint8_t> dgram,
                                Instant now) {
    // Answer with whichever topic's key validates. A keyed topic's probe cannot
    // be forged by a non-member, so a match also tells us which topic this is.
    for (auto& [tid, topic] : topics) {
        auto& ti = *topic->impl_;
        auto  reply = path::PunchSession::answer_probe(from, dgram, ti.probe_key(),
                                                       alloc_txn());
        if (!reply) continue;

        send_raw(reply->to, reply->data);

        wire::Reader r{dgram};
        if (wire::Header::decode(r)) {
            if (auto probe = wire::Probe::decode(r)) {
                // Remember the transaction so a HandshakeInit bound to it can
                // be accepted. Without this gate a replayed HandshakeInit would
                // cost us a DH on demand.
                answered[probe->txn] = AnsweredProbe{from, now,
                                                     ti.keyed ? std::optional<TopicId>(tid)
                                                              : std::nullopt};
            }
        }
        if (ti.keyed) break;  // a keyed match is unambiguous
    }

    // Feed any in-flight attempt: their probe proves the path works one way.
    for (auto& [tid, topic] : topics) {
        (void)tid;
        for (auto& [dev, peer] : topic->impl_->peers) {
            (void)dev;
            if (peer.punch) peer.punch->on_datagram(from, dgram, now);
        }
    }
}

void Node::Impl::on_handshake_dgram(const Endpoint& from, std::span<const uint8_t> dgram,
                                    Instant now) {
    wire::Reader r{dgram};
    auto         h = wire::Header::decode(r);
    if (!h) return;

    if (h->type == wire::MsgType::HandshakeResp) {
        auto hr = wire::HandshakeResp::decode(r);
        if (!hr) return;
        auto cit = conns.find(hr->conn_id);
        if (cit == conns.end()) return;
        auto tit = topics.find(cit->second.first);
        if (tit == topics.end()) return;
        auto& ti = *tit->second->impl_;
        auto  pe = ti.peers.find(cit->second.second);
        if (pe == ti.peers.end() || !pe->second.sess) return;
        pe->second.sess->on_datagram(from, dgram, now);
        return;
    }

    if (h->type != wire::MsgType::HandshakeInit) return;
    auto hi = wire::HandshakeInit::decode(r);
    if (!hi) return;

    // Gate: the probe_txn must be one WE issued and answered, recently, and not
    // yet consumed. This is what makes a replayed HandshakeInit useless.
    auto ait = answered.find(hi->probe_txn);
    if (ait == answered.end()) return;
    if (now - ait->second.when > kProbeMemory) {
        answered.erase(ait);
        return;
    }

    auto try_topic = [&](const TopicId& tid, Topic::Impl& ti) -> bool {
        DevId placeholder{};
        std::memcpy(placeholder.data(), &hi->conn_id, sizeof(hi->conn_id));

        auto s = session::Session::accept(session::SessionConfig{}, tid, 0, ti.psk(),
                                          placeholder, from, hi->probe_txn, dgram, now);
        if (!s) return false;

        // The peer identifies itself inside the authenticated handshake payload,
        // so we do not have to guess from the source address. Guessing was the
        // bug: behind a symmetric NAT the handshake arrives from a different
        // mapping than the peer advertised, matching failed, and the session got
        // filed under `placeholder` -- making one peer appear twice, once under
        // its real dev_id from LOOKUP and once under a synthetic one.
        DevId owner = s->peer();

        auto& peer  = ti.peers[owner];
        peer.dev_id = owner;

        // Glare. Both peers call connect() at once, so both initiate, and
        // without a tie-break each would replace its own session with the one
        // it accepted -- leaving the two ends on different conn_ids, each
        // talking on a session the other has thrown away. Symptom: handshakes
        // complete, both sides report "connected", and no data ever arrives.
        //
        // Break it deterministically on dev_id: the numerically smaller dev_id
        // is the designated initiator, so both ends independently keep the same
        // session.
        if (peer.sess && ti.self) {
            bool we_are_initiator =
                std::memcmp(ti.self->data(), owner.data(), kDevIdLen) < 0;
            if (we_are_initiator) return true;  // keep ours; ignore theirs
            conns.erase(peer.sess->conn_id());  // yield: drop ours, take theirs
        }

        peer.sess = std::move(*s);
        peer.punch.reset();
        conns[hi->conn_id] = {tid, owner};
        set_peer_state(ti, peer, PeerState::Handshaking);
        drive_peer(ti, tid, peer, now);
        return true;
    };

    if (ait->second.topic) {
        auto tit = topics.find(*ait->second.topic);
        if (tit != topics.end()) try_topic(tit->first, *tit->second->impl_);
        return;
    }
    // Open topic: the prologue carries topic_id, so only the right one accepts.
    for (auto& [tid, topic] : topics) {
        if (try_topic(tid, *topic->impl_)) break;
    }
}

void Node::Impl::on_transport_dgram(const Endpoint& from, std::span<const uint8_t> dgram,
                                    Instant now) {
    wire::Reader r{dgram};
    auto         h = wire::Header::decode(r);
    if (!h) return;
    auto t = wire::Transport::decode(r);
    if (!t) return;

    // Match on conn_id, never the 4-tuple: that is what lets a session survive
    // a NAT rebind.
    auto cit = conns.find(t->conn_id);
    if (cit == conns.end()) return;
    auto tit = topics.find(cit->second.first);
    if (tit == topics.end()) return;
    auto& ti = *tit->second->impl_;
    auto  pe = ti.peers.find(cit->second.second);
    if (pe == ti.peers.end() || !pe->second.sess) return;

    pe->second.sess->on_datagram(from, dgram, now);
    drive_peer(ti, cit->second.first, pe->second, now);
}

// ---------------------------------------------------------------------------
// Driving topics and peers
// ---------------------------------------------------------------------------
void Node::Impl::set_peer_state(Topic::Impl& ti, Peer& peer, PeerState s) {
    if (peer.state == s) return;
    peer.state = s;
    // Deferred, not called inline: callbacks fire with `mu` held otherwise, and
    // the natural thing to do from on_peer is call back into the library
    // (send a greeting, look up peers) -- which would deadlock on a
    // non-recursive mutex.
    if (ti.on_peer) {
        deferred.push_back([cb = ti.on_peer, dev = peer.dev_id, s] { cb(dev, s); });
    }
}

// ---------------------------------------------------------------------------
// Relay fallback
// ---------------------------------------------------------------------------
void Node::Impl::send_to_peer(Peer& peer, const Endpoint& to, std::span<const uint8_t> d) {
    if (!peer.relayed) {
        send_raw(to, d);
        return;
    }

    // Wrap and hand to the server. The payload is a Noise handshake message or
    // an AEAD-sealed transport frame either way, so the relay forwards bytes it
    // cannot read.
    std::vector<uint8_t> buf(wire::kMaxDatagram + 64);
    wire::Writer         w{buf};
    wire::Header{wire::MsgType::RelayData, wire::kVersion, 0, 0}.encode(w);
    wire::RelayData rd;
    rd.relay_id = peer.relay_id;
    rd.payload.assign(d.begin(), d.end());
    rd.encode(w);
    if (!w.ok()) return;
    buf.resize(w.size());
    send_raw(server, buf);
}

void Node::Impl::request_relay(Topic::Impl& ti, const TopicId& tid, Peer& peer, Instant now) {
    (void)now;
    if (peer.relay_asked || !ti.self) return;
    peer.relay_asked = true;

    uint32_t txn = alloc_txn();

    // Built through a closure so the retransmission in pump() can resend it.
    //
    // A one-shot RelayAlloc meant a single dropped datagram stranded the pair
    // permanently -- no retry, no timeout, no Failed event, the peer just sat
    // in Probing forever. Which is the same lost-datagram failure the LOOKUP
    // path already fixes, in the very path that exists to rescue connections
    // that have already failed once.
    //
    // The sequence number is drawn FRESH on every build, not captured. The
    // server rejects a sequence it has already seen, so a retransmission
    // carrying the original seq would be refused as a replay and the retry
    // would accomplish nothing. Re-reading the topic through `this` keeps the
    // counter authoritative even though the Pending outlives this call.
    const TopicId topic = tid;

    auto build = [this, topic, txn](const std::vector<uint8_t>&) {
        auto tit = topics.find(topic);
        if (tit == topics.end()) return std::vector<uint8_t>{};
        auto& t = *tit->second->impl_;
        if (!t.self) return std::vector<uint8_t>{};

        auto pit = pending.find(txn);
        if (pit == pending.end() || !pit->second.relay_for) return std::vector<uint8_t>{};

        std::vector<uint8_t> buf(wire::kMaxDatagram);
        wire::Writer         w{buf};
        wire::Header{wire::MsgType::RelayAlloc, wire::kVersion, 0, txn}.encode(w);
        wire::RelayAlloc m;
        m.from_dev = *t.self;
        m.peer_dev = pit->second.relay_for->second;
        m.auth.seq = ++t.seq;
        m.encode_prefix(w);
        w.array(compute_mac(t.lease, w.written()));
        if (!w.ok()) return std::vector<uint8_t>{};
        buf.resize(w.size());
        return buf;
    };

    Pending p;
    p.expect     = wire::MsgType::RelayAllocOk;
    p.rebuild    = build;
    p.relay_for  = std::make_pair(tid, peer.dev_id);
    pending[txn] = std::move(p);

    if (cfg.verbose) {
        std::fprintf(stderr, "[uconnect] RelayAlloc txn=%u peer=%s\n", txn,
                     to_hex(peer.dev_id).substr(0, 8).c_str());
    }
    send_raw(server, build(cookie));
}

void Node::Impl::start_relay_session(Topic::Impl& ti, const TopicId& tid, Peer& peer,
                                     Instant now) {
    if (peer.sess || peer.relay_id == 0) return;

    // A relayed path needs no probing: the server is reachable by definition,
    // and it is the server that validates both ends. So there is no probe
    // transaction to bind the handshake to -- derive a deterministic one from
    // the relay id instead, which both peers can compute identically.
    wire::ProbeTxn txn{};
    for (size_t i = 0; i < 8; ++i) {
        txn[i]     = static_cast<uint8_t>(peer.relay_id >> (8 * (7 - i)));
        txn[i + 8] = txn[i];
    }

    auto s = session::Session::initiate(session::SessionConfig{}, tid, 0, ti.psk(),
                                        ti.self ? *ti.self : DevId{}, peer.dev_id,
                                        server, txn, now);
    conns[s.conn_id()] = {tid, peer.dev_id};
    peer.sess          = std::move(s);
    peer.punch.reset();

    // The responder must accept a handshake bound to this transaction, so
    // record it as though we had answered a probe for it.
    answered[txn] = AnsweredProbe{server, now, ti.keyed ? std::optional<TopicId>(tid)
                                                        : std::nullopt};
    set_peer_state(ti, peer, PeerState::Handshaking);
}

void Node::Impl::start_punch(Topic::Impl& ti, const TopicId& tid, Peer& peer, Instant now) {
    path::LocalView lv;
    lv.our_srflx = srflx;

    peer.punch.emplace(path::PunchConfig{}, peer.dev_id, peer.cands, lv, ti.probe_key());
    peer.punch->begin(now);
    set_peer_state(ti, peer, PeerState::Probing);
    (void)tid;
}

void Node::Impl::drive_peer(Topic::Impl& ti, const TopicId& tid, Peer& peer, Instant now) {
    if (peer.punch) {
        peer.punch->on_timeout(now);
        while (auto o = peer.punch->poll_transmit()) send_raw(o->to, o->data);

        while (auto e = peer.punch->poll_event()) {
            if (e->kind == path::PunchEvent::Kind::Nominated) {
                // Hand the validated path and its transaction to the session
                // layer; the prologue binds the handshake to both.
                auto s = session::Session::initiate(
                    session::SessionConfig{}, tid, 0, ti.psk(),
                    ti.self ? *ti.self : DevId{}, peer.dev_id, e->path, e->txn, now);
                conns[s.conn_id()] = {tid, peer.dev_id};
                peer.sess          = std::move(s);
                peer.punch.reset();
                set_peer_state(ti, peer, PeerState::Handshaking);
                break;
            }
            if (e->kind == path::PunchEvent::Kind::Failed) {
                peer.punch.reset();

                // Punching failed. On a real network that overwhelmingly means
                // symmetric NAT on both ends: each allocates a fresh external
                // port per destination, so the address the rendezvous server
                // observed is not the address the peer must hit, and no amount
                // of further probing finds one that works.
                //
                // Fall back to relaying through the server.
                //
                // The designated initiator asks immediately; the other side
                // waits a moment and then asks too if no offer has arrived.
                //
                // Only one side asking was a single point of failure: if its
                // request was lost or refused, the pair was stranded with the
                // other end never even trying. The tie-break is not needed for
                // correctness here -- unlike handshake glare, a duplicate
                // request is harmless, because the store already returns the
                // existing binding for a pair rather than allocating a second.
                // So it is only an optimisation to avoid a redundant round
                // trip, and it should not be allowed to block the fallback.
                const bool first =
                    ti.self && std::memcmp(ti.self->data(), peer.dev_id.data(),
                                           kDevIdLen) < 0;
                if (!peer.relay_asked) {
                    if (first) {
                        request_relay(ti, tid, peer, now);
                    } else {
                        // Give the other end its head start, then follow up.
                        peer.relay_backup_at = now + kRelayBackupDelay;
                        set_peer_state(ti, peer, PeerState::Probing);
                    }
                }
                break;
            }
        }
    }

    if (peer.sess) {
        peer.sess->on_timeout(now);
        while (auto o = peer.sess->poll_transmit()) send_to_peer(peer, o->to, o->data);

        while (auto e = peer.sess->poll_event()) {
            using K = session::SessionEvent::Kind;
            switch (e->kind) {
                case K::Established: {
                    // Bring up the reliable stream layer over this session.
                    // Roles must differ between the two ends so concurrently
                    // opened stream ids never collide; reuse the dev_id
                    // ordering that already decides the initiator.
                    if (!peer.streams) {
                        const bool a =
                            ti.self && std::memcmp(ti.self->data(), peer.dev_id.data(),
                                                   kDevIdLen) < 0;
                        stream::StreamConfig scfg;
                        scfg.stream_recv_window      = cfg.stream_recv_window;
                        scfg.conn_recv_window        = cfg.conn_recv_window;
                        scfg.max_concurrent_streams  = cfg.max_streams_per_peer;
                        peer.streams.emplace(scfg, a ? stream::Role::A : stream::Role::B);
                    } else {
                        // Streams already exist, so this is a second session
                        // with the same peer -- a re-handshake at the session
                        // lifetime limit, or a glare resolution that swapped
                        // which session we kept.
                        //
                        // They carry on. Only the part that was keyed on the
                        // old session's packet numbers is rebuilt, and this is
                        // the right moment: the new session exists and has not
                        // carried a byte yet.
                        peer.streams->on_session_restart(now);
                    }
                    set_peer_state(ti, peer, PeerState::Connected);
                    break;
                }
                case K::Data:
                    // The leading byte says which transport this belongs to.
                    if (e->data.empty()) break;
                    if (e->data[0] == payload_kind::kStream && peer.streams) {
                        peer.streams->on_datagram(
                            e->packet_number,
                            std::span<const uint8_t>(e->data).subspan(1), now);
                    } else if (ti.on_data) {
                        deferred.push_back([cb = ti.on_data, dev = peer.dev_id,
                                            bytes = std::vector<uint8_t>(
                                                e->data.begin() + 1, e->data.end())] {
                            cb(dev, bytes);
                        });
                    }
                    break;
                case K::PathChanged:
                    break;
                case K::NeedsRehandshake:
                    // The path is still good; re-establish on it.
                    //
                    // peer.streams is deliberately KEPT. The session reached
                    // its lifetime limit -- the peer has not gone anywhere, so
                    // destroying its streams would abandon whatever was in
                    // flight, and silently: no event fires on this path, so an
                    // application would watch a transfer stop for no stated
                    // reason every fifteen minutes. They are re-based on the
                    // new session once it is established.
                    conns.erase(peer.sess->conn_id());
                    peer.sess.reset();
                    if (peer.relayed) start_relay_session(ti, tid, peer, now);
                    else if (!peer.cands.empty()) start_punch(ti, tid, peer, now);
                    break;
                case K::Closed: {
                    const PeerGone why = peer_gone_from(e->cause, e->peer_reason);
                    if (cfg.verbose) {
                        std::fprintf(stderr, "[uconnect] session closed peer=%s reason=%s\n",
                                     to_hex(peer.dev_id).substr(0, 8).c_str(),
                                     to_string(why));
                    }
                    conns.erase(peer.sess->conn_id());
                    peer.sess.reset();
                    peer.streams.reset();
                    if (ti.on_peer_closed) {
                        deferred.push_back(
                            [cb = ti.on_peer_closed, dev = peer.dev_id, why] { cb(dev, why); });
                    }
                    set_peer_state(ti, peer, PeerState::Closed);
                    break;
                }
            }
            if (!peer.sess) break;
        }

        if (peer.sess) drive_streams(ti, tid, peer, now);
        if (peer.sess) {
            while (auto o = peer.sess->poll_transmit()) send_to_peer(peer, o->to, o->data);
        }
    }
}

// Pump the stream layer: hand it the session packet number it is about to use,
// let it build a payload, then send that payload as one session datagram.
void Node::Impl::drive_streams(Topic::Impl& ti, const TopicId& tid, Peer& peer, Instant now) {
    if (!peer.streams || !peer.sess) return;
    if (peer.sess->state() != session::SessionState::Established) return;

    peer.streams->on_timeout(now);

    // Bounded per pass so one busy peer cannot starve the others on this loop
    // iteration; the congestion window is the real limit.
    //
    // Byte 0 carries the payload tag and the stream layer writes from byte 1,
    // so the receiver can tell stream frames from a raw application datagram.
    std::vector<uint8_t> buf(1200);
    buf[0] = payload_kind::kStream;
    for (int i = 0; i < 32; ++i) {
        // The stream layer records the packet number in its loss-recovery
        // tables, so it must know the number BEFORE building the payload that
        // will be acknowledged under it.
        const uint64_t pn = peer.sess->next_send_counter();
        size_t n = peer.streams->poll_datagram(pn, std::span(buf).subspan(1), now);
        if (n == 0) break;
        if (!peer.sess->send(std::span(buf).first(n + 1), now)) break;
        while (auto o = peer.sess->poll_transmit()) send_to_peer(peer, o->to, o->data);
    }

    while (auto e = peer.streams->poll_event()) {
        using K = stream::StreamEventKind;
        switch (e->kind) {
            case K::Opened:
                if (ti.on_stream) {
                    deferred.push_back([cb = ti.on_stream, dev = peer.dev_id, id = e->id] {
                        cb(dev, id);
                    });
                }
                break;
            case K::Readable:
                if (ti.on_stream_readable) {
                    deferred.push_back(
                        [cb = ti.on_stream_readable, dev = peer.dev_id, id = e->id] {
                            cb(dev, id);
                        });
                }
                break;
            case K::Finished:
                if (ti.on_stream_finished) {
                    deferred.push_back(
                        [cb = ti.on_stream_finished, dev = peer.dev_id, id = e->id] {
                            cb(dev, id);
                        });
                }
                break;
            case K::Writable:
                // Backpressure lifted. Without this an application that got a
                // short write from Stream::write had no way to learn the window
                // had reopened except by polling.
                if (ti.on_stream_writable) {
                    deferred.push_back(
                        [cb = ti.on_stream_writable, dev = peer.dev_id, id = e->id] {
                            cb(dev, id);
                        });
                }
                break;
            case K::Reset:
                // The peer aborted, or it overran our window and we tore the
                // stream down. Either way the bytes stop here and the
                // application has to be told, or the stream just goes quiet.
                if (ti.on_stream_reset) {
                    deferred.push_back([cb = ti.on_stream_reset, dev = peer.dev_id,
                                        id = e->id, code = e->error_code] {
                        cb(dev, id, code);
                    });
                }
                break;
            case K::Closed:
                if (ti.on_stream_closed) {
                    deferred.push_back(
                        [cb = ti.on_stream_closed, dev = peer.dev_id, id = e->id] {
                            cb(dev, id);
                        });
                }
                break;
            case K::ConnDead:
                if (peer.sess) peer.sess->close(now);
                break;
        }
    }
    (void)tid;
}

void Node::Impl::send_register(Topic::Impl& ti, const TopicId& tid, Instant now) {
    (void)now;
    uint32_t txn = alloc_txn();

    auto build = [this, &ti, tid, txn](const std::vector<uint8_t>& ck) {
        std::vector<uint8_t> buf(wire::kMaxDatagram);
        wire::Writer         w{buf};
        uint8_t flags = ti.unlisted ? wire::flags::kUnlisted : 0;
        wire::Header{wire::MsgType::Register, wire::kVersion, flags, txn}.encode(w);
        wire::Register m;
        m.id         = tid;
        m.mode       = ti.keyed ? TopicMode::Keyed : TopicMode::Open;
        m.unlisted   = ti.unlisted;
        m.host_cands = host_cands;
        m.meta       = ti.meta;
        m.cookie     = ck;
        m.encode(w);
        if (!w.ok()) return std::vector<uint8_t>{};
        buf.resize(w.size());
        return buf;
    };

    Pending p;
    p.expect  = wire::MsgType::RegisterOk;
    p.rebuild = build;
    pending[txn] = std::move(p);
    send_raw(server, build(cookie));
}

void Node::Impl::send_keepalive(Topic::Impl& ti, Instant now) {
    if (!ti.self) return;
    uint32_t txn = alloc_txn();

    std::vector<uint8_t> buf(wire::kMaxDatagram);
    wire::Writer         w{buf};
    wire::Header{wire::MsgType::Keepalive, wire::kVersion, 0, txn}.encode(w);
    wire::Keepalive k;
    k.dev_id   = *ti.self;
    k.auth.seq = ++ti.seq;
    k.encode_prefix(w);
    auto mac = compute_mac(ti.lease, w.written());
    w.array(mac);
    if (!w.ok()) return;
    buf.resize(w.size());

    Pending p;
    p.expect     = wire::MsgType::KeepaliveOk;
    pending[txn] = std::move(p);
    send_raw(server, buf);
    ti.next_keepalive = now + cfg.keepalive;
}

void Node::Impl::send_connect_relay(Topic::Impl& ti, const TopicId& tid, const DevId& to,
                                    Instant now) {
    (void)now;
    if (!ti.self) return;

    auto cands = host_cands;
    if (srflx) cands.insert(cands.begin(), Candidate{Candidate::Kind::Srflx, *srflx});

    uint32_t txn = alloc_txn();
    std::vector<uint8_t> buf(wire::kMaxDatagram);
    wire::Writer         w{buf};
    wire::Header{wire::MsgType::Connect, wire::kVersion, 0, txn}.encode(w);
    wire::Connect c;
    c.from_dev   = *ti.self;
    c.to_dev     = to;
    wire::RelayId offer = 0;
    if (auto pit = ti.peers.find(to); pit != ti.peers.end() && pit->second.relayed) {
        offer = pit->second.relay_id;
    }
    c.payload    = encode_relay_payload(tid, cands, offer);
    c.auth.seq   = ++ti.seq;
    c.encode_prefix(w);
    auto mac = compute_mac(ti.lease, w.written());
    w.array(mac);
    if (!w.ok()) return;
    buf.resize(w.size());
    send_raw(server, buf);
}

void Node::Impl::drive_topic(Topic::Impl& ti, const TopicId& tid, Instant now) {
    if (ti.published && ti.self && now >= ti.next_keepalive) send_keepalive(ti, now);

    // Auto-connect: one LOOKUP per interval, driven here rather than by the
    // application polling peers() in a loop.
    //
    // Every caller was writing that loop by hand -- both bundled examples did,
    // one of them every 20ms, which produced over a thousand lookups in ten
    // seconds. Rude against a shared rendezvous server, and exactly the work a
    // library should be doing.
    if (ti.auto_connect && ti.published && ti.self && now >= ti.next_discovery) {
        ti.next_discovery = now + kDiscoveryInterval;
        if (connected_count(ti) < ti.max_peers) discover(ti, tid, now);
    }

    for (auto& [dev, peer] : ti.peers) {
        (void)dev;

        // The other end was given a head start to offer a relay and has not.
        // Ask for one ourselves rather than waiting on it indefinitely.
        if (peer.relay_backup_at != Instant{} && now >= peer.relay_backup_at &&
            !peer.relay_asked && !peer.relayed && !peer.sess) {
            peer.relay_backup_at = Instant{};
            request_relay(ti, tid, peer, now);
        }

        drive_peer(ti, tid, peer, now);
    }
}

size_t Node::Impl::connected_count(const Topic::Impl& ti) const {
    size_t n = 0;
    for (const auto& [dev, peer] : ti.peers) {
        (void)dev;
        if (peer.sess || peer.punch) ++n;
    }
    return n;
}

size_t Node::Impl::total_peer_count() const {
    size_t n = 0;
    for (const auto& [id, topic] : topics) {
        (void)id;
        n += connected_count(*topic->impl_);
    }
    return n;
}

// Issue a LOOKUP whose result drives connections rather than returning to a
// caller. Asynchronous by necessity: peers() blocks until the reply arrives,
// and this runs on the very loop that would have to process it.
void Node::Impl::discover(Topic::Impl& ti, const TopicId& tid, Instant now) {
    (void)now;
    uint32_t txn = alloc_txn();

    auto build = [tid, txn](const std::vector<uint8_t>& ck) {
        std::vector<uint8_t> buf(wire::kMaxDatagram);
        wire::Writer         w{buf};
        wire::Header{wire::MsgType::Lookup, wire::kVersion, 0, txn}.encode(w);
        wire::Lookup m;
        m.id     = tid;
        m.max    = wire::kLookupDefault;
        m.cookie = ck;
        m.encode(w);
        if (!w.ok()) return std::vector<uint8_t>{};
        buf.resize(w.size());
        return buf;
    };

    Pending p;
    p.expect        = wire::MsgType::LookupOk;
    p.rebuild       = build;
    p.auto_discover = tid;
    pending[txn]    = std::move(p);
    send_raw(server, build(cookie));
    (void)ti;
}

// Start connecting to a peer. Assumes the node lock is held, so it can be
// called both from the public API and from the loop itself.
void Node::Impl::begin_connect(Topic::Impl& ti, const TopicId& tid, const DevId& dev,
                               Instant now) {
    auto it = ti.peers.find(dev);
    if (it == ti.peers.end() || it->second.cands.empty()) return;
    if (it->second.sess || it->second.punch || it->second.relayed) return;

    // Caps are enforced here rather than at the public API, so auto-connect and
    // an explicit connect() obey the same limits. Previously set_max_peers()
    // and max_total_peers stored a value that nothing ever read.
    if (connected_count(ti) >= ti.max_peers) return;
    if (total_peer_count() >= cfg.max_total_peers) return;

    if (cfg.verbose) {
        std::fprintf(stderr, "[uconnect] connect %s relay=%d self=%d cands=%zu\n",
                     to_hex(dev).substr(0, 8).c_str(), cfg.force_relay ? 1 : 0,
                     ti.self.has_value() ? 1 : 0, it->second.cands.size());
    }

    if (cfg.force_relay) {
        const bool first =
            ti.self && std::memcmp(ti.self->data(), dev.data(), kDevIdLen) < 0;
        if (first) {
            request_relay(ti, tid, it->second, now);
        } else {
            it->second.relay_backup_at = now + kRelayBackupDelay;
            set_peer_state(ti, it->second, PeerState::Probing);
        }
        return;
    }

    // Tell them to punch back at the same moment; without this they have no
    // reason to open their NAT toward us.
    send_connect_relay(ti, tid, dev, now);
    start_punch(ti, tid, it->second, now);
}

// ---------------------------------------------------------------------------
// Topic public API
// ---------------------------------------------------------------------------
Topic::Topic(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
Topic::~Topic() = default;

const TopicId& Topic::id() const { return impl_->creds.id; }
bool Topic::is_authenticated() const { return impl_->keyed; }

bool Topic::publish(std::span<const uint8_t> meta, bool unlisted) {
    auto& n = *impl_->node;
    std::unique_lock<std::mutex> lk(n.mu);

    impl_->meta.assign(meta.begin(), meta.end());
    impl_->unlisted = unlisted;

    uint32_t txn_before = n.next_txn;
    n.send_register(*impl_, impl_->creds.id, std::chrono::steady_clock::now());

    // Wait for RegisterOk (possibly after a Retry round trip).
    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline) {
        auto it = n.pending.find(txn_before);
        if (it != n.pending.end() && it->second.done) {
            bool ok = it->second.dev_id.has_value();
            if (ok) {
                impl_->self      = *it->second.dev_id;
                impl_->lease     = it->second.lease;
                impl_->seq       = 0;
                impl_->published = true;
                impl_->next_keepalive =
                    std::chrono::steady_clock::now() + n.cfg.keepalive;
            }
            n.pending.erase(it);
            return ok;
        }
        n.cv.wait_for(lk, 50ms);
    }
    n.pending.erase(txn_before);
    return false;
}

void Topic::unpublish() {
    auto& n = *impl_->node;
    std::lock_guard<std::mutex> lk(n.mu);
    if (!impl_->self) return;

    std::vector<uint8_t> buf(wire::kMaxDatagram);
    wire::Writer         w{buf};
    wire::Header{wire::MsgType::Unregister, wire::kVersion, 0, n.alloc_txn()}.encode(w);
    wire::Unregister u;
    u.dev_id   = *impl_->self;
    u.auth.seq = ++impl_->seq;
    u.encode_prefix(w);
    w.array(compute_mac(impl_->lease, w.written()));
    if (w.ok()) {
        buf.resize(w.size());
        n.send_raw(n.server, buf);
    }
    impl_->published = false;
    impl_->self.reset();
}

std::optional<DevId> Topic::self() const {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    return impl_->self;
}

std::vector<PeerInfo> Topic::peers(uint8_t max, bool want_meta,
                                   std::chrono::milliseconds timeout) {
    auto& n = *impl_->node;
    std::unique_lock<std::mutex> lk(n.mu);

    uint32_t txn = n.alloc_txn();
    TopicId  tid = impl_->creds.id;

    auto build = [tid, txn, max, want_meta](const std::vector<uint8_t>& ck) {
        std::vector<uint8_t> buf(wire::kMaxDatagram);
        wire::Writer         w{buf};
        uint8_t flags = want_meta ? wire::flags::kWantMeta : 0;
        wire::Header{wire::MsgType::Lookup, wire::kVersion, flags, txn}.encode(w);
        wire::Lookup m;
        m.id     = tid;
        m.max    = max;
        m.cookie = ck;
        m.encode(w);
        if (!w.ok()) return std::vector<uint8_t>{};
        buf.resize(w.size());
        return buf;
    };

    Pending p;
    p.expect     = wire::MsgType::LookupOk;
    p.rebuild    = build;
    n.pending[txn] = std::move(p);
    n.send_raw(n.server, build(n.cookie));

    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        auto it = n.pending.find(txn);
        if (it != n.pending.end() && it->second.done) break;
        n.cv.wait_for(lk, 50ms);
    }

    std::vector<PeerInfo> out;
    auto it = n.pending.find(txn);
    if (it != n.pending.end()) {
        out = std::move(it->second.peers);
        n.pending.erase(it);
    }
    // Never return ourselves: our own record is in the topic too, and punching
    // it wastes attempts and produces confusing self-connections.
    if (impl_->self) {
        std::erase_if(out, [&](const PeerInfo& pi) { return pi.dev_id == *impl_->self; });
    }
    return out;
}

std::optional<PeerInfo> Topic::resolve(const DevId& dev, std::chrono::milliseconds timeout) {
    auto& n = *impl_->node;
    std::unique_lock<std::mutex> lk(n.mu);

    uint32_t txn = n.alloc_txn();

    auto build = [dev, txn](const std::vector<uint8_t>& ck) {
        std::vector<uint8_t> buf(wire::kMaxDatagram);
        wire::Writer         w{buf};
        wire::Header{wire::MsgType::Resolve, wire::kVersion, 0, txn}.encode(w);
        wire::Resolve m;
        m.dev_id = dev;
        m.cookie = ck;
        m.encode(w);
        if (!w.ok()) return std::vector<uint8_t>{};
        buf.resize(w.size());
        return buf;
    };

    Pending p;
    p.expect       = wire::MsgType::ResolveOk;
    p.rebuild      = build;
    n.pending[txn] = std::move(p);
    n.send_raw(n.server, build(n.cookie));

    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        auto it = n.pending.find(txn);
        if (it != n.pending.end() && it->second.done) break;
        n.cv.wait_for(lk, 50ms);
    }

    std::optional<PeerInfo> out;
    auto it = n.pending.find(txn);
    if (it != n.pending.end()) {
        out = it->second.one;
        n.pending.erase(it);
    }
    return out;
}

void Topic::connect(const DevId& dev) {
    auto& n = *impl_->node;
    std::lock_guard<std::mutex> lk(n.mu);
    n.begin_connect(*impl_, impl_->creds.id, dev,
                    std::chrono::steady_clock::now());
}

void Topic::connect_all(size_t max_peers) {
    auto list = peers(static_cast<uint8_t>(std::min<size_t>(max_peers * 2, 100)));
    size_t started = 0;
    for (const auto& pi : list) {
        if (started >= max_peers) break;
        if (pi.stale) continue;
        connect(pi.dev_id);
        ++started;
    }
}

// Shared by disconnect() and disconnect_all(). The reason is a parameter so a
// node that is exiting can say so, rather than looking to every peer like an
// application that happened to drop one connection. Caller holds the lock.
void Topic::drop_peer_locked(const DevId& dev, uint16_t reason) {
    auto& n  = *impl_->node;
    auto  it = impl_->peers.find(dev);
    if (it == impl_->peers.end()) return;
    if (it->second.sess) {
        // Queue the notice, then drain: close_with_notice() seals it before
        // tearing down, because close() clears the send keys.
        it->second.sess->close_with_notice(reason, std::chrono::steady_clock::now());
        while (auto o = it->second.sess->poll_transmit()) n.send_raw(o->to, o->data);
        n.conns.erase(it->second.sess->conn_id());
    }
    impl_->peers.erase(it);
}

void Topic::disconnect(const DevId& dev) {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    drop_peer_locked(dev, wire::close_reason::kGoingAway);
}

void Topic::disconnect_all() { disconnect_all_with_reason(wire::close_reason::kGoingAway); }

void Topic::disconnect_all_with_reason(uint16_t reason) {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    std::vector<DevId> all;
    all.reserve(impl_->peers.size());
    for (auto& [dev, peer] : impl_->peers) {
        (void)peer;
        all.push_back(dev);
    }
    for (const auto& d : all) drop_peer_locked(d, reason);
}

std::optional<LinkInfo> Topic::link(const DevId& dev) const {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    auto it = impl_->peers.find(dev);
    if (it == impl_->peers.end() || !it->second.sess) return std::nullopt;
    const auto& p = it->second;

    LinkInfo li;
    li.relayed            = p.relayed;
    li.datagrams_sent     = p.sess->messages_sent();
    li.datagrams_received = p.sess->messages_received();

    // The stream layer only exists once the handshake completes, and it is
    // where the path measurements live -- the session deliberately keeps no
    // timers of its own beyond liveness.
    if (p.streams) {
        li.rtt = std::chrono::duration_cast<std::chrono::milliseconds>(
            p.streams->smoothed_rtt());
        li.congestion_window = p.streams->congestion_window();
        li.bytes_in_flight   = p.streams->bytes_in_flight();
        li.slow_start        = p.streams->in_slow_start();
        li.packets_sent      = p.streams->packets_sent();
        li.packets_lost      = p.streams->packets_lost();
        li.open_streams      = p.streams->active_streams().size();
    }
    return li;
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

bool Topic::send(const DevId& dev, std::span<const uint8_t> payload) {
    auto& n = *impl_->node;
    std::lock_guard<std::mutex> lk(n.mu);
    auto it = impl_->peers.find(dev);
    if (it == impl_->peers.end() || !it->second.sess) return false;
    auto now = std::chrono::steady_clock::now();

    std::vector<uint8_t> framed;
    framed.reserve(payload.size() + 1);
    framed.push_back(payload_kind::kDatagram);
    framed.insert(framed.end(), payload.begin(), payload.end());
    if (!it->second.sess->send(framed, now)) return false;
    while (auto o = it->second.sess->poll_transmit()) n.send_raw(o->to, o->data);
    return true;
}

size_t Topic::broadcast(std::span<const uint8_t> payload) {
    std::vector<DevId> targets = connected();
    size_t             sent    = 0;
    for (const auto& d : targets) {
        if (send(d, payload)) ++sent;
    }
    return sent;
}

void Topic::on_peer(std::function<void(DevId, PeerState)> cb) {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    impl_->on_peer = std::move(cb);
}

void Topic::on_data(std::function<void(DevId, std::span<const uint8_t>)> cb) {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    impl_->on_data = std::move(cb);
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
    auto it = impl_->peers.find(dev);
    if (it == impl_->peers.end() || !it->second.sess) return std::nullopt;
    if (it->second.state != PeerState::Connected) return std::nullopt;
    return it->second.sess->sas();
}

std::optional<std::array<uint8_t, 32>> Topic::channel_binding(const DevId& dev) const {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    auto it = impl_->peers.find(dev);
    if (it == impl_->peers.end() || !it->second.sess) return std::nullopt;
    if (it->second.state != PeerState::Connected) return std::nullopt;
    return it->second.sess->handshake_hash();
}

// ---------------------------------------------------------------------------
// Node public API
// ---------------------------------------------------------------------------
Node::Node(Config cfg) : impl_(std::make_unique<Impl>()) {
    impl_->cfg = std::move(cfg);
    io::init_networking();

    if (!impl_->sock.open(impl_->cfg.bind_port)) {
        throw std::runtime_error("uconnect: failed to bind UDP socket: " +
                                 impl_->sock.last_error());
    }
    auto server = io::resolve(impl_->cfg.server);
    if (!server) {
        throw std::runtime_error("uconnect: cannot resolve server address: " +
                                 impl_->cfg.server);
    }
    impl_->server = *server;
    impl_->gather_host_candidates();
}

Node::Node(std::string server) : Node(Config{std::move(server)}) {}

Node::~Node() { shutdown(); }

Topic& Node::join(const TopicCreds& creds) {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->topics.find(creds.id);
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

std::vector<TopicSummary> Node::explore(size_t limit, std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lk(impl_->mu);
    uint32_t                     txn = impl_->alloc_txn();

    auto build = [txn, limit](const std::vector<uint8_t>& ck) {
        std::vector<uint8_t> buf(wire::kMaxDatagram);
        wire::Writer         w{buf};
        wire::Header{wire::MsgType::Topics, wire::kVersion, 0, txn}.encode(w);
        wire::Topics m;
        m.limit  = static_cast<uint8_t>(std::min<size_t>(limit, 255));
        m.cookie = ck;
        m.encode(w);
        if (!w.ok()) return std::vector<uint8_t>{};
        buf.resize(w.size());
        return buf;
    };

    Pending p;
    p.expect           = wire::MsgType::TopicsOk;
    p.rebuild          = build;
    impl_->pending[txn] = std::move(p);
    impl_->send_raw(impl_->server, build(impl_->cookie));

    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        auto it = impl_->pending.find(txn);
        if (it != impl_->pending.end() && it->second.done) break;
        impl_->cv.wait_for(lk, 50ms);
    }

    std::vector<TopicSummary> out;
    auto                      it = impl_->pending.find(txn);
    if (it != impl_->pending.end()) {
        out = std::move(it->second.summaries);
        impl_->pending.erase(it);
    }
    return out;
}

std::optional<ServerStats> Node::stats(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lk(impl_->mu);
    uint32_t                     txn = impl_->alloc_txn();

    auto build = [txn](const std::vector<uint8_t>& ck) {
        std::vector<uint8_t> buf(wire::kMaxDatagram);
        wire::Writer         w{buf};
        wire::Header{wire::MsgType::Stats, wire::kVersion, 0, txn}.encode(w);
        wire::Stats m;
        m.cookie = ck;
        m.encode(w);
        if (!w.ok()) return std::vector<uint8_t>{};
        buf.resize(w.size());
        return buf;
    };

    Pending p;
    p.expect            = wire::MsgType::StatsOk;
    p.rebuild           = build;
    impl_->pending[txn] = std::move(p);
    impl_->send_raw(impl_->server, build(impl_->cookie));

    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        auto it = impl_->pending.find(txn);
        if (it != impl_->pending.end() && it->second.done) break;
        impl_->cv.wait_for(lk, 50ms);
    }

    std::optional<ServerStats> out;
    auto                       it = impl_->pending.find(txn);
    if (it != impl_->pending.end()) {
        out = it->second.stats;
        impl_->pending.erase(it);
    }
    return out;
}

void Node::run() { impl_->loop(); }

void Node::run_in_background() {
    if (impl_->running) return;
    impl_->stop   = false;
    impl_->thread = std::thread([this] { impl_->loop(); });
    // Let the loop reach its first wait so callers can immediately publish.
    for (int i = 0; i < 100 && !impl_->running; ++i) std::this_thread::sleep_for(1ms);
}

void Node::shutdown() {
    if (!impl_) return;

    // UNREGISTER explicitly: records would expire in 90s anyway, but a
    // restarting node should not leave a corpse for peers to waste punches on.
    std::vector<Topic*> all;
    {
        std::lock_guard<std::mutex> lk(impl_->mu);
        for (auto& [id, t] : impl_->topics) {
            (void)id;
            all.push_back(t.get());
        }
    }
    for (auto* t : all) {
        t->unpublish();
        t->disconnect_all_with_reason(wire::close_reason::kShutdown);
    }

    impl_->stop = true;
    if (impl_->thread.joinable()) impl_->thread.join();

    std::lock_guard<std::mutex> lk(impl_->mu);
    impl_->topics.clear();
    impl_->conns.clear();
    impl_->pending.clear();
}

bool     Node::is_running() const { return impl_->running; }
uint16_t Node::local_port() const { return impl_->sock.local_port(); }

std::optional<Endpoint> Node::reflexive() const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    return impl_->srflx;
}


// ---------------------------------------------------------------------------
// Streams
// ---------------------------------------------------------------------------
namespace {

// Every Stream operation funnels through here: find the peer, confirm the
// stream layer is up, then run `fn`. A handle to a peer that has since
// disconnected simply reports nothing rather than dangling.
using PeerMap = std::unordered_map<DevId, Peer, ArrayHash>;

template <typename R, typename F>
R with_stream(PeerMap& peers, const DevId& dev, R fallback, F&& fn) {
    auto it = peers.find(dev);
    if (it == peers.end() || !it->second.streams) return fallback;
    return fn(*it->second.streams);
}

}  // namespace

size_t Stream::write(std::span<const uint8_t> data) {
    if (!topic_) return 0;
    auto& ti = *topic_->impl_;
    auto& n  = *ti.node;
    std::lock_guard<std::mutex> lk(n.mu);

    size_t wrote = with_stream<size_t>(ti.peers, peer_, size_t{0},
                                       [&](auto& sc) { return sc.write(id_, data); });

    // Push it out now rather than waiting for the next loop tick, so a small
    // request/response exchange does not pay an extra 20ms of latency.
    if (wrote > 0) {
        auto it = ti.peers.find(peer_);
        if (it != ti.peers.end()) {
            n.drive_streams(ti, ti.creds.id, it->second, std::chrono::steady_clock::now());
        }
    }
    return wrote;
}

size_t Stream::read(std::span<uint8_t> out) {
    if (!topic_) return 0;
    std::lock_guard<std::mutex> lk(topic_->impl_->node->mu);
    return with_stream<size_t>(topic_->impl_->peers, peer_, size_t{0},
                               [&](auto& sc) { return sc.read(id_, out); });
}

void Stream::finish() {
    if (!topic_) return;
    std::lock_guard<std::mutex> lk(topic_->impl_->node->mu);
    with_stream<int>(topic_->impl_->peers, peer_, 0, [&](auto& sc) {
        sc.finish(id_);
        return 0;
    });
}

void Stream::reset(uint64_t code) {
    if (!topic_) return;
    std::lock_guard<std::mutex> lk(topic_->impl_->node->mu);
    with_stream<int>(topic_->impl_->peers, peer_, 0, [&](auto& sc) {
        sc.reset(id_, code);
        return 0;
    });
}

void Stream::stop_sending(uint64_t code) {
    if (!topic_) return;
    std::lock_guard<std::mutex> lk(topic_->impl_->node->mu);
    with_stream<int>(topic_->impl_->peers, peer_, 0, [&](auto& sc) {
        sc.stop_sending(id_, code);
        return 0;
    });
}

void Stream::close(uint64_t code) {
    if (!topic_) return;
    std::lock_guard<std::mutex> lk(topic_->impl_->node->mu);
    with_stream<int>(topic_->impl_->peers, peer_, 0, [&](auto& sc) {
        sc.close(id_, code);
        return 0;
    });
}

bool Stream::readable() const {
    if (!topic_) return false;
    std::lock_guard<std::mutex> lk(topic_->impl_->node->mu);
    return with_stream<bool>(topic_->impl_->peers, peer_, false,
                             [&](auto& sc) { return sc.readable(id_); });
}

size_t Stream::readable_bytes() const {
    if (!topic_) return 0;
    std::lock_guard<std::mutex> lk(topic_->impl_->node->mu);
    return with_stream<size_t>(topic_->impl_->peers, peer_, size_t{0},
                               [&](auto& sc) { return sc.readable_bytes(id_); });
}

bool Stream::writable() const {
    if (!topic_) return false;
    std::lock_guard<std::mutex> lk(topic_->impl_->node->mu);
    return with_stream<bool>(topic_->impl_->peers, peer_, false,
                             [&](auto& sc) { return sc.writable(id_); });
}

bool Stream::finished() const {
    if (!topic_) return false;
    std::lock_guard<std::mutex> lk(topic_->impl_->node->mu);
    return with_stream<bool>(topic_->impl_->peers, peer_, false,
                             [&](auto& sc) { return sc.finished(id_); });
}

Stream Topic::open_stream(const DevId& dev, bool bidirectional) {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    auto it = impl_->peers.find(dev);
    // Streams need an established session: the stream layer is created when the
    // handshake completes, because its role depends on which side initiated.
    if (it == impl_->peers.end() || !it->second.streams) return Stream{};
    // Nullopt means this peer already has max_concurrent_streams open; the
    // caller gets an invalid handle, same as for an unconnected peer.
    auto id = it->second.streams->open(bidirectional);
    if (!id) return Stream{};
    return Stream{this, dev, *id};
}

Stream Topic::stream(const DevId& dev, StreamId id) {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    auto it = impl_->peers.find(dev);
    if (it == impl_->peers.end() || !it->second.streams) return Stream{};
    if (!it->second.streams->exists(id)) return Stream{};
    return Stream{this, dev, id};
}

std::vector<StreamId> Topic::streams(const DevId& dev) const {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    auto it = impl_->peers.find(dev);
    if (it == impl_->peers.end() || !it->second.streams) return {};
    return it->second.streams->active_streams();
}

void Topic::on_stream(std::function<void(Stream)> cb) {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    impl_->on_stream = [this, cb = std::move(cb)](DevId dev, uint64_t id) {
        cb(Stream{this, dev, id});
    };
}

void Topic::on_stream_readable(std::function<void(Stream)> cb) {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    impl_->on_stream_readable = [this, cb = std::move(cb)](DevId dev, uint64_t id) {
        cb(Stream{this, dev, id});
    };
}

void Topic::on_stream_finished(std::function<void(Stream)> cb) {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    impl_->on_stream_finished = [this, cb = std::move(cb)](DevId dev, uint64_t id) {
        cb(Stream{this, dev, id});
    };
}

void Topic::on_stream_writable(std::function<void(Stream)> cb) {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    impl_->on_stream_writable = [this, cb = std::move(cb)](DevId dev, uint64_t id) {
        cb(Stream{this, dev, id});
    };
}

void Topic::on_stream_reset(std::function<void(Stream, uint64_t)> cb) {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    impl_->on_stream_reset = [this, cb = std::move(cb)](DevId dev, uint64_t id,
                                                        uint64_t code) {
        cb(Stream{this, dev, id}, code);
    };
}

void Topic::on_peer_closed(std::function<void(DevId, PeerGone)> cb) {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    impl_->on_peer_closed = std::move(cb);
}

void Topic::on_stream_closed(std::function<void(Stream)> cb) {
    std::lock_guard<std::mutex> lk(impl_->node->mu);
    impl_->on_stream_closed = [this, cb = std::move(cb)](DevId dev, uint64_t id) {
        cb(Stream{this, dev, id});
    };
}
}  // namespace uconnect
