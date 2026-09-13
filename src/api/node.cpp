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

#include <atomic>
#include <condition_variable>
#include <cstring>
#include <map>
#include <mutex>
#include <thread>
#include <unordered_map>

#include "kdf.hpp"
#include "messages.hpp"
#include "noise.hpp"
#include "primitives.hpp"
#include "punch.hpp"
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

constexpr auto kProbeMemory = 30s;  // how long an answered probe_txn stays usable

}  // namespace

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
    DevId                                dev_id{};
    std::vector<Candidate>               cands;
    std::optional<path::PunchSession>    punch;
    std::optional<session::Session>      sess;
    PeerState                            state = PeerState::Unknown;
};

// A pending server request awaiting its reply.
struct Pending {
    wire::MsgType expect{};
    // Rebuilds the request with a Retry cookie, so address validation costs one
    // extra round trip and no bookkeeping at the call site.
    std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)> rebuild;

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
    bool                 listed    = false;
    std::vector<uint8_t> meta;
    Instant              next_keepalive{};

    std::unordered_map<DevId, Peer, ArrayHash> peers;
    size_t                                     max_peers    = 8;
    bool                                       auto_connect = false;

    std::function<void(DevId, PeerState)>                       on_peer;
    std::function<void(DevId, std::span<const uint8_t>)>        on_data;

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

    std::thread       thread;
    std::atomic<bool> running{false};
    std::atomic<bool> stop{false};

    // --- helpers ----------------------------------------------------------
    void log(const char* fmt, ...) const;
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
std::vector<uint8_t> encode_relay_payload(const TopicId& topic,
                                          const std::vector<Candidate>& cands) {
    std::vector<uint8_t> buf(wire::kMaxRelayPayload);
    wire::Writer         w{buf};
    w.array(topic);
    size_t n = std::min<size_t>(cands.size(), wire::kMaxCandidates);
    w.u8(static_cast<uint8_t>(n));
    for (size_t i = 0; i < n; ++i) w.candidate(cands[i]);
    if (!w.ok()) return {};
    buf.resize(w.size());
    return buf;
}

bool decode_relay_payload(std::span<const uint8_t> p, TopicId& topic,
                          std::vector<Candidate>& cands) {
    wire::Reader r{p};
    topic    = r.array<kTopicIdLen>();
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

        for (int i = 0; i < 256; ++i) {
            auto got = sock.recv_from(buf);
            if (!got) break;
            auto now = std::chrono::steady_clock::now();
            std::lock_guard<std::mutex> lk(mu);
            dispatch(got->from, std::span(buf).first(got->len), now);
        }

        auto now = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> lk(mu);
        pump(now);
    }
    running = false;
}

void Node::Impl::pump(Instant now) {
    for (auto& [tid, topic] : topics) drive_topic(*topic->impl_, tid, now);

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

    // Relayed arrives from the server but is not a reply to anything we sent.
    if (h->type == wire::MsgType::Relayed) {
        auto rel = wire::Relayed::decode(r);
        if (!rel) return;

        TopicId                topic{};
        std::vector<Candidate> cands;
        if (!decode_relay_payload(rel->payload, topic, cands)) return;

        auto tit = topics.find(topic);
        if (tit == topics.end()) return;
        auto& ti = *tit->second->impl_;

        // The peer is about to punch us. Punch back now -- this is the
        // simultaneity the whole thing depends on.
        auto& peer  = ti.peers[rel->from_dev];
        peer.dev_id = rel->from_dev;
        if (!peer.cands.empty()) peer.cands.clear();
        peer.cands = cands;
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
            p.done  = true;
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

        // Attach to the peer we were already punching on this path, if any.
        DevId owner = placeholder;
        for (auto& [dev, peer] : ti.peers) {
            if (peer.punch && peer.punch->nominated_path() &&
                *peer.punch->nominated_path() == from) {
                owner = dev;
                break;
            }
            for (const auto& c : peer.cands) {
                if (c.ep == from) { owner = dev; break; }
            }
        }

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
    if (ti.on_peer) ti.on_peer(peer.dev_id, s);
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
                auto s = session::Session::initiate(session::SessionConfig{}, tid, 0, ti.psk(),
                                                    peer.dev_id, e->path, e->txn, now);
                conns[s.conn_id()] = {tid, peer.dev_id};
                peer.sess          = std::move(s);
                peer.punch.reset();
                set_peer_state(ti, peer, PeerState::Handshaking);
                break;
            }
            if (e->kind == path::PunchEvent::Kind::Failed) {
                peer.punch.reset();
                set_peer_state(ti, peer, PeerState::Failed);
                break;
            }
        }
    }

    if (peer.sess) {
        peer.sess->on_timeout(now);
        while (auto o = peer.sess->poll_transmit()) send_raw(o->to, o->data);

        while (auto e = peer.sess->poll_event()) {
            using K = session::SessionEvent::Kind;
            switch (e->kind) {
                case K::Established:
                    set_peer_state(ti, peer, PeerState::Connected);
                    break;
                case K::Data:
                    if (ti.on_data) ti.on_data(peer.dev_id, e->data);
                    break;
                case K::PathChanged:
                    break;
                case K::NeedsRehandshake:
                    // The path is still good; re-punch and handshake afresh.
                    conns.erase(peer.sess->conn_id());
                    peer.sess.reset();
                    if (!peer.cands.empty()) start_punch(ti, tid, peer, now);
                    break;
                case K::Closed:
                    conns.erase(peer.sess->conn_id());
                    peer.sess.reset();
                    set_peer_state(ti, peer, PeerState::Closed);
                    break;
            }
            if (!peer.sess) break;
        }
        if (peer.sess) {
            while (auto o = peer.sess->poll_transmit()) send_raw(o->to, o->data);
        }
    }
}

void Node::Impl::send_register(Topic::Impl& ti, const TopicId& tid, Instant now) {
    (void)now;
    uint32_t txn = alloc_txn();

    auto build = [this, &ti, tid, txn](const std::vector<uint8_t>& ck) {
        std::vector<uint8_t> buf(wire::kMaxDatagram);
        wire::Writer         w{buf};
        uint8_t flags = ti.listed ? wire::flags::kListed : 0;
        wire::Header{wire::MsgType::Register, wire::kVersion, flags, txn}.encode(w);
        wire::Register m;
        m.id         = tid;
        m.mode       = ti.keyed ? TopicMode::Keyed : TopicMode::Open;
        m.listed     = ti.listed;
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
    c.payload    = encode_relay_payload(tid, cands);
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

    for (auto& [dev, peer] : ti.peers) {
        (void)dev;
        drive_peer(ti, tid, peer, now);
    }
}

// ---------------------------------------------------------------------------
// Topic public API
// ---------------------------------------------------------------------------
Topic::Topic(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
Topic::~Topic() = default;

const TopicId& Topic::id() const { return impl_->creds.id; }
bool Topic::is_authenticated() const { return impl_->keyed; }

bool Topic::publish(std::span<const uint8_t> meta, bool listed) {
    auto& n = *impl_->node;
    std::unique_lock<std::mutex> lk(n.mu);

    impl_->meta.assign(meta.begin(), meta.end());
    impl_->listed = listed;

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
    std::vector<uint8_t> buf(wire::kMaxDatagram);
    wire::Writer         w{buf};
    wire::Header{wire::MsgType::Resolve, wire::kVersion, 0, txn}.encode(w);
    wire::Resolve{dev}.encode(w);
    buf.resize(w.size());

    Pending p;
    p.expect       = wire::MsgType::ResolveOk;
    n.pending[txn] = std::move(p);
    n.send_raw(n.server, buf);

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

    auto it = impl_->peers.find(dev);
    if (it == impl_->peers.end() || it->second.cands.empty()) return;
    if (it->second.sess || it->second.punch) return;

    auto now = std::chrono::steady_clock::now();
    // Tell them to punch back at the same moment; without this they have no
    // reason to open their NAT toward us.
    n.send_connect_relay(*impl_, impl_->creds.id, dev, now);
    n.start_punch(*impl_, impl_->creds.id, it->second, now);
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

void Topic::disconnect(const DevId& dev) {
    auto& n = *impl_->node;
    std::lock_guard<std::mutex> lk(n.mu);
    auto it = impl_->peers.find(dev);
    if (it == impl_->peers.end()) return;
    if (it->second.sess) {
        it->second.sess->close(std::chrono::steady_clock::now());
        while (auto o = it->second.sess->poll_transmit()) n.send_raw(o->to, o->data);
        n.conns.erase(it->second.sess->conn_id());
    }
    impl_->peers.erase(it);
}

void Topic::disconnect_all() {
    std::vector<DevId> all;
    {
        std::lock_guard<std::mutex> lk(impl_->node->mu);
        for (auto& [dev, peer] : impl_->peers) {
            (void)peer;
            all.push_back(dev);
        }
    }
    for (const auto& d : all) disconnect(d);
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
    if (!it->second.sess->send(payload, now)) return false;
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

    std::vector<uint8_t> buf(wire::kMaxDatagram);
    wire::Writer         w{buf};
    wire::Header{wire::MsgType::Stats, wire::kVersion, 0, txn}.encode(w);
    buf.resize(w.size());

    Pending p;
    p.expect            = wire::MsgType::StatsOk;
    impl_->pending[txn] = std::move(p);
    impl_->send_raw(impl_->server, buf);

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
        t->disconnect_all();
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

}  // namespace uconnect
