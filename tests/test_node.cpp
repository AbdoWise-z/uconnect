// Node-level tests: the public API, where configuration arrives from the
// application and the sans-IO layers meet a real socket.
//
// Two kinds. Configuration checks run offline: construction validates before it
// opens a socket or resolves anything. Behaviour checks run real Nodes over
// loopback against a rendezvous server hosted in-process (LocalServer below),
// built from the same Store and UdpService the real server binary uses.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

#include "messages.hpp"
#include "primitives.hpp"
#include "session.hpp"
#include "socket.hpp"
#include "testing.hpp"
#include "udp_service.hpp"
#include "uconnect/uconnect.hpp"

using namespace uconnect;
using namespace std::chrono_literals;

namespace {

// A rendezvous server on 127.0.0.1, on its own thread. It is the real server
// logic -- Store and UdpService -- with two knobs the real network has and a
// test needs to control: a restart that forgets everything, and latency.
class LocalServer {
public:
    explicit LocalServer(server::StoreConfig scfg = {}) : scfg_(scfg) {
        if (!sock_.open(0, "127.0.0.1")) throw std::runtime_error("LocalServer: bind failed");
        reset_state();
        thread_ = std::thread([this] { run(); });
    }
    ~LocalServer() {
        stop_ = true;
        thread_.join();
    }
    LocalServer(const LocalServer&)            = delete;
    LocalServer& operator=(const LocalServer&) = delete;

    std::string address() const { return "127.0.0.1:" + std::to_string(sock_.local_port()); }

    // Forget every record, lease and relay binding: what a process restart
    // does to a server that keeps everything in memory.
    void restart() {
        std::lock_guard<std::mutex> lk(mu_);
        reset_state();
    }

    // Hold every datagram the server sends for this long -- one-way latency
    // on the server's side of the path.
    void set_reply_delay(std::chrono::milliseconds d) {
        std::lock_guard<std::mutex> lk(mu_);
        delay_ = d;
    }

    server::Stats stats() {
        std::lock_guard<std::mutex> lk(mu_);
        return store_->stats(std::chrono::steady_clock::now());
    }

    // Drop incoming datagrams for which `f` returns true -- a lossy path on
    // the server's side, aimed at exactly the packet a test cares about.
    void set_drop(std::function<bool(std::span<const uint8_t>)> f) {
        std::lock_guard<std::mutex> lk(mu_);
        drop_ = std::move(f);
    }

private:
    struct Held {
        Instant              at;
        Endpoint             to;
        std::vector<uint8_t> data;
    };

    void reset_state() {
        svc_.reset();
        store_ = std::make_unique<server::Store>(scfg_);
        svc_   = std::make_unique<server::UdpService>(*store_);
        held_.clear();
    }

    void run() {
        std::vector<uint8_t> buf(2048);
        auto last_tick = std::chrono::steady_clock::now();
        while (!stop_) {
            sock_.wait_readable(5ms);
            std::lock_guard<std::mutex> lk(mu_);
            const auto now = std::chrono::steady_clock::now();
            for (int i = 0; i < 256; ++i) {
                auto got = sock_.recv_from(buf);
                if (!got) break;
                if (drop_ && drop_(std::span(buf).first(got->len))) continue;
                for (auto& r : svc_->handle(got->from, std::span(buf).first(got->len), now)) {
                    if (!r.data.empty()) held_.push_back({now + delay_, r.to, std::move(r.data)});
                }
            }
            for (auto it = held_.begin(); it != held_.end();) {
                if (it->at <= now) {
                    sock_.send_to(it->to, it->data);
                    it = held_.erase(it);
                } else {
                    ++it;
                }
            }
            if (now - last_tick >= 1s) {
                svc_->tick(now);
                last_tick = now;
            }
        }
    }

    server::StoreConfig                 scfg_;
    io::UdpSocket                       sock_;
    std::mutex                          mu_;
    std::unique_ptr<server::Store>      store_;
    std::unique_ptr<server::UdpService> svc_;
    std::vector<Held>                   held_;
    std::chrono::milliseconds           delay_{0};
    std::function<bool(std::span<const uint8_t>)> drop_;
    std::atomic<bool>                   stop_{false};
    std::thread                         thread_;
};

template <typename F>
bool wait_until(F&& cond, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (cond()) return true;
        std::this_thread::sleep_for(20ms);
    }
    return cond();
}

Node::Config config_for(const LocalServer& srv, bool force_relay = false) {
    Node::Config c;
    c.server      = srv.address();
    c.force_relay = force_relay;
    return c;
}

// A client that speaks the wire protocol by hand, for playing the attacker: it
// can register, allocate a relay and send whatever bytes it likes, which a
// Node never would.
class RawClient {
public:
    explicit RawClient(const LocalServer& srv) {
        auto s = io::resolve(srv.address());
        if (!s || !sock_.open(0, "127.0.0.1")) throw std::runtime_error("RawClient: setup failed");
        server_ = *s;
    }

    void send_to(const Endpoint& to, std::span<const uint8_t> d) { sock_.send_to(to, d); }

    // Everything that arrives within `window`.
    std::vector<std::vector<uint8_t>> receive_for(std::chrono::milliseconds window) {
        std::vector<std::vector<uint8_t>> out;
        const auto deadline = std::chrono::steady_clock::now() + window;
        for (;;) {
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now());
            if (left.count() <= 0) break;
            if (auto d = recv(left)) out.push_back(std::move(*d));
        }
        return out;
    }

    // Register in `topic`, following the Retry round trip.
    bool register_in(const TopicId& topic) {
        auto reply = request([&](const std::vector<uint8_t>& cookie) {
            std::vector<uint8_t> buf(wire::kMaxDatagram);
            wire::Writer         w{buf};
            wire::Header{wire::MsgType::Register, wire::kVersion, 0, next_txn_}.encode(w);
            wire::Register m;
            m.id     = topic;
            m.mode   = TopicMode::Keyed;
            m.cookie = cookie;
            m.encode(w);
            buf.resize(std::max(w.size(), wire::kMinUnvalidatedRequest));
            return buf;
        });
        if (!reply) return false;
        wire::Reader r{*reply};
        auto h = wire::Header::decode(r);
        if (!h || h->type != wire::MsgType::RegisterOk) return false;
        auto ok = wire::RegisterOk::decode(r);
        if (!ok) return false;
        dev_   = ok->dev_id;
        lease_ = ok->lease_token;
        return true;
    }

    std::optional<wire::RelayId> relay_alloc(const DevId& peer) {
        auto reply = request([&](const std::vector<uint8_t>&) {
            std::vector<uint8_t> buf(wire::kMaxDatagram);
            wire::Writer         w{buf};
            wire::Header{wire::MsgType::RelayAlloc, wire::kVersion, 0, next_txn_}.encode(w);
            wire::RelayAlloc m;
            m.from_dev = dev_;
            m.peer_dev = peer;
            m.auth.seq = ++seq_;
            m.encode_prefix(w);
            auto      h = crypto::Blake2s::mac(lease_, w.written());
            wire::Mac mac{};
            std::memcpy(mac.data(), h.data(), wire::kMacLen);
            w.array(mac);
            buf.resize(w.size());
            return buf;
        });
        if (!reply) return std::nullopt;
        wire::Reader r{*reply};
        auto h = wire::Header::decode(r);
        if (!h || h->type != wire::MsgType::RelayAllocOk) return std::nullopt;
        auto ok = wire::RelayAllocOk::decode(r);
        if (!ok) return std::nullopt;
        return ok->relay_id;
    }

    void relay_data(wire::RelayId id, std::span<const uint8_t> payload) {
        std::vector<uint8_t> buf(wire::kMaxDatagram + 64);
        wire::Writer         w{buf};
        wire::Header{wire::MsgType::RelayData, wire::kVersion, 0, 0}.encode(w);
        wire::RelayData rd;
        rd.relay_id = id;
        rd.payload.assign(payload.begin(), payload.end());
        rd.encode(w);
        buf.resize(w.size());
        sock_.send_to(server_, buf);
    }

private:
    template <typename Build>
    std::optional<std::vector<uint8_t>> request(Build&& build) {
        std::vector<uint8_t> cookie;
        for (int attempt = 0; attempt < 3; ++attempt, ++next_txn_) {
            sock_.send_to(server_, build(cookie));
            auto reply = recv(1s);
            if (!reply) return std::nullopt;
            if (wire::peek_type(*reply) != wire::MsgType::Retry) return reply;
            wire::Reader r{*reply};
            wire::Header::decode(r);
            auto retry = wire::Retry::decode(r);
            if (!retry) return std::nullopt;
            cookie = retry->cookie;
        }
        return std::nullopt;
    }

    std::optional<std::vector<uint8_t>> recv(std::chrono::milliseconds timeout) {
        std::vector<uint8_t> buf(2048);
        if (!sock_.wait_readable(timeout)) return std::nullopt;
        auto got = sock_.recv_from(buf);
        if (!got) return std::nullopt;
        buf.resize(got->len);
        return buf;
    }

    io::UdpSocket    sock_;
    Endpoint         server_{};
    DevId            dev_{};
    wire::LeaseToken lease_{};
    uint64_t         seq_      = 0;
    uint32_t         next_txn_ = 1;
};

// A server-to-client Relayed message, as the server sends when another member
// CONNECTs: "`from` is punching you in `topic`" -- here also offering a relay,
// which makes the receiver stop probing and wait for a handshake on it.
std::vector<uint8_t> forged_relayed(const DevId& from, const TopicId& topic,
                                    wire::RelayId offer) {
    std::vector<uint8_t> payload(64);
    wire::Writer         pw{payload};
    pw.array(topic);
    pw.u64(offer);
    pw.u8(0);  // no candidates
    payload.resize(pw.size());

    std::vector<uint8_t> buf(wire::kMaxDatagram);
    wire::Writer         w{buf};
    wire::Header{wire::MsgType::Relayed, wire::kVersion, 0, 0}.encode(w);
    wire::Relayed rel;
    rel.from_dev = from;
    rel.payload  = payload;
    rel.encode(w);
    buf.resize(w.size());
    return buf;
}

// Two published members of one keyed topic, each told to connect to the other.
// Returns false if they do not both reach Connected in time.
bool connect_pair(Topic& a, Topic& b, std::chrono::milliseconds timeout = 20s) {
    if (!a.self() || !b.self()) return false;
    const DevId ida = *a.self(), idb = *b.self();
    (void)a.peers();  // learn the other's candidates
    (void)b.peers();
    a.connect(idb);
    b.connect(ida);
    return wait_until([&] {
        return a.state(idb) == PeerState::Connected && b.state(ida) == PeerState::Connected;
    }, timeout);
}

// Returns true if constructing a Node with this config is refused outright.
bool refused(Node::Config cfg) {
    try {
        Node n{std::move(cfg)};
        return false;
    } catch (const std::invalid_argument&) {
        return true;
    } catch (...) {
        return false;  // some other failure is not the validation under test
    }
}

}  // namespace

TEST(node_refuses_a_rekey_shift_outside_its_safe_range) {
    // #27. The documented rule is that a key generation must span more than
    // the 64-packet replay window, i.e. a shift of at least 7 -- that is what
    // bounds a reordered packet to one generation old. Below it, reordered
    // packets decrypt under the wrong key and vanish without a word; at 64 or
    // more the shift is undefined behaviour. Neither should be accepted
    // silently from an application.
    Node::Config cfg;
    cfg.server = "127.0.0.1:9";

    cfg.rekey_shift = 6;
    CHECK(refused(cfg));
    cfg.rekey_shift = 0;
    CHECK(refused(cfg));
    cfg.rekey_shift = 64;
    CHECK(refused(cfg));
    cfg.rekey_shift = 200;
    CHECK(refused(cfg));
}

TEST(node_accepts_the_boundaries_of_the_rekey_shift_range) {
    Node::Config cfg;
    cfg.server = "127.0.0.1:9";

    cfg.rekey_shift = 7;   // what the stream smoke test uses to cross boundaries
    CHECK(!refused(cfg));
    cfg.rekey_shift = 63;
    CHECK(!refused(cfg));
    cfg.rekey_shift = 16;  // the default
    CHECK(!refused(cfg));
}

// ---------------------------------------------------------------------------
// Behaviour over loopback, against a LocalServer
// ---------------------------------------------------------------------------
TEST(datagrams_reach_a_peer_over_the_relay) {
    // #6. On a relayed peer the session's path IS the rendezvous server, so
    // anything not wrapped in RelayData reaches the server raw and is dropped.
    // Streams went through the wrapper; Topic::send went straight to the socket
    // and returned true for datagrams that never arrived.
    LocalServer srv;
    Node na{config_for(srv, /*force_relay=*/true)};
    Node nb{config_for(srv, /*force_relay=*/true)};
    na.run_in_background();
    nb.run_in_background();

    const auto creds = TopicCreds::generate_keyed();
    Topic& a = na.join(creds);
    Topic& b = nb.join(creds);
    REQUIRE(a.publish());
    REQUIRE(b.publish());

    std::atomic<int> got{0};
    b.on_data([&](DevId, std::span<const uint8_t> d) {
        if (d.size() == 5 && d[0] == 'h') ++got;
    });

    REQUIRE(connect_pair(a, b));
    const DevId idb = *b.self();
    auto li = a.link(idb);
    REQUIRE(li.has_value());
    REQUIRE(li->relayed);

    const std::vector<uint8_t> hello{'h', 'e', 'l', 'l', 'o'};
    CHECK(a.send(idb, hello));
    CHECK(wait_until([&] { return got.load() > 0; }, 3s));
}

TEST(a_disconnect_notice_reaches_a_peer_over_the_relay) {
    // #6, the other casualty: close notices went out the same raw way, so a
    // relayed peer never heard the goodbye and sat out its idle timeout.
    LocalServer srv;
    Node na{config_for(srv, /*force_relay=*/true)};
    Node nb{config_for(srv, /*force_relay=*/true)};
    na.run_in_background();
    nb.run_in_background();

    const auto creds = TopicCreds::generate_keyed();
    Topic& a = na.join(creds);
    Topic& b = nb.join(creds);
    REQUIRE(a.publish());
    REQUIRE(b.publish());

    std::atomic<bool> told{false};
    b.on_peer_closed([&](DevId, PeerGone why) {
        if (why == PeerGone::GoingAway) told = true;
    });

    REQUIRE(connect_pair(a, b));
    a.disconnect(*b.self());
    CHECK(wait_until([&] { return told.load(); }, 3s));
}

TEST(a_node_registers_again_after_the_server_forgets_it) {
    // #7. The server keeps records in memory and forgets them all on a
    // restart -- which the deploy watcher does on every commit. The next
    // keepalive then fails with NotFound, and the node used to shrug: it
    // stayed "published", unfindable, and unable to authenticate anything.
    LocalServer srv;
    Node::Config cfg = config_for(srv);
    cfg.keepalive    = 1s;
    Node na{cfg};
    Node observer{config_for(srv)};
    na.run_in_background();
    observer.run_in_background();

    const auto creds = TopicCreds::generate_keyed();
    Topic& a = na.join(creds);
    Topic& o = observer.join(creds);  // looks, never publishes
    REQUIRE(a.publish());
    REQUIRE(o.peers().size() == 1);

    srv.restart();

    // Within a few keepalives A must be findable again. The restarted server
    // derives dev_ids from a new secret, so A's identity changes with it.
    CHECK(wait_until([&] {
        auto self  = a.self();
        auto found = o.peers(30, false, 500ms);
        return self && found.size() == 1 && found[0].dev_id == *self;
    }, 8s));
}

TEST(a_slow_server_path_does_not_leave_the_node_holding_a_stale_lease) {
    // #8. With the server's replies 300ms late, REGISTER -> Retry ->
    // REGISTER takes longer than the client's 400ms retransmit timer, so the
    // registration reaches the server twice. Each one used to mint a new
    // lease; the client kept the first reply, the server the second, and every
    // signed message after that was rejected.
    LocalServer srv;
    srv.set_reply_delay(300ms);
    Node::Config cfg = config_for(srv);
    cfg.keepalive    = 1s;
    Node na{cfg};
    na.run_in_background();

    Topic& a = na.join(TopicCreds::generate_keyed());
    REQUIRE(a.publish());

    std::this_thread::sleep_for(3500ms);  // three keepalives
    const auto st = srv.stats();
    CHECK(st.keepalives >= 2u);
    CHECK_EQ(st.rej_bad_auth, 0u);
}

TEST(requests_the_loop_issues_for_itself_are_retired) {
    // #9. Only the blocking calls (publish, peers, resolve, explore, stats)
    // erased their requests. Everything the loop issues on its own --
    // a keepalive every interval, a LOOKUP every discovery round -- stayed in
    // the table forever, and pump() walks the whole table every 20ms.
    LocalServer srv;
    Node::Config cfg = config_for(srv);
    cfg.keepalive    = 1s;
    Node na{cfg};
    na.run_in_background();

    Topic& a = na.join(TopicCreds::generate_keyed());
    a.set_auto_connect(true);
    REQUIRE(a.publish());

    // Six keepalives and at least one discovery LOOKUP, all answered.
    std::this_thread::sleep_for(6500ms);
    REQUIRE(srv.stats().keepalives >= 5u);
    CHECK(na.pending_requests() <= 2u);  // at most what is genuinely in flight
}

TEST(stats_and_explore_reach_a_server_that_refuses_to_amplify) {
    // #12, client side. A server that drops unvalidated requests too small to
    // answer without amplifying must still serve this client's Stats and
    // Topics -- which were the two requests small enough to be dropped.
    LocalServer srv;
    Node na{config_for(srv)};
    Node nb{config_for(srv)};
    na.run_in_background();
    nb.run_in_background();

    Topic& a = na.join(TopicCreds::generate_keyed());
    REQUIRE(a.publish());

    // A fresh node holds no cookie, so its first request of each kind is the
    // unvalidated one.
    auto st = nb.stats();
    REQUIRE(st.has_value());
    CHECK(st->entries_total >= 1u);
    CHECK(nb.explore().size() == 1u);
}

TEST(a_forged_server_message_from_another_address_is_ignored) {
    // #1. Signaling was accepted from any source address. Anyone who knew a
    // node's IP:port -- which LOOKUP hands to anyone holding the topic id --
    // could forge server messages: here a Relayed that invents a peer and
    // offers it a relay, which the node took at its word.
    LocalServer srv;
    Node na{config_for(srv)};
    na.run_in_background();
    const auto creds = TopicCreds::generate_keyed();
    Topic& a = na.join(creds);
    REQUIRE(a.publish());

    RawClient attacker{srv};
    DevId     ghost{};
    ghost.fill(0xEE);
    const Endpoint node_addr{IpAddr::v4(127, 0, 0, 1), na.local_port()};
    attacker.send_to(node_addr, forged_relayed(ghost, creds.id, 0x1234));

    std::this_thread::sleep_for(300ms);
    CHECK(a.state(ghost) == PeerState::Unknown);
}

TEST(a_relay_peer_cannot_smuggle_server_messages_inside_relay_data) {
    // #1, the other door. RelayData really does come from the server, but its
    // payload is whatever the peer at the other end of the binding put there,
    // and the node dispatched it as though the server had said it.
    LocalServer srv;
    Node na{config_for(srv)};
    na.run_in_background();
    const auto creds = TopicCreds::generate_keyed();
    Topic& a = na.join(creds);
    REQUIRE(a.publish());

    // The attacker joins the topic -- the server holds no keys, so anyone
    // knowing a topic id can -- and opens a relay binding to the node.
    RawClient attacker{srv};
    REQUIRE(attacker.register_in(creds.id));
    auto rid = attacker.relay_alloc(*a.self());
    REQUIRE(rid.has_value());

    DevId ghost{};
    ghost.fill(0xEF);
    attacker.relay_data(*rid, forged_relayed(ghost, creds.id, 0x1234));

    std::this_thread::sleep_for(300ms);
    CHECK(a.state(ghost) == PeerState::Unknown);
}

TEST(a_lost_handshake_response_is_answered_again_on_retransmit) {
    // #5. The glare tie-break could not tell a RETRANSMITTED HandshakeInit --
    // same conn_id as the session already accepted -- from a competing one.
    // When the responder held the smaller dev_id it kept "its" session and
    // ignored the init, so after a lost HandshakeResp nothing was ever sent
    // again: the initiator gave up, the responder showed Connected, and no
    // data could flow.
    LocalServer srv;
    Node na{config_for(srv, /*force_relay=*/true)};
    Node nb{config_for(srv, /*force_relay=*/true)};
    na.run_in_background();
    nb.run_in_background();

    const auto creds = TopicCreds::generate_keyed();
    Topic& t1 = na.join(creds);
    Topic& t2 = nb.join(creds);
    REQUIRE(t1.publish());
    REQUIRE(t2.publish());

    // Only the LARGER dev_id dials, so the smaller one is the responder.
    const bool one_is_smaller = std::memcmp(t1.self()->data(), t2.self()->data(), kDevIdLen) < 0;
    Topic& small = one_is_smaller ? t1 : t2;
    Topic& large = one_is_smaller ? t2 : t1;
    const DevId ids = *small.self(), idl = *large.self();

    // Lose the responder's first HandshakeResp on its way through the relay.
    std::atomic<int> dropped{0};
    srv.set_drop([&](std::span<const uint8_t> d) {
        wire::Reader r{d};
        auto h = wire::Header::decode(r);
        if (!h || h->type != wire::MsgType::RelayData) return false;
        auto rd = wire::RelayData::decode(r);
        if (!rd || wire::peek_type(rd->payload) != wire::MsgType::HandshakeResp) return false;
        return dropped.fetch_add(1) == 0;
    });

    (void)large.peers();
    large.connect(ids);

    // One retransmit of the init (5s) must be enough.
    CHECK(wait_until([&] {
        return large.state(ids) == PeerState::Connected && small.state(idl) == PeerState::Connected;
    }, 12s));
    CHECK(dropped.load() >= 1);

    // And it is a working connection, not just two ends saying so.
    std::atomic<bool> got{false};
    small.on_data([&](DevId, std::span<const uint8_t>) { got = true; });
    const std::vector<uint8_t> hi{'h', 'i'};
    large.send(ids, hi);
    CHECK(wait_until([&] { return got.load(); }, 3s));
}

namespace {

// A relayed pair where the SMALLER dev_id dials, so the larger one is the
// responder -- the side whose glare rule gives up its own session to an
// incoming handshake. The first HandshakeInit to cross the relay is captured
// on the way, for replaying.
struct ReplaySetup {
    LocalServer                srv;
    Node                       n1{config_for(srv, /*force_relay=*/true)};
    Node                       n2{config_for(srv, /*force_relay=*/true)};
    TopicCreds                 creds = TopicCreds::generate_keyed();
    Topic*                     small = nullptr;
    Topic*                     large = nullptr;
    Node*                      large_node = nullptr;
    std::mutex                 mu;
    std::vector<uint8_t>       captured_init;

    bool connect() {
        n1.run_in_background();
        n2.run_in_background();
        Topic& t1 = n1.join(creds);
        Topic& t2 = n2.join(creds);
        if (!t1.publish() || !t2.publish()) return false;
        const bool one_small = std::memcmp(t1.self()->data(), t2.self()->data(), kDevIdLen) < 0;
        small      = one_small ? &t1 : &t2;
        large      = one_small ? &t2 : &t1;
        large_node = one_small ? &n2 : &n1;

        srv.set_drop([this](std::span<const uint8_t> d) {
            wire::Reader r{d};
            auto h = wire::Header::decode(r);
            if (!h || h->type != wire::MsgType::RelayData) return false;
            auto rd = wire::RelayData::decode(r);
            if (!rd || wire::peek_type(rd->payload) != wire::MsgType::HandshakeInit) return false;
            std::lock_guard<std::mutex> lk(mu);
            if (captured_init.empty()) captured_init = rd->payload;
            return false;  // observe only
        });

        (void)small->peers();
        small->connect(*large->self());
        return wait_until([&] {
            return small->state(*large->self()) == PeerState::Connected &&
                   large->state(*small->self()) == PeerState::Connected;
        }, 10s);
    }

    // The captured init with its conn_id changed. The conn_id sits outside the
    // Noise message, so the handshake itself still verifies.
    std::vector<uint8_t> replay() {
        std::lock_guard<std::mutex> lk(mu);
        auto d = captured_init;
        if (d.size() > wire::Header::kSize) d[wire::Header::kSize] ^= 0x5A;
        return d;
    }

    // Both directions still carry data.
    bool still_works() {
        std::atomic<int> got{0};
        small->on_data([&](DevId, std::span<const uint8_t>) { ++got; });
        large->on_data([&](DevId, std::span<const uint8_t>) { ++got; });
        const std::vector<uint8_t> ping{'p'};
        small->send(*large->self(), ping);
        large->send(*small->self(), ping);
        return wait_until([&] { return got.load() >= 2; }, 3s);
    }
};

}  // namespace

TEST(a_handshake_init_replayed_from_another_address_is_refused) {
    // #13. The probe_txn gate checked that the txn was one we had answered,
    // but not WHO we answered it for -- so anyone who saw an init could send
    // it again from anywhere for 30 seconds. Accepted, it cost a DH, and on
    // the larger dev_id the glare rule then swapped the live session for the
    // replay's, whose initiator holds no matching keys: connection dead.
    ReplaySetup s;
    REQUIRE(s.connect());
    auto init = s.replay();
    REQUIRE(init.size() > wire::Header::kSize);

    RawClient attacker{s.srv};
    attacker.send_to(Endpoint{IpAddr::v4(127, 0, 0, 1), s.large_node->local_port()}, init);
    std::this_thread::sleep_for(300ms);

    CHECK(s.still_works());
}

TEST(a_probe_txn_is_consumed_by_the_handshake_it_admits) {
    // #13, from the right address: through the relay, where the init arrives
    // from the server exactly as the genuine one did. What must stop it is
    // that the txn was already spent on the handshake that succeeded.
    ReplaySetup s;
    REQUIRE(s.connect());
    auto init = s.replay();
    REQUIRE(init.size() > wire::Header::kSize);

    RawClient attacker{s.srv};
    REQUIRE(attacker.register_in(s.creds.id));
    auto rid = attacker.relay_alloc(*s.large->self());
    REQUIRE(rid.has_value());
    attacker.relay_data(*rid, init);
    std::this_thread::sleep_for(300ms);

    CHECK(s.still_works());
}

TEST(a_live_session_cannot_be_taken_over_by_a_claimed_dev_id) {
    // #2. On an open topic the initiator's dev_id travels in plaintext, so
    // nothing proves the claim. An attacker who probes a node and then
    // handshakes claiming to be one of its connected peers won the glare
    // rule whenever the node held the larger dev_id: the node dropped its
    // real session, filed the attacker under the peer's name, carried the
    // streams across to it, and never said a word to the application.
    LocalServer srv;
    Node n1{config_for(srv)};
    Node n2{config_for(srv)};
    n1.run_in_background();
    n2.run_in_background();

    const auto creds = TopicCreds::generate_open();
    Topic& t1 = n1.join(creds);
    Topic& t2 = n2.join(creds);
    REQUIRE(t1.publish());
    REQUIRE(t2.publish());
    REQUIRE(connect_pair(t1, t2));

    // Aim at the larger dev_id, impersonating the smaller.
    const bool one_small = std::memcmp(t1.self()->data(), t2.self()->data(), kDevIdLen) < 0;
    Topic& victim_side = one_small ? t2 : t1;   // the node being attacked
    Topic& impersonated = one_small ? t1 : t2;  // the peer being claimed
    Node&  victim_node  = one_small ? n2 : n1;
    const Endpoint target{IpAddr::v4(127, 0, 0, 1), victim_node.local_port()};

    RawClient attacker{srv};

    // A probe on an open topic is answered for anyone; that admits the txn.
    wire::ProbeTxn txn{};
    txn.fill(0x77);
    std::vector<uint8_t> probe(64);
    {
        wire::Writer w{probe};
        wire::Header{wire::MsgType::Probe, wire::kVersion, 0, 1}.encode(w);
        wire::Probe{txn, wire::ProbeTag{}}.encode(w);
        probe.resize(w.size());
    }
    attacker.send_to(target, probe);
    std::this_thread::sleep_for(100ms);

    // A genuine Noise_NN init, claiming the impersonated peer's dev_id.
    auto forged = session::Session::initiate(session::SessionConfig{}, creds.id, 0, nullptr,
                                             *impersonated.self(), *victim_side.self(), target,
                                             txn, std::chrono::steady_clock::now());
    auto init = forged.poll_transmit();
    REQUIRE(init.has_value());
    attacker.send_to(target, init->data);
    std::this_thread::sleep_for(300ms);

    CHECK(victim_side.state(*impersonated.self()) == PeerState::Connected);

    std::atomic<int> got{0};
    t1.on_data([&](DevId, std::span<const uint8_t>) { ++got; });
    t2.on_data([&](DevId, std::span<const uint8_t>) { ++got; });
    const std::vector<uint8_t> ping{'p'};
    t1.send(*t2.self(), ping);
    t2.send(*t1.self(), ping);
    CHECK(wait_until([&] { return got.load() >= 2; }, 3s));
}

namespace {

std::vector<uint8_t> probe_datagram(const wire::ProbeTxn& txn) {
    std::vector<uint8_t> d(64);
    wire::Writer         w{d};
    wire::Header{wire::MsgType::Probe, wire::kVersion, 0, 1}.encode(w);
    wire::Probe{txn, wire::ProbeTag{}}.encode(w);
    d.resize(w.size());
    return d;
}

}  // namespace

TEST(one_probe_draws_one_answer) {
    // #16. A probe was answered once for every open topic the node had joined
    // (every open topic accepts any probe), and again by every punch session
    // in flight. Each ProbeOk is larger than the Probe, so one spoofed probe
    // came back several times over, at whoever it claimed to be from.
    LocalServer srv;
    Node na{config_for(srv)};
    na.run_in_background();
    for (int i = 0; i < 3; ++i) na.join(TopicCreds::generate_open());

    RawClient attacker{srv};
    wire::ProbeTxn txn{};
    txn.fill(0x31);
    const auto probe = probe_datagram(txn);
    attacker.send_to(Endpoint{IpAddr::v4(127, 0, 0, 1), na.local_port()}, probe);

    auto replies = attacker.receive_for(300ms);
    CHECK_EQ(replies.size(), 1u);
    size_t bytes = 0;
    for (const auto& r : replies) bytes += r.size();
    // One ProbeOk is somewhat larger than the probe -- it reports the address
    // it saw -- but only once.
    CHECK(bytes < 2 * probe.size());
}

TEST(punch_sessions_in_flight_do_not_multiply_probe_answers) {
    // #16, the other multiplier: every PunchSession fed the probe answered it
    // too. With a punch in flight toward a peer, one probe drew a node-level
    // answer plus one per session.
    LocalServer srv;
    Node na{config_for(srv)};
    Node nb{config_for(srv)};
    na.run_in_background();
    nb.run_in_background();
    const auto creds = TopicCreds::generate_open();
    Topic& a = na.join(creds);
    Topic& b = nb.join(creds);
    REQUIRE(a.publish());
    REQUIRE(b.publish());

    // Put A into Probing toward B -- then take B away so the punch stays open.
    (void)a.peers();
    const DevId idb = *b.self();
    nb.shutdown();
    a.connect(idb);
    REQUIRE(wait_until([&] { return a.state(idb) == PeerState::Probing; }, 2s));

    RawClient attacker{srv};
    wire::ProbeTxn txn{};
    txn.fill(0x32);
    attacker.send_to(Endpoint{IpAddr::v4(127, 0, 0, 1), na.local_port()}, probe_datagram(txn));

    auto replies = attacker.receive_for(300ms);
    size_t probe_oks = 0;
    for (const auto& r : replies) {
        if (wire::peek_type(r) == wire::MsgType::ProbeOk) ++probe_oks;
    }
    CHECK_EQ(probe_oks, 1u);
}

TEST(a_probe_flood_does_not_grow_the_answered_table_without_bound) {
    // #17. On an open topic any probe is answered, and every answered txn was
    // remembered for 30s -- so memory grew with whatever rate someone cared to
    // send probes at.
    LocalServer srv;
    Node na{config_for(srv)};
    na.run_in_background();
    na.join(TopicCreds::generate_open());

    RawClient attacker{srv};
    const Endpoint target{IpAddr::v4(127, 0, 0, 1), na.local_port()};
    for (uint32_t i = 0; i < 4000; ++i) {
        wire::ProbeTxn txn{};
        std::memcpy(txn.data(), &i, sizeof(i));
        attacker.send_to(target, probe_datagram(txn));
        if (i % 100 == 99) std::this_thread::sleep_for(2ms);  // let the loop keep up
    }
    std::this_thread::sleep_for(300ms);

    CHECK(na.answered_probes() <= 1024u);
}

TEST(explore_follows_the_cursor_past_one_request) {
    // #32. explore() sent one TOPICS request and returned whatever came back,
    // ignoring next_cursor -- so no caller, the dashboard included, could see
    // past the first page, and a limit above one request's 255 was silently
    // cut to it.
    server::StoreConfig scfg;
    scfg.max_per_ip_total = 1000;  // every registrant here is 127.0.0.1
    LocalServer srv{scfg};

    RawClient registrar{srv};
    for (int i = 0; i < 300; ++i) {
        REQUIRE(registrar.register_in(TopicCreds::generate_open().id));
    }

    Node observer{config_for(srv)};
    observer.run_in_background();

    auto all = observer.explore(0, 1000, 10s);
    CHECK_EQ(all.size(), 300u);

    // Distinct topics, not one page seen twice.
    std::vector<TopicId> ids;
    for (const auto& t : all) ids.push_back(t.id);
    std::sort(ids.begin(), ids.end());
    CHECK(std::adjacent_find(ids.begin(), ids.end()) == ids.end());

    // And a limit is still a limit.
    CHECK_EQ(observer.explore(0, 40, 10s).size(), 40u);
}

TEST(a_relayed_peer_can_be_reconnected_after_its_session_ends) {
    // #11. The relay flags outlived the session they belonged to, and
    // begin_connect refuses any peer already marked relayed -- so once a
    // relayed connection ended, that peer could never be reached again for
    // the life of the node.
    LocalServer srv;
    Node na{config_for(srv, /*force_relay=*/true)};
    Node nb{config_for(srv, /*force_relay=*/true)};
    na.run_in_background();
    nb.run_in_background();

    const auto creds = TopicCreds::generate_keyed();
    Topic& a = na.join(creds);
    Topic& b = nb.join(creds);
    REQUIRE(a.publish());
    REQUIRE(b.publish());

    std::atomic<bool> closed{false};
    b.on_peer_closed([&](DevId, PeerGone) { closed = true; });

    REQUIRE(connect_pair(a, b));
    const DevId ida = *a.self(), idb = *b.self();
    a.disconnect(idb);
    REQUIRE(wait_until([&] { return closed.load(); }, 3s));

    // B, whose session ended under it, dials A again.
    b.connect(ida);
    CHECK(wait_until([&] {
        return a.state(idb) == PeerState::Connected && b.state(ida) == PeerState::Connected;
    }, 10s));
}
