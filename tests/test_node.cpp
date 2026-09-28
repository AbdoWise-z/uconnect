// Node-level tests: the public API, where configuration arrives from the
// application and the sans-IO layers meet a real socket.
//
// Two kinds. Configuration checks run offline: construction validates before it
// opens a socket or resolves anything. Behaviour checks run real Nodes over
// loopback against a rendezvous server hosted in-process (LocalServer below),
// the same Rendezvous the real server binary runs.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

#include "control.hpp"
#include "rendezvous.hpp"
#include "socket.hpp"
#include "testing.hpp"
#include "uconnect/uconnect.hpp"

using namespace uconnect;
using namespace std::chrono_literals;
namespace ctl = wire::ctl;

namespace {

// A rendezvous server on loopback, on its own thread, with one knob the real
// network has and a test needs: a restart that forgets everything.
class LocalServer {
public:
    explicit LocalServer(server::RendezvousConfig cfg = {}) : cfg_(std::move(cfg)) {
        cfg_.port = 0;
        start();
        cfg_.port = rv_->port();  // a restart comes back on the same port
        thread_   = std::thread([this] { run(); });
    }
    ~LocalServer() {
        stop_ = true;
        thread_.join();
    }
    LocalServer(const LocalServer&)            = delete;
    LocalServer& operator=(const LocalServer&) = delete;

    uint16_t    port() const { return cfg_.port; }
    std::string address() const { return "127.0.0.1:" + std::to_string(cfg_.port); }
    Endpoint    endpoint() const { return Endpoint{IpAddr::v4(127, 0, 0, 1), cfg_.port}; }

    // Forget every record and connection: what a process restart does to a
    // server that keeps everything in memory.
    void restart() {
        std::lock_guard<std::mutex> lk(mu_);
        rv_.reset();
        start();
    }

    server::RegistryStats stats() {
        std::lock_guard<std::mutex> lk(mu_);
        return rv_->service().registry().stats(std::chrono::steady_clock::now());
    }

    size_t connections() {
        std::lock_guard<std::mutex> lk(mu_);
        return rv_->service().connections();
    }

private:
    void start() {
        rv_ = std::make_unique<server::Rendezvous>(cfg_);
        if (!rv_->open()) throw std::runtime_error("LocalServer: " + rv_->error());
    }

    void run() {
        while (!stop_) {
            std::lock_guard<std::mutex> lk(mu_);
            rv_->poll_once(5ms);
        }
    }

    server::RendezvousConfig            cfg_;
    std::unique_ptr<server::Rendezvous> rv_;
    std::mutex                          mu_;
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

// A raw TCP client, for playing the attacker or standing in for many nodes: it
// sends whatever bytes it likes, which a Node never would.
class RawConn {
public:
    explicit RawConn(const Endpoint& to) {
        if (!sock_.open(0) || !sock_.connect(to)) throw std::runtime_error("RawConn: setup failed");
        const auto deadline = std::chrono::steady_clock::now() + 2s;
        while (sock_.state() == io::TcpSocket::State::Connecting &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(2ms);
        }
    }

    bool connected() { return sock_.state() == io::TcpSocket::State::Connected; }

    void send_raw(std::span<const uint8_t> bytes) {
        while (!bytes.empty()) {
            auto n = sock_.send(bytes);
            if (!n) return;
            bytes = bytes.subspan(*n);
            if (*n == 0) std::this_thread::sleep_for(1ms);
        }
    }

    // The next control message of type `want`, skipping others.
    std::optional<std::vector<uint8_t>> expect(wire::MsgType want, std::chrono::milliseconds t = 2s) {
        const auto deadline = std::chrono::steady_clock::now() + t;
        std::vector<uint8_t> buf(4096);
        while (std::chrono::steady_clock::now() < deadline) {
            while (auto m = reader_.next()) {
                if (wire::peek_type(*m) == want) return m;
            }
            auto got = sock_.recv(buf);
            if (!got) return std::nullopt;
            if (*got == 0) {
                std::this_thread::sleep_for(2ms);
                continue;
            }
            if (!reader_.feed(std::span(buf).first(*got))) return std::nullopt;
        }
        return std::nullopt;
    }

    // True once the other end has closed the connection.
    bool closed_within(std::chrono::milliseconds t) {
        const auto deadline = std::chrono::steady_clock::now() + t;
        std::vector<uint8_t> buf(4096);
        while (std::chrono::steady_clock::now() < deadline) {
            auto got = sock_.recv(buf);
            if (!got) return true;
            if (*got == 0) std::this_thread::sleep_for(5ms);
        }
        return false;
    }

    // Register in `topic` on a control connection; the dev_id, if accepted.
    std::optional<DevId> register_in(const TopicId& topic) {
        ctl::Register m;
        m.id   = topic;
        m.mode = TopicMode::Open;
        send_raw(ctl::frame(ctl::message(wire::MsgType::Register, next_txn_++, m)));
        auto reply = expect(wire::MsgType::RegisterOk);
        if (!reply) return std::nullopt;
        wire::Reader r{*reply};
        if (!wire::Header::decode(r, ctl::kVersion)) return std::nullopt;
        auto ok = ctl::RegisterOk::decode(r);
        if (!ok) return std::nullopt;
        return ok->dev_id;
    }

private:
    io::TcpSocket    sock_;
    ctl::FrameReader reader_;
    uint32_t         next_txn_ = 1;
};

// Two published members of one topic, each told to connect to the other.
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

// A pair of nodes in one topic, published and ready to connect.
struct Pair {
    Node   na;
    Node   nb;
    Topic* a = nullptr;
    Topic* b = nullptr;

    Pair(const LocalServer& srv, bool force_relay, TopicCreds creds = TopicCreds::generate_keyed())
        : na{config_for(srv, force_relay)}, nb{config_for(srv, force_relay)} {
        na.run_in_background();
        nb.run_in_background();
        a = &na.join(creds);
        b = &nb.join(creds);
    }
    bool publish() { return a->publish() && b->publish(); }
    DevId ida() const { return *a->self(); }
    DevId idb() const { return *b->self(); }
};

std::vector<uint8_t> bytes(std::string_view s) { return {s.begin(), s.end()}; }

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
    // #27. A key generation must span more than the 64-packet replay window,
    // i.e. a shift of at least 7; at 64 or more the shift is undefined
    // behaviour. Neither should be accepted silently from an application.
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

    cfg.rekey_shift = 7;
    CHECK(!refused(cfg));
    cfg.rekey_shift = 63;
    CHECK(!refused(cfg));
    cfg.rekey_shift = 16;  // the default
    CHECK(!refused(cfg));
}

// ---------------------------------------------------------------------------
// Behaviour over loopback, against a LocalServer
// ---------------------------------------------------------------------------
TEST(node_keeps_a_control_connection_to_the_server) {
    LocalServer srv;
    Node        na{config_for(srv)};
    na.run_in_background();
    CHECK(wait_until([&] { return na.server_connected(); }, 3s));
    CHECK_EQ(srv.connections(), 1u);
}

TEST(two_nodes_punch_a_direct_connection_and_exchange_messages) {
    LocalServer srv;
    Pair        p{srv, /*force_relay=*/false};
    REQUIRE(p.publish());

    std::atomic<int> got{0};
    p.b->on_data([&](DevId, std::span<const uint8_t> d) {
        if (std::string(d.begin(), d.end()) == "hello") ++got;
    });

    REQUIRE(connect_pair(*p.a, *p.b));
    auto li = p.a->link(p.idb());
    REQUIRE(li.has_value());
    CHECK(!li->relayed);

    CHECK(p.a->send(p.idb(), bytes("hello")));
    CHECK(wait_until([&] { return got.load() == 1; }, 3s));
    CHECK_EQ(p.a->link(p.idb())->messages_sent, 1u);
    CHECK_EQ(p.b->link(p.ida())->messages_received, 1u);
}

TEST(messages_reach_a_peer_over_the_relay) {
    LocalServer srv;
    Pair        p{srv, /*force_relay=*/true};
    REQUIRE(p.publish());

    std::atomic<int> got{0};
    p.b->on_data([&](DevId, std::span<const uint8_t> d) {
        if (std::string(d.begin(), d.end()) == "hello") ++got;
    });

    REQUIRE(connect_pair(*p.a, *p.b));
    auto li = p.a->link(p.idb());
    REQUIRE(li.has_value());
    CHECK(li->relayed);
    CHECK(p.b->link(p.ida())->relayed);

    CHECK(p.a->send(p.idb(), bytes("hello")));
    CHECK(wait_until([&] { return got.load() == 1; }, 3s));
    CHECK(srv.stats().relays_allocated >= 1u);
}

TEST(messages_arrive_whole_once_and_in_order) {
    LocalServer srv;
    Pair        p{srv, /*force_relay=*/false};
    REQUIRE(p.publish());

    std::mutex                        mu;
    std::vector<std::vector<uint8_t>> seen;
    p.b->on_data([&](DevId, std::span<const uint8_t> d) {
        std::lock_guard<std::mutex> lk(mu);
        seen.emplace_back(d.begin(), d.end());
    });
    REQUIRE(connect_pair(*p.a, *p.b));

    // Every size from empty to the maximum, in one burst.
    std::vector<std::vector<uint8_t>> sent;
    for (size_t n : {size_t{0}, size_t{1}, size_t{1400}, size_t{65536}, size_t{300000},
                     Topic::max_message()}) {
        std::vector<uint8_t> m(n);
        for (size_t i = 0; i < n; ++i) m[i] = static_cast<uint8_t>(i * 7 + sent.size());
        REQUIRE(p.a->send(p.idb(), m));
        sent.push_back(std::move(m));
    }
    CHECK(!p.a->send(p.idb(), std::vector<uint8_t>(Topic::max_message() + 1)));

    CHECK(wait_until([&] {
        std::lock_guard<std::mutex> lk(mu);
        return seen.size() >= sent.size();
    }, 10s));
    std::lock_guard<std::mutex> lk(mu);
    REQUIRE(seen.size() == sent.size());
    for (size_t i = 0; i < sent.size(); ++i) CHECK(seen[i] == sent[i]);
}

TEST(both_sides_connecting_at_once_end_on_one_session) {
    // Each side CONNECTs with its own attempt nonce; they must settle on one,
    // not two sessions each missing half the traffic.
    LocalServer srv;
    Pair        p{srv, /*force_relay=*/false};
    REQUIRE(p.publish());

    std::atomic<int> at_a{0}, at_b{0};
    p.a->on_data([&](DevId, std::span<const uint8_t>) { ++at_a; });
    p.b->on_data([&](DevId, std::span<const uint8_t>) { ++at_b; });
    REQUIRE(connect_pair(*p.a, *p.b));

    // Both ends agree on which session this is.
    CHECK(p.a->channel_binding(p.idb()) == p.b->channel_binding(p.ida()));
    for (int i = 0; i < 10; ++i) {
        p.a->send(p.idb(), bytes("x"));
        p.b->send(p.ida(), bytes("y"));
    }
    CHECK(wait_until([&] { return at_a.load() == 10 && at_b.load() == 10; }, 3s));
}

TEST(an_open_topic_shows_both_ends_the_same_sas) {
    LocalServer srv;
    Pair        p{srv, /*force_relay=*/false, TopicCreds::generate_open()};
    REQUIRE(p.publish());
    REQUIRE(connect_pair(*p.a, *p.b));
    CHECK(!p.a->is_authenticated());
    auto sa = p.a->sas(p.idb()), sb = p.b->sas(p.ida());
    REQUIRE(sa.has_value());
    CHECK(sa == sb);
}

TEST(a_disconnect_notice_reaches_the_peer_directly_and_over_the_relay) {
    for (bool relay : {false, true}) {
        LocalServer srv;
        Pair        p{srv, relay};
        REQUIRE(p.publish());

        std::atomic<bool> told{false};
        p.b->on_peer_closed([&](DevId, PeerGone why) {
            if (why == PeerGone::GoingAway) told = true;
        });

        REQUIRE(connect_pair(*p.a, *p.b));
        p.a->disconnect(p.idb());
        CHECK(wait_until([&] { return told.load(); }, 3s));
        CHECK(p.b->state(p.ida()) == PeerState::Closed);
    }
}

TEST(a_shutdown_tells_peers_the_node_is_exiting) {
    LocalServer srv;
    Pair        p{srv, /*force_relay=*/false};
    REQUIRE(p.publish());

    std::atomic<bool> told{false};
    p.b->on_peer_closed([&](DevId, PeerGone why) {
        if (why == PeerGone::ShuttingDown) told = true;
    });
    REQUIRE(connect_pair(*p.a, *p.b));
    p.na.shutdown();
    CHECK(wait_until([&] { return told.load(); }, 3s));
}

TEST(a_relayed_peer_can_be_reconnected_after_its_session_ends) {
    // #11. Once a relayed connection ended, that peer could never be reached
    // again for the life of the node.
    LocalServer srv;
    Pair        p{srv, /*force_relay=*/true};
    REQUIRE(p.publish());

    std::atomic<bool> closed{false};
    p.b->on_peer_closed([&](DevId, PeerGone) { closed = true; });

    REQUIRE(connect_pair(*p.a, *p.b));
    p.a->disconnect(p.idb());
    REQUIRE(wait_until([&] { return closed.load(); }, 3s));

    // B, whose session ended under it, dials A again.
    p.b->connect(p.ida());
    CHECK(wait_until([&] {
        return p.a->state(p.idb()) == PeerState::Connected &&
               p.b->state(p.ida()) == PeerState::Connected;
    }, 15s));
}

TEST(a_peer_with_no_path_is_reported_failed) {
    // Punching cannot reach a peer that is gone, and this server refuses to
    // relay: the attempt must end in Failed, not dial forever.
    server::RendezvousConfig rcfg;
    rcfg.registry.relay_enabled = false;
    LocalServer srv{rcfg};

    Node::Config cfg  = config_for(srv);
    cfg.punch_timeout = 1s;
    Node na{cfg};
    auto nb = std::make_unique<Node>(config_for(srv));
    na.run_in_background();
    nb->run_in_background();
    const auto creds = TopicCreds::generate_keyed();
    Topic&     a     = na.join(creds);
    Topic&     b     = nb->join(creds);
    REQUIRE(a.publish());
    REQUIRE(b.publish());
    const DevId idb = *b.self();
    REQUIRE(a.peers().size() == 1u);  // A now knows where B was

    nb.reset();
    a.connect(idb);
    CHECK(wait_until([&] { return a.state(idb) == PeerState::Failed; }, 6s));
}

TEST(connect_needs_a_published_topic) {
    // The server introduces a peer only to a registered one.
    LocalServer srv;
    Pair        p{srv, /*force_relay=*/false};
    REQUIRE(p.b->publish());
    (void)p.a->peers();
    p.a->connect(*p.b->self());
    std::this_thread::sleep_for(200ms);
    CHECK(p.a->state(*p.b->self()) == PeerState::Unknown);
}

TEST(auto_connect_finds_and_connects_peers_on_its_own) {
    LocalServer srv;
    Pair        p{srv, /*force_relay=*/false};
    p.a->set_auto_connect(true);
    REQUIRE(p.publish());
    CHECK(wait_until([&] {
        return p.a->connected().size() == 1 && p.b->connected().size() == 1;
    }, 15s));
}

TEST(a_node_registers_again_after_the_server_restarts) {
    // #7. The server keeps records in memory and forgets them all on a
    // restart. The node must notice -- its control connection drops -- and
    // come back findable, without the application doing anything.
    LocalServer srv;
    Node        na{config_for(srv)};
    Node        observer{config_for(srv)};
    na.run_in_background();
    observer.run_in_background();

    const auto creds = TopicCreds::generate_keyed();
    Topic&     a     = na.join(creds);
    Topic&     o     = observer.join(creds);  // looks, never publishes
    REQUIRE(a.publish());
    REQUIRE(o.peers().size() == 1);

    srv.restart();

    // The restarted server derives dev_ids from a new secret, so A's identity
    // changes with it.
    CHECK(wait_until([&] {
        auto self  = a.self();
        auto found = o.peers(30, false, 500ms);
        return self && found.size() == 1 && found[0].dev_id == *self;
    }, 10s));
}

TEST(requests_the_loop_issues_for_itself_are_retired) {
    // #9. Keepalives and discovery LOOKUPs are issued by the loop, not by a
    // blocking caller, and must not accumulate in the request table.
    LocalServer  srv;
    Node::Config cfg = config_for(srv);
    cfg.keepalive    = 1s;
    Node na{cfg};
    na.run_in_background();

    Topic& a = na.join(TopicCreds::generate_keyed());
    a.set_auto_connect(true);
    REQUIRE(a.publish());

    std::this_thread::sleep_for(6500ms);
    CHECK(na.pending_requests() <= 2u);  // at most what is genuinely in flight
    CHECK_EQ(srv.stats().registers, 1u);  // and the keepalives did not re-register
}

TEST(stats_and_explore_reach_the_server) {
    LocalServer srv;
    Node        na{config_for(srv)};
    Node        nb{config_for(srv)};
    na.run_in_background();
    nb.run_in_background();

    Topic& a = na.join(TopicCreds::generate_keyed());
    REQUIRE(a.publish());

    auto st = nb.stats();
    REQUIRE(st.has_value());
    CHECK(st->entries_total >= 1u);
    CHECK_EQ(st->connections, 2u);
    CHECK_EQ(nb.explore().size(), 1u);
}

TEST(explore_follows_the_cursor_past_one_request) {
    // #32. explore() must follow next_cursor past the first page, and a limit
    // above one request's 255 must not be silently cut to it.
    server::RendezvousConfig rcfg;
    rcfg.registry.max_per_ip_total = 1000;  // every registrant here is 127.0.0.1
    LocalServer srv{rcfg};

    RawConn registrar{srv.endpoint()};
    for (int i = 0; i < 300; ++i) {
        REQUIRE(registrar.register_in(TopicCreds::generate_open().id).has_value());
    }

    Node observer{config_for(srv)};
    observer.run_in_background();

    auto all = observer.explore(0, 1000, 10s);
    CHECK_EQ(all.size(), 300u);

    std::vector<TopicId> ids;
    for (const auto& t : all) ids.push_back(t.id);
    std::sort(ids.begin(), ids.end());
    CHECK(std::adjacent_find(ids.begin(), ids.end()) == ids.end());

    CHECK_EQ(observer.explore(0, 40, 10s).size(), 40u);
}

TEST(an_inbound_connection_naming_no_attempt_of_ours_is_dropped) {
    // Anyone can reach the node's port -- LOOKUP hands it out. A connection
    // must name an introduction the node is part of, or be closed.
    LocalServer srv;
    Node        na{config_for(srv)};
    na.run_in_background();
    Topic& a = na.join(TopicCreds::generate_keyed());
    REQUIRE(a.publish());

    RawConn attacker{Endpoint{IpAddr::v4(127, 0, 0, 1), na.local_port()}};
    REQUIRE(attacker.connected());
    std::vector<uint8_t> hello{'U', 'C'};
    for (int i = 0; i < 16; ++i) hello.push_back(0xAB);
    attacker.send_raw(hello);
    CHECK(attacker.closed_within(2s));
}

TEST(a_silent_inbound_connection_does_not_linger_forever) {
    LocalServer srv;
    Node        na{config_for(srv)};
    na.run_in_background();

    RawConn idle{Endpoint{IpAddr::v4(127, 0, 0, 1), na.local_port()}};
    REQUIRE(idle.connected());
    // Nothing sent. The node gives it ten seconds to identify itself.
    CHECK(idle.closed_within(12s));
}

TEST(an_introduction_from_a_stranger_does_not_disturb_a_live_session) {
    // #2, under v2. Any member of a topic can CONNECT to any other; the server
    // stamps its real dev_id on the introduction, so it cannot claim to be
    // someone else, but it can still try to make a node give up a working
    // session. It must not.
    LocalServer srv;
    Pair        p{srv, /*force_relay=*/false, TopicCreds::generate_open()};
    REQUIRE(p.publish());
    REQUIRE(connect_pair(*p.a, *p.b));
    const auto binding = p.a->channel_binding(p.idb());

    RawConn stranger{srv.endpoint()};
    auto    me = stranger.register_in(p.a->id());
    REQUIRE(me.has_value());
    ctl::Connect c;
    c.from_dev = *me;
    c.to_dev   = p.ida();
    c.payload  = std::vector<uint8_t>(40, 0x00);  // nonsense intro
    stranger.send_raw(ctl::frame(ctl::message(wire::MsgType::Connect, 7, c)));
    std::this_thread::sleep_for(300ms);

    CHECK(p.a->state(p.idb()) == PeerState::Connected);
    CHECK(p.a->channel_binding(p.idb()) == binding);
}
