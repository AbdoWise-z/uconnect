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
#include "tcp_session.hpp"
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
    c.verbose     = std::getenv("UCONNECT_TEST_VERBOSE") != nullptr;
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

    // Whatever has arrived (possibly nothing), or nullopt once it is closed.
    std::optional<std::vector<uint8_t>> read_some() {
        std::vector<uint8_t> buf(4096);
        auto                 got = sock_.recv(buf);
        if (!got) return std::nullopt;
        buf.resize(*got);
        return buf;
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

// In the tests below, whatever a callback touches is declared before the Pair,
// so it outlives the nodes whose loop threads call it.

TEST(two_nodes_punch_a_direct_connection_and_exchange_messages) {
    LocalServer      srv;
    std::atomic<int> got{0};
    Pair             p{srv, /*force_relay=*/false};
    REQUIRE(p.publish());

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
    LocalServer      srv;
    std::atomic<int> got{0};
    Pair             p{srv, /*force_relay=*/true};
    REQUIRE(p.publish());

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
    LocalServer                       srv;
    std::mutex                        mu;
    std::vector<std::vector<uint8_t>> seen;
    Pair                              p{srv, /*force_relay=*/false};
    REQUIRE(p.publish());

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
    LocalServer      srv;
    std::atomic<int> at_a{0}, at_b{0};
    Pair             p{srv, /*force_relay=*/false};
    p.a->set_max_peers(1);
    p.b->set_max_peers(1);
    REQUIRE(p.publish());

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
        LocalServer       srv;
        std::atomic<bool> told{false};
        Pair              p{srv, relay};
        REQUIRE(p.publish());

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
    LocalServer       srv;
    std::atomic<bool> told{false};
    Pair              p{srv, /*force_relay=*/false};
    REQUIRE(p.publish());

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
    LocalServer       srv;
    std::atomic<bool> closed{false};
    Pair              p{srv, /*force_relay=*/true};
    REQUIRE(p.publish());

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

TEST(a_resolved_peer_can_be_connected_without_a_lookup) {
    // #46. resolve() returned the peer but threw its candidates away, so
    // connect() had nowhere to dial until some peers() sample happened to
    // include it -- in a large swarm, possibly never.
    LocalServer srv;
    Pair        p{srv, /*force_relay=*/false};
    REQUIRE(p.publish());
    REQUIRE(p.a->resolve(p.idb()).has_value());
    p.a->connect(p.idb());
    CHECK(p.a->state(p.idb()) != PeerState::Unknown);
    CHECK(wait_until([&] {
        return p.a->state(p.idb()) == PeerState::Connected &&
               p.b->state(p.ida()) == PeerState::Connected;
    }, 15s));
}

TEST(resolve_answers_only_for_members_of_its_own_topic) {
    // A dev_id registered in another topic is not a peer of this one: it must
    // not be reported as found, nor remembered as somewhere to dial.
    LocalServer srv;
    Pair        p{srv, /*force_relay=*/false};
    Node        nc{config_for(srv)};
    nc.run_in_background();
    Topic& c = nc.join(TopicCreds::generate_keyed());
    REQUIRE(p.publish());
    REQUIRE(c.publish());
    const DevId idc = *c.self();

    CHECK(!p.a->resolve(idc).has_value());
    p.a->connect(idc);
    CHECK(p.a->state(idc) == PeerState::Unknown);
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

TEST(try_queries_tell_a_failed_request_from_an_empty_answer) {
    // #48. explore() and peers() return an empty list for an unreachable
    // server and for an empty one alike; the try_ forms must not.
    {
        Node::Config cfg;
        cfg.server = "127.0.0.1:1";  // nothing listens here
        Node lonely{cfg};
        lonely.run_in_background();
        Topic& t = lonely.join(TopicCreds::generate_open());
        CHECK(!lonely.try_explore(0, 10, 300ms).has_value());
        CHECK(!t.try_peers(10, false, 300ms).has_value());
        CHECK(lonely.explore(0, 10, 300ms).empty());  // the old forms are unchanged
        CHECK(t.peers(10, false, 300ms).empty());
    }
    LocalServer srv;
    Node        na{config_for(srv)};
    na.run_in_background();
    Topic& t = na.join(TopicCreds::generate_open());

    auto listing = na.try_explore(0, 10, 3s);
    REQUIRE(listing.has_value());
    CHECK(listing->empty());  // reachable, and genuinely nothing listed
    auto members = t.try_peers(10, false, 3s);
    REQUIRE(members.has_value());
    CHECK(members->empty());

    REQUIRE(t.publish());
    Node   nb{config_for(srv)};
    nb.run_in_background();
    Topic& u = nb.join(*na.creds(t.id()));
    CHECK_EQ(nb.try_explore(0, 10, 3s).value_or(std::vector<TopicSummary>{}).size(), 1u);
    CHECK_EQ(u.try_peers(10, false, 3s).value_or(std::vector<PeerInfo>{}).size(), 1u);
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
    // Held for up to two seconds -- an introduction may be on its way -- and
    // then dropped, since none names it.
    CHECK(attacker.closed_within(4s));
}

TEST(a_connection_that_arrives_before_its_introduction_is_held_for_it) {
    // A peer close by can dial faster than the server, further off, can
    // introduce it. The node used to drop such a connection at once as naming
    // no attempt of its own -- and on a LAN with a distant server that was
    // most of them. Here peer A dials B, speaks, and only half a second later
    // sends the CONNECT that introduces it; the held connection must carry
    // the handshake.
    LocalServer srv;
    Node        nb{config_for(srv)};
    nb.run_in_background();
    const auto creds = TopicCreds::generate_open();
    Topic&     b     = nb.join(creds);
    REQUIRE(b.publish());
    const DevId idb = *b.self();

    RawConn ctrl{srv.endpoint()};  // A's control connection
    auto    ida = ctrl.register_in(creds.id);
    REQUIRE(ida.has_value());

    session::AttemptNonce attempt{};
    attempt.fill(0x5C);
    const bool a_initiates = std::memcmp(ida->data(), idb.data(), kDevIdLen) < 0;
    const auto t0          = std::chrono::steady_clock::now();
    auto s = a_initiates ? session::TcpSession::initiate({}, creds.id, 0, nullptr, *ida, idb, attempt, t0)
                         : session::TcpSession::respond({}, creds.id, 0, nullptr, *ida, idb, attempt, t0);

    // A dials first: no introduction exists yet.
    RawConn dial{Endpoint{IpAddr::v4(127, 0, 0, 1), nb.local_port()}};
    REQUIRE(dial.connected());
    if (a_initiates) dial.send_raw(s.take_output());
    else dial.send_raw(session::TcpSession::hello(attempt));
    std::this_thread::sleep_for(500ms);

    // Then the introduction, naming that attempt.
    std::vector<uint8_t> intro(creds.id.begin(), creds.id.end());
    intro.insert(intro.end(), attempt.begin(), attempt.end());
    intro.push_back(0);  // no candidates: the connection is already there
    ctl::Connect c;
    c.from_dev = *ida;
    c.to_dev   = idb;
    c.payload  = intro;
    ctrl.send_raw(ctl::frame(ctl::message(wire::MsgType::Connect, 9, c)));

    CHECK(wait_until([&] {
        auto got = dial.read_some();
        if (!got) return false;  // dropped
        s.on_bytes(*got, std::chrono::steady_clock::now());
        dial.send_raw(s.take_output());
        return s.state() == session::TcpSession::State::Established;
    }, 5s));
    CHECK(wait_until([&] { return b.state(*ida) == PeerState::Connected; }, 3s));
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

// ---------------------------------------------------------------------------
// Datagrams
// ---------------------------------------------------------------------------
namespace {

// A connected pair, with every datagram each side receives collected.
//
// What the callbacks write to is declared BEFORE the nodes, so it is destroyed
// after them: until a node has shut down, its loop thread may still call in.
struct DgramPair {
    LocalServer&              srv;
    std::mutex                mu;
    std::vector<std::string>  at_a, at_b;
    std::vector<DatagramPath> paths_b;
    Node                      na;
    Node                      nb;
    Topic*                    a = nullptr;
    Topic*                    b = nullptr;

    DgramPair(LocalServer& s, Node::Config ca, Node::Config cb)
        : srv(s), na{std::move(ca)}, nb{std::move(cb)} {
        na.run_in_background();
        nb.run_in_background();
        const auto creds = TopicCreds::generate_keyed();
        a = &na.join(creds);
        b = &nb.join(creds);
        a->on_datagram([this](DevId, std::span<const uint8_t> d) {
            std::lock_guard<std::mutex> lk(mu);
            at_a.emplace_back(d.begin(), d.end());
        });
        b->on_datagram([this](DevId, std::span<const uint8_t> d) {
            std::lock_guard<std::mutex> lk(mu);
            at_b.emplace_back(d.begin(), d.end());
        });
        b->on_datagram_path([this](DevId, DatagramPath p) {
            std::lock_guard<std::mutex> lk(mu);
            paths_b.push_back(p);
        });
    }
    bool connect() { return a->publish() && b->publish() && connect_pair(*a, *b); }
    DevId ida() const { return *a->self(); }
    DevId idb() const { return *b->self(); }

    bool settled(DatagramPath want, std::chrono::milliseconds t = 15s) {
        return wait_until([&] {
            return a->datagram_path(idb()) == want && b->datagram_path(ida()) == want;
        }, t);
    }
    size_t count_a() { std::lock_guard<std::mutex> lk(mu); return at_a.size(); }
    size_t count_b() { std::lock_guard<std::mutex> lk(mu); return at_b.size(); }
};

Node::Config dgram_config(const LocalServer& srv, bool force_relay, DatagramFallback fb) {
    Node::Config c       = config_for(srv, force_relay);
    c.datagram_fallback  = fb;
    return c;
}

}  // namespace

TEST(datagrams_punch_a_direct_udp_path_and_flow_both_ways) {
    LocalServer srv;
    DgramPair   p{srv, config_for(srv), config_for(srv)};
    REQUIRE(p.connect());
    CHECK(p.a->datagram_path(p.idb()) == DatagramPath::None);

    REQUIRE(p.a->open_datagrams(p.idb(), DatagramFallback::None));
    REQUIRE(p.settled(DatagramPath::Direct));

    // Unreliable, so send a few and ask for most.
    for (int i = 0; i < 20; ++i) {
        CHECK(p.a->send_datagram(p.idb(), bytes("ping")));
        CHECK(p.b->send_datagram(p.ida(), bytes("pong")));
        std::this_thread::sleep_for(5ms);
    }
    CHECK(wait_until([&] { return p.count_a() >= 15 && p.count_b() >= 15; }, 3s));
    CHECK(p.a->link(p.idb())->datagrams_sent == 20u);
    CHECK(p.b->link(p.ida())->datagrams_received >= 15u);

    // The accepting side reported its path as it went.
    std::lock_guard<std::mutex> lk(p.mu);
    REQUIRE(!p.paths_b.empty());
    CHECK(p.paths_b.front() == DatagramPath::Opening);
    CHECK(p.paths_b.back() == DatagramPath::Direct);
}

TEST(datagrams_fall_back_over_tcp_when_udp_cannot_be_punched) {
    LocalServer srv;
    DgramPair   p{srv, dgram_config(srv, true, DatagramFallback::Tcp),
                  dgram_config(srv, true, DatagramFallback::Tcp)};
    REQUIRE(p.connect());
    REQUIRE(p.a->open_datagrams(p.idb(), DatagramFallback::Tcp));
    REQUIRE(p.settled(DatagramPath::Tcp));

    CHECK(p.a->send_datagram(p.idb(), bytes("over tcp")));
    CHECK(p.b->send_datagram(p.ida(), bytes("and back")));
    CHECK(wait_until([&] { return p.count_a() == 1 && p.count_b() == 1; }, 3s));
    std::lock_guard<std::mutex> lk(p.mu);
    CHECK(p.at_b.front() == "over tcp");
}

TEST(datagrams_fall_back_to_the_udp_relay_when_asked_to) {
    LocalServer srv;
    DgramPair   p{srv, dgram_config(srv, true, DatagramFallback::Relay),
                  dgram_config(srv, true, DatagramFallback::Relay)};
    REQUIRE(p.connect());
    const auto tcp_relays = srv.stats().relays_allocated;

    REQUIRE(p.a->open_datagrams(p.idb(), DatagramFallback::Relay));
    REQUIRE(p.settled(DatagramPath::Relayed));
    CHECK(srv.stats().relays_allocated == tcp_relays + 1);  // one binding, both sides

    for (int i = 0; i < 10; ++i) {
        CHECK(p.a->send_datagram(p.idb(), bytes("via relay")));
        CHECK(p.b->send_datagram(p.ida(), bytes("via relay too")));
    }
    CHECK(wait_until([&] { return p.count_a() >= 8 && p.count_b() >= 8; }, 3s));
}

TEST(datagrams_with_no_fallback_report_failure_and_refuse_to_send) {
    LocalServer srv;
    DgramPair   p{srv, dgram_config(srv, true, DatagramFallback::None),
                  dgram_config(srv, true, DatagramFallback::None)};
    REQUIRE(p.connect());
    REQUIRE(p.a->open_datagrams(p.idb(), DatagramFallback::None));
    REQUIRE(p.settled(DatagramPath::Failed));
    CHECK(!p.a->send_datagram(p.idb(), bytes("nowhere to go")));
}

TEST(each_side_applies_its_own_fallback) {
    // A chose TCP for itself; B's configuration says relay. A sends over TCP,
    // B through the relay, and both arrive -- the receiver takes datagrams by
    // whatever way they come.
    LocalServer srv;
    DgramPair   p{srv, dgram_config(srv, true, DatagramFallback::Tcp),
                  dgram_config(srv, true, DatagramFallback::Relay)};
    REQUIRE(p.connect());
    REQUIRE(p.a->open_datagrams(p.idb(), DatagramFallback::Tcp));
    CHECK(wait_until([&] {
        return p.a->datagram_path(p.idb()) == DatagramPath::Tcp &&
               p.b->datagram_path(p.ida()) == DatagramPath::Relayed;
    }, 15s));
    CHECK(p.a->send_datagram(p.idb(), bytes("a")));
    CHECK(p.b->send_datagram(p.ida(), bytes("b")));
    CHECK(wait_until([&] { return p.count_a() == 1 && p.count_b() == 1; }, 3s));
}

TEST(a_datagram_channel_closes_on_both_ends_and_can_be_opened_again) {
    // Reopening keys the channel under a new epoch. Under the old keys its
    // counter would start from zero again, reusing every nonce -- and the
    // peer's replay window would silently drop what it had already seen.
    LocalServer srv;
    DgramPair   p{srv, config_for(srv), config_for(srv)};
    REQUIRE(p.connect());
    REQUIRE(p.a->open_datagrams(p.idb(), DatagramFallback::None));
    REQUIRE(p.settled(DatagramPath::Direct));
    for (int i = 0; i < 5; ++i) p.a->send_datagram(p.idb(), bytes("first"));
    REQUIRE(wait_until([&] { return p.count_b() >= 3; }, 3s));

    p.a->close_datagrams(p.idb());
    REQUIRE(p.settled(DatagramPath::None, 3s));
    CHECK(!p.a->send_datagram(p.idb(), bytes("closed")));

    const size_t before = p.count_b();
    REQUIRE(p.b->open_datagrams(p.ida(), DatagramFallback::None));  // from the other side
    REQUIRE(p.settled(DatagramPath::Direct));
    for (int i = 0; i < 5; ++i) p.a->send_datagram(p.idb(), bytes("second"));
    CHECK(wait_until([&] { return p.count_b() >= before + 3; }, 3s));
}

TEST(datagrams_need_a_connected_peer_and_respect_the_size_limit) {
    LocalServer srv;
    DgramPair   p{srv, dgram_config(srv, true, DatagramFallback::Tcp),
                  dgram_config(srv, true, DatagramFallback::Tcp)};
    REQUIRE(p.a->publish());
    REQUIRE(p.b->publish());
    CHECK(!p.a->open_datagrams(*p.b->self()));  // not connected yet

    REQUIRE(connect_pair(*p.a, *p.b));
    REQUIRE(p.a->open_datagrams(p.idb(), DatagramFallback::Tcp));
    REQUIRE(p.settled(DatagramPath::Tcp));
    CHECK(p.a->send_datagram(p.idb(), std::vector<uint8_t>(Topic::max_datagram())));
    CHECK(!p.a->send_datagram(p.idb(), std::vector<uint8_t>(Topic::max_datagram() + 1)));
}

TEST(a_local_disconnect_reports_the_close_to_the_local_application) {
    // #47. The peer was erased before its session's Closed event was polled,
    // so the side that hung up never heard on_peer(Closed), on_peer_closed
    // (Local) or the end of its datagram channel. Each must arrive exactly
    // once, on the loop thread, whichever way the local side hangs up.
    enum class How { Disconnect, DisconnectAll, Shutdown };
    for (How how : {How::Disconnect, How::DisconnectAll, How::Shutdown}) {
        LocalServer         srv;
        std::atomic<int>    gone_local{0}, gone_other{0}, closed_state{0}, dgram_none{0};
        std::atomic<bool>   off_loop{false};
        const auto          test_thread = std::this_thread::get_id();
        DgramPair           p{srv, dgram_config(srv, true, DatagramFallback::Tcp),
                                   dgram_config(srv, true, DatagramFallback::Tcp)};
        REQUIRE(p.connect());
        REQUIRE(p.a->open_datagrams(p.idb(), DatagramFallback::Tcp));
        REQUIRE(p.settled(DatagramPath::Tcp));

        auto note_thread = [&] { if (std::this_thread::get_id() == test_thread) off_loop = true; };
        p.a->on_peer_closed([&](DevId, PeerGone why) {
            note_thread();
            ++(why == PeerGone::Local ? gone_local : gone_other);
        });
        p.a->on_peer([&](DevId, PeerState s) {
            note_thread();
            if (s == PeerState::Closed) ++closed_state;
        });
        p.a->on_datagram_path([&](DevId, DatagramPath dp) {
            note_thread();
            if (dp == DatagramPath::None) ++dgram_none;
        });

        switch (how) {
            case How::Disconnect:    p.a->disconnect(p.idb()); break;
            case How::DisconnectAll: p.a->disconnect_all(); break;
            case How::Shutdown:      p.na.shutdown(); break;
        }
        CHECK(wait_until([&] {
            return gone_local.load() >= 1 && closed_state.load() >= 1 && dgram_none.load() >= 1;
        }, 3s));
        std::this_thread::sleep_for(300ms);  // and nothing more after that
        CHECK_EQ(gone_local.load(), 1);
        CHECK_EQ(gone_other.load(), 0);
        CHECK_EQ(closed_state.load(), 1);
        CHECK_EQ(dgram_none.load(), 1);
        CHECK(!off_loop.load());
    }
}

TEST(a_stranger_probing_the_udp_port_gets_no_answer) {
    // Probes are tagged with the channel's probe key, which only the peer
    // holds: nobody else can make the node reveal it is listening.
    LocalServer srv;
    DgramPair   p{srv, config_for(srv), config_for(srv)};
    REQUIRE(p.connect());
    REQUIRE(p.a->open_datagrams(p.idb(), DatagramFallback::None));
    REQUIRE(p.settled(DatagramPath::Direct));

    io::UdpSocket stranger;
    REQUIRE(stranger.open(0, "127.0.0.1"));
    std::vector<uint8_t> probe(64);
    wire::Writer         w{probe};
    wire::Header{wire::MsgType::Probe, wire::kVersion, 0, 1}.encode(w);
    wire::Probe pr;
    pr.txn.fill(0x31);
    pr.encode(w);  // an all-zero tag, as an open topic once used
    probe.resize(w.size());
    // The node binds UDP on its TCP port's number when it can.
    stranger.send_to(Endpoint{IpAddr::v4(127, 0, 0, 1), p.na.local_port()}, probe);

    CHECK(!stranger.wait_readable(300ms));
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

TEST(incoming_introductions_obey_zero_peer_limits) {
    for (bool node_limit : {false, true}) {
        LocalServer srv;
        auto cfg = config_for(srv, true);
        if (node_limit) cfg.max_total_peers = 0;
        Node victim{cfg}, caller{config_for(srv, true)};
        victim.run_in_background();
        caller.run_in_background();
        auto creds = TopicCreds::generate_keyed();
        auto& v = victim.join(creds);
        auto& c = caller.join(creds);
        if (!node_limit) v.set_max_peers(0);
        REQUIRE(v.publish());
        REQUIRE(c.publish());
        c.peers();
        c.connect(*v.self());
        CHECK(!wait_until([&] { return v.state(*c.self()) != PeerState::Unknown; }, 1500ms));
        CHECK(v.connected().empty());
    }
}

TEST(incoming_introductions_obey_full_limits_and_reuse_freed_capacity) {
    for (bool node_limit : {false, true}) {
        LocalServer srv;
        auto cfg = config_for(srv, true);
        if (node_limit) cfg.max_total_peers = 1;
        Node victim{cfg}, first{config_for(srv, true)};
        victim.run_in_background();
        first.run_in_background();
        auto creds = TopicCreds::generate_open();
        auto& v = victim.join(creds);
        auto& f = first.join(creds);
        if (!node_limit) v.set_max_peers(1);
        REQUIRE(v.publish());
        REQUIRE(f.publish());
        REQUIRE(connect_pair(v, f));
        // A global limit must also prevent admission through another topic.
        auto& target = node_limit ? victim.join(TopicCreds::generate_open()) : v;
        REQUIRE(target.publish());
        RawConn caller{srv.endpoint()};
        auto caller_id = caller.register_in(target.id());
        REQUIRE(caller_id.has_value());
        auto introduce = [&](uint8_t nonce) {
            std::vector<uint8_t> intro(target.id().begin(), target.id().end());
            intro.insert(intro.end(), 16, nonce);
            intro.push_back(0);
            ctl::Connect c;
            c.from_dev = *caller_id;
            c.to_dev = *target.self();
            c.payload = std::move(intro);
            caller.send_raw(ctl::frame(ctl::message(wire::MsgType::Connect, nonce, c)));
        };
        introduce(1);
        CHECK(!wait_until([&] { return target.state(*caller_id) != PeerState::Unknown; }, 1500ms));
        CHECK(v.state(*f.self()) == PeerState::Connected);
        v.disconnect(*f.self());
        introduce(2);
        CHECK(wait_until([&] { return target.state(*caller_id) == PeerState::Probing; }, 2s));
    }
}

TEST(shutdown_from_a_callback_stops_both_loop_modes_without_throwing) {
    for (bool background : {true, false}) {
        LocalServer srv;
        std::atomic<bool> returned{false}, threw{false}, notified{false};
        Node na{config_for(srv, true)}, nb{config_for(srv, true)};
        struct Runner {
            Node& node;
            std::thread thread;
            ~Runner() { node.shutdown(); if (thread.joinable()) thread.join(); }
        } runner{na, {}};
        if (background) na.run_in_background();
        else runner.thread = std::thread([&] { na.run(); });
        nb.run_in_background();
        auto creds = TopicCreds::generate_keyed();
        auto& a = na.join(creds);
        auto& b = nb.join(creds);
        REQUIRE(a.publish());
        REQUIRE(b.publish());
        REQUIRE(connect_pair(a, b));
        const auto ida = *a.self();
        b.on_peer_closed([&](DevId, PeerGone why) { notified = why == PeerGone::ShuttingDown; });
        a.on_data([&](DevId, std::span<const uint8_t>) {
            try { na.shutdown(); }
            catch (const std::system_error&) { threw = true; }
            returned = true;
        });
        REQUIRE(b.send(ida, bytes("stop")));
        REQUIRE(wait_until([&] { return returned.load(); }, 3s));
        CHECK(!threw.load());
        CHECK(wait_until([&] { return !na.is_running(); }, 3s));
        na.shutdown(); // joins a completed background loop; repeated calls are safe
        CHECK(na.topics().empty());
        CHECK(!na.server_connected());
        CHECK(wait_until([&] { return notified.load(); }, 3s));
    }
}

TEST(tcp_fallback_datagrams_share_message_backpressure_and_resume_after_draining) {
    LocalServer srv;
    std::atomic<bool> blocked{false}, release{false};
    std::atomic<size_t> messages{0}, datagrams{0};
    DgramPair p{srv, dgram_config(srv, true, DatagramFallback::Tcp),
                    dgram_config(srv, true, DatagramFallback::Tcp)};
    // Unblock before the nodes are destroyed even when a REQUIRE fails.
    struct Release { std::atomic<bool>& flag; ~Release() { flag = true; } } guard{release};
    REQUIRE(p.connect());
    REQUIRE(p.a->open_datagrams(p.idb(), DatagramFallback::Tcp));
    REQUIRE(p.settled(DatagramPath::Tcp));
    p.b->on_data([&](DevId, std::span<const uint8_t> data) {
        if (data.size() == 1) {
            blocked = true;
            while (!release) std::this_thread::sleep_for(1ms);
        } else { ++messages; }
    });
    p.b->on_datagram([&](DevId, std::span<const uint8_t>) { ++datagrams; });
    REQUIRE(p.a->send(p.idb(), bytes("x")));
    REQUIRE(wait_until([&] { return blocked.load(); }, 3s));

    std::vector<uint8_t> message(Topic::max_message(), 0x42);
    size_t sent_messages = 0;
    while (sent_messages < 128 && p.a->send(p.idb(), message)) ++sent_messages;
    REQUIRE(sent_messages > 0 && sent_messages < 128);
    // A last rejected large message can leave at most one message's space.
    // Four MiB of small datagrams must hit that same queue limit.
    std::vector<uint8_t> datagram(Topic::max_datagram(), 0x17);
    size_t sent_datagrams = 0;
    while (sent_datagrams < 4096 && p.a->send_datagram(p.idb(), datagram)) ++sent_datagrams;
    CHECK(sent_datagrams < 4096);
    REQUIRE(p.a->state(p.idb()) == PeerState::Connected);
    CHECK(p.a->link(p.idb())->datagrams_sent == sent_datagrams);
    release = true;
    REQUIRE(wait_until([&] { return messages == sent_messages && datagrams == sent_datagrams; }, 15s));
    REQUIRE(p.a->send_datagram(p.idb(), datagram));
    CHECK(wait_until([&] { return datagrams == sent_datagrams + 1; }, 3s));
}

TEST(blocking_queries_from_callbacks_fail_promptly_without_requests_or_side_effects) {
    LocalServer srv;
    std::atomic<int> calls{0};
    std::atomic<bool> rejected{false};
    std::atomic<int64_t> elapsed_ms{-1};
    Pair p{srv, true};
    REQUIRE(p.publish());
    REQUIRE(connect_pair(*p.a, *p.b));
    auto before = p.na.stats();
    REQUIRE(before.has_value());
    const auto ida = p.ida(), idb = p.idb();
    p.a->on_data([&](DevId, std::span<const uint8_t>) {
        if (calls.load() == 0) {
            const auto start = std::chrono::steady_clock::now();
            bool failed = p.a->peers(10, false, 250ms).empty();
            failed &= !p.a->resolve(idb, 250ms).has_value();
            failed &= !p.na.stats(250ms).has_value();
            failed &= p.na.explore(0, 10, 250ms).empty();
            failed &= !p.a->publish();
            rejected = failed;
            elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
        }
        ++calls;
    });
    REQUIRE(p.b->send(ida, bytes("queries")));
    REQUIRE(wait_until([&] { return calls.load() == 1; }, 8s));
    CHECK(rejected.load());
    CHECK(elapsed_ms.load() < 200);
    auto after = p.na.stats();
    REQUIRE(after.has_value());
    CHECK(after->registers == before->registers);
    CHECK(after->lookups == before->lookups);
    REQUIRE(p.b->send(ida, bytes("still live")));
    CHECK(wait_until([&] { return calls.load() == 2; }, 2s));
}
