// C API tests: uconnect_c.h used the way an FFI caller uses it, through the
// shared library, against a rendezvous server hosted in-process.
//
// Behaviour proper is covered by test_node.cpp; these check what the C layer
// adds -- conversions, topics named by id, the event queue, and errors that
// arrive as return values instead of exceptions.

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "rendezvous.hpp"
#include "testing.hpp"
#include "uconnect/uconnect_c.h"

using namespace std::chrono_literals;

namespace {

// A rendezvous server on loopback, on its own thread.
class LocalServer {
public:
    LocalServer() {
        uconnect::server::RendezvousConfig cfg;
        cfg.port = 0;
        rv_      = std::make_unique<uconnect::server::Rendezvous>(cfg);
        if (!rv_->open()) throw std::runtime_error("LocalServer: " + rv_->error());
        address_ = "127.0.0.1:" + std::to_string(rv_->port());
        thread_  = std::thread([this] {
            while (!stop_) rv_->poll_once(5ms);
        });
    }
    ~LocalServer() {
        stop_ = true;
        thread_.join();
    }
    LocalServer(const LocalServer&)            = delete;
    LocalServer& operator=(const LocalServer&) = delete;

    const std::string& address() const { return address_; }

private:
    std::unique_ptr<uconnect::server::Rendezvous> rv_;
    std::string                                   address_;
    std::atomic<bool>                             stop_{false};
    std::thread                                   thread_;
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

struct NodeFree {
    void operator()(uconnect_node* n) const { uconnect_node_free(n); }
};
using NodePtr = std::unique_ptr<uconnect_node, NodeFree>;

// A node for `server`, not yet running; null if construction failed.
NodePtr make_node(const std::string& server) {
    uconnect_node_config cfg;
    uconnect_node_config_init(&cfg);
    cfg.server  = server.c_str();
    cfg.verbose = std::getenv("UCONNECT_TEST_VERBOSE") != nullptr;
    return NodePtr{uconnect_node_new(&cfg)};
}

NodePtr start_node(const LocalServer& srv) {
    NodePtr n = make_node(srv.address());
    if (n) uconnect_node_run_in_background(n.get());
    return n;
}

template <typename T>
bool same(const T& a, const T& b) {
    return std::memcmp(a.bytes, b.bytes, sizeof a.bytes) == 0;
}

// Drains n's event queue until an event satisfies `match`, or time runs out.
template <typename P>
bool await_event(uconnect_node* n, P&& match, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        uconnect_event* e = uconnect_node_next_event(n, 50);
        if (!e) continue;
        const bool hit = match(*e);
        uconnect_event_free(e);
        if (hit) return true;
    }
    return false;
}

// What a C callback was last handed, for a test to read from its own thread.
struct Inbox {
    std::mutex  mu;
    std::string got;
};

void inbox_on_data(void* user, uconnect_dev_id, const uint8_t* data, size_t len) {
    auto*                       in = static_cast<Inbox*>(user);
    std::lock_guard<std::mutex> lk(in->mu);
    in->got.assign(reinterpret_cast<const char*>(data), len);
}

}  // namespace

// ---------------------------------------------------------------------------
// Offline
// ---------------------------------------------------------------------------
TEST(capi_creds_round_trip_through_a_uri) {
    for (bool keyed : {true, false}) {
        uconnect_topic_creds c;
        REQUIRE(uconnect_creds_generate(keyed, &c));
        CHECK_EQ(c.keyed, keyed);

        char         uri[UCONNECT_URI_MAX];
        const size_t len = uconnect_creds_to_uri(&c, uri, sizeof uri);
        REQUIRE(len < sizeof uri);
        CHECK_EQ(std::strlen(uri), len);

        uconnect_topic_creds back;
        REQUIRE(uconnect_creds_parse(uri, &back));
        CHECK(same(back.id, c.id));
        CHECK_EQ(back.keyed, keyed);
        if (keyed) CHECK(same(back.key, c.key));
    }

    uconnect_topic_creds junk;
    CHECK(!uconnect_creds_parse("uconn://not-hex", &junk));
    CHECK(!uconnect_creds_parse(nullptr, &junk));
}

TEST(capi_to_uri_reports_the_length_it_needed_when_truncated) {
    uconnect_topic_creds c;
    REQUIRE(uconnect_creds_generate(true, &c));
    char small[10];
    CHECK_EQ(uconnect_creds_to_uri(&c, small, sizeof small), UCONNECT_URI_MAX - 1);
    CHECK_EQ(std::strlen(small), sizeof small - 1);
}

TEST(capi_node_new_refuses_a_bad_config_and_says_why) {
    uconnect_node_config cfg;
    uconnect_node_config_init(&cfg);
    CHECK(uconnect_node_new(&cfg) == nullptr);  // no server
    CHECK(std::strlen(uconnect_last_error()) > 0);

    cfg.server      = "127.0.0.1:9";
    cfg.rekey_shift = 0;
    CHECK(uconnect_node_new(&cfg) == nullptr);
    CHECK(std::string(uconnect_last_error()).find("rekey_shift") != std::string::npos);

    cfg.rekey_shift = 16;
    NodePtr n{uconnect_node_new(&cfg)};
    CHECK(n != nullptr);
    CHECK_EQ(std::strlen(uconnect_last_error()), 0u);
}

TEST(capi_topic_calls_race_leave_and_join_without_dangling) {
    // Calls on a topic from several threads while another joins and leaves it
    // over and over. Each call must find the topic joined and alive, or
    // absent -- never half-destroyed. A crash here, or a report from a
    // sanitizer, is the failure; there is nothing else to check.
    NodePtr n = make_node("127.0.0.1:9");  // never run: nothing here needs the server
    REQUIRE(n);
    uconnect_topic_creds c;
    REQUIRE(uconnect_creds_generate(true, &c));

    std::atomic<bool>        stop{false};
    std::vector<std::thread> callers;
    for (int i = 0; i < 4; ++i) {
        callers.emplace_back([&] {
            const uconnect_dev_id dev{};
            uconnect_dev_id       out[4];
            while (!stop) {
                (void)uconnect_topic_state(n.get(), c.id, dev);
                (void)uconnect_topic_connected(n.get(), c.id, out, 4);
                (void)uconnect_topic_is_authenticated(n.get(), c.id);
                uconnect_topic_set_max_peers(n.get(), c.id, 8);
                uconnect_topic_queue_events(n.get(), c.id);
            }
        });
    }
    for (int i = 0; i < 500; ++i) {
        CHECK(uconnect_node_join(n.get(), &c));
        uconnect_node_leave(n.get(), c.id);
    }
    stop = true;
    for (auto& t : callers) t.join();
    CHECK_EQ(uconnect_node_topics(n.get(), nullptr, 0), 0u);
}

// ---------------------------------------------------------------------------
// Over loopback, against a LocalServer
// ---------------------------------------------------------------------------
TEST(capi_two_nodes_exchange_messages_by_callback_and_by_event_queue) {
    LocalServer srv;
    Inbox       inbox;  // declared before the nodes, so it outlives their callbacks
    NodePtr     a = start_node(srv);
    NodePtr     b = start_node(srv);
    REQUIRE(a && b);

    uconnect_topic_creds c;
    REQUIRE(uconnect_node_create(a.get(), true, &c));
    REQUIRE(uconnect_node_join(b.get(), &c));
    const uconnect_topic_id t = c.id;

    // a takes its messages by callback, b from the queue.
    uconnect_topic_on_data(a.get(), t, inbox_on_data, &inbox);
    uconnect_topic_queue_events(b.get(), t);

    REQUIRE(uconnect_topic_publish(a.get(), t, nullptr, 0, false));
    REQUIRE(uconnect_topic_publish(b.get(), t, nullptr, 0, false));
    uconnect_dev_id ida, idb;
    REQUIRE(uconnect_topic_self(a.get(), t, &ida));
    REQUIRE(uconnect_topic_self(b.get(), t, &idb));

    // Learn each other's candidates, then dial from both ends.
    uconnect_peer_list* pa = uconnect_topic_peers(a.get(), t, 30, false, UCONNECT_DEFAULT_TIMEOUT_MS);
    uconnect_peer_list* pb = uconnect_topic_peers(b.get(), t, 30, false, UCONNECT_DEFAULT_TIMEOUT_MS);
    CHECK(pa != nullptr && pb != nullptr);
    CHECK_EQ(uconnect_peer_list_size(pa), 1u);
    uconnect_peer_info info;
    CHECK(uconnect_peer_list_get(pa, 0, &info) && same(info.dev_id, idb));
    CHECK(!uconnect_peer_list_get(pa, 1, &info));
    uconnect_peer_list_free(pa);
    uconnect_peer_list_free(pb);

    uconnect_topic_connect(a.get(), t, idb);
    uconnect_topic_connect(b.get(), t, ida);
    REQUIRE(wait_until([&] {
        return uconnect_topic_state(a.get(), t, idb) == UCONNECT_PEER_CONNECTED &&
               uconnect_topic_state(b.get(), t, ida) == UCONNECT_PEER_CONNECTED;
    }, 20s));

    CHECK(await_event(b.get(), [&](const uconnect_event& e) {
        return e.kind == UCONNECT_EVENT_PEER && e.peer_state == UCONNECT_PEER_CONNECTED &&
               same(e.topic, t) && same(e.dev, ida);
    }, 3s));

    const uint8_t hello[] = {'h', 'e', 'l', 'l', 'o'};
    REQUIRE(uconnect_topic_send(a.get(), t, idb, hello, sizeof hello));
    CHECK(await_event(b.get(), [&](const uconnect_event& e) {
        return e.kind == UCONNECT_EVENT_DATA && same(e.dev, ida) &&
               std::string(reinterpret_cast<const char*>(e.data), e.len) == "hello";
    }, 3s));

    const uint8_t world[] = {'w', 'o', 'r', 'l', 'd'};
    REQUIRE(uconnect_topic_send(b.get(), t, ida, world, sizeof world));
    CHECK(wait_until([&] {
        std::lock_guard<std::mutex> lk(inbox.mu);
        return inbox.got == "world";
    }, 3s));

    uconnect_link_info li;
    REQUIRE(uconnect_topic_link(a.get(), t, idb, &li));
    CHECK_EQ(li.messages_sent, 1u);
    CHECK_EQ(li.messages_received, 1u);

    // A NULL pointer with a length is refused, not dereferenced.
    CHECK(!uconnect_topic_send(a.get(), t, idb, nullptr, 5));
}

TEST(capi_a_left_topic_is_absent_rather_than_dangling) {
    LocalServer srv;
    NodePtr     n = start_node(srv);
    REQUIRE(n);

    uconnect_topic_creds c;
    REQUIRE(uconnect_node_create(n.get(), false, &c));
    uconnect_topic_creds got;
    CHECK(uconnect_node_creds(n.get(), c.id, &got) && !got.keyed && same(got.id, c.id));
    CHECK_EQ(uconnect_node_topics(n.get(), nullptr, 0), 1u);
    REQUIRE(uconnect_topic_publish(n.get(), c.id, nullptr, 0, false));

    uconnect_node_leave(n.get(), c.id);
    CHECK(!uconnect_node_creds(n.get(), c.id, &got));
    CHECK_EQ(uconnect_node_topics(n.get(), nullptr, 0), 0u);
    CHECK(!uconnect_topic_publish(n.get(), c.id, nullptr, 0, false));
    uconnect_dev_id self;
    CHECK(!uconnect_topic_self(n.get(), c.id, &self));
    CHECK(uconnect_topic_peers(n.get(), c.id, 30, false, UCONNECT_DEFAULT_TIMEOUT_MS) == nullptr);
    CHECK_EQ(std::strlen(uconnect_last_error()), 0u);  // absent is not an error

    uconnect_node_leave(n.get(), c.id);  // leaving twice is harmless
}

TEST(capi_shutdown_retires_every_topic_and_wakes_the_event_queue) {
    LocalServer srv;
    NodePtr     n = start_node(srv);
    REQUIRE(n);
    uconnect_topic_creds c;
    REQUIRE(uconnect_node_create(n.get(), true, &c));
    uconnect_topic_queue_events(n.get(), c.id);

    std::thread consumer([&] {
        while (uconnect_event* e = uconnect_node_next_event(n.get(), 10000)) uconnect_event_free(e);
    });
    std::this_thread::sleep_for(100ms);  // let it block

    const auto t0 = std::chrono::steady_clock::now();
    uconnect_node_shutdown(n.get());
    consumer.join();
    CHECK(std::chrono::steady_clock::now() - t0 < 5s);  // woken, not timed out

    CHECK(!uconnect_node_is_running(n.get()));
    uconnect_topic_creds got;
    CHECK(!uconnect_node_creds(n.get(), c.id, &got));
    CHECK_EQ(uconnect_node_topics(n.get(), nullptr, 0), 0u);
    CHECK(!uconnect_node_join(n.get(), &c));
}
