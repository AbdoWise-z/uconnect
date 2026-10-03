// The C API (uconnect_c.h) over Node and Topic.
//
// Almost all of this is translation: fixed-size structs to std::array, enums
// to enums, std::optional to a bool and an out-parameter. The two parts with
// real logic are the topic table, which is what lets callers name topics by id
// without ever holding a Topic& that leave() or shutdown() could pull away,
// and the event queue, for callers that cannot be called back on a foreign
// thread.

#include "uconnect/uconnect_c.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <exception>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "uconnect/uconnect.hpp"

using namespace uconnect;

// The C enums are declared by value so that a C header needs nothing from
// C++; these keep the two from drifting apart.
#define UCONNECT_SAME(c_value, cpp_value) \
    static_assert(static_cast<int>(c_value) == static_cast<int>(cpp_value), #c_value)

UCONNECT_SAME(UCONNECT_TOPIC_OPEN, TopicMode::Open);
UCONNECT_SAME(UCONNECT_TOPIC_KEYED, TopicMode::Keyed);

UCONNECT_SAME(UCONNECT_PEER_UNKNOWN, PeerState::Unknown);
UCONNECT_SAME(UCONNECT_PEER_PROBING, PeerState::Probing);
UCONNECT_SAME(UCONNECT_PEER_HANDSHAKING, PeerState::Handshaking);
UCONNECT_SAME(UCONNECT_PEER_CONNECTED, PeerState::Connected);
UCONNECT_SAME(UCONNECT_PEER_FAILED, PeerState::Failed);
UCONNECT_SAME(UCONNECT_PEER_CLOSED, PeerState::Closed);

UCONNECT_SAME(UCONNECT_GONE_LOCAL, PeerGone::Local);
UCONNECT_SAME(UCONNECT_GONE_TIMED_OUT, PeerGone::TimedOut);
UCONNECT_SAME(UCONNECT_GONE_GOING_AWAY, PeerGone::GoingAway);
UCONNECT_SAME(UCONNECT_GONE_SHUTTING_DOWN, PeerGone::ShuttingDown);
UCONNECT_SAME(UCONNECT_GONE_UNSPECIFIED, PeerGone::Unspecified);

UCONNECT_SAME(UCONNECT_DATAGRAM_FALLBACK_TCP, DatagramFallback::Tcp);
UCONNECT_SAME(UCONNECT_DATAGRAM_FALLBACK_RELAY, DatagramFallback::Relay);
UCONNECT_SAME(UCONNECT_DATAGRAM_FALLBACK_NONE, DatagramFallback::None);

UCONNECT_SAME(UCONNECT_DATAGRAM_PATH_NONE, DatagramPath::None);
UCONNECT_SAME(UCONNECT_DATAGRAM_PATH_OPENING, DatagramPath::Opening);
UCONNECT_SAME(UCONNECT_DATAGRAM_PATH_DIRECT, DatagramPath::Direct);
UCONNECT_SAME(UCONNECT_DATAGRAM_PATH_RELAYED, DatagramPath::Relayed);
UCONNECT_SAME(UCONNECT_DATAGRAM_PATH_TCP, DatagramPath::Tcp);
UCONNECT_SAME(UCONNECT_DATAGRAM_PATH_FAILED, DatagramPath::Failed);

#undef UCONNECT_SAME

static_assert(sizeof(uconnect_topic_id::bytes) == kTopicIdLen);
static_assert(sizeof(uconnect_dev_id::bytes) == kDevIdLen);
static_assert(sizeof(uconnect_key::bytes) == kKeyLen);
static_assert(UCONNECT_URI_MAX == sizeof("uconn://#") + 2 * kTopicIdLen + 2 * kKeyLen);

// ---------------------------------------------------------------------------
// The opaque types
// ---------------------------------------------------------------------------
struct uconnect_peer_list {
    std::vector<PeerInfo> peers;
};

struct uconnect_node {
    // One joined topic. Every call on it counts itself in `users` for as long
    // as it uses `topic`; leave and shutdown mark the entry dead, which turns
    // new calls away, and wait for `users` to drain before Node destroys the
    // Topic. (Not a shared_mutex: under MinGW it is a winpthreads rwlock,
    // whose read lock fails with EINVAL when several threads first use a new
    // one at once -- and every join makes a new one.)
    struct Entry {
        std::mutex              mu;
        std::condition_variable idle;
        size_t                  users = 0;     // guarded by mu
        bool                    alive = true;  // guarded by mu
        Topic*                  topic = nullptr;
        TopicCreds              creds;         // as first joined; never changes
    };

    std::mutex                  events_mu;
    std::condition_variable     events_cv;
    std::deque<uconnect_event*> events;
    bool                        events_closed = false;  // shutdown was called

    // Join, leave and shutdown take this first, so that none of them can run
    // between another's change to Node and its change to `topics`.
    std::mutex membership_mu;
    bool       closed = false;  // guarded by membership_mu

    // Guards the map itself, and only for as long as a lookup takes.
    mutable std::mutex                        topics_mu;
    std::map<TopicId, std::shared_ptr<Entry>> topics;

    std::unique_ptr<Node> node;

    ~uconnect_node() {
        node.reset();  // stops the loop thread, the only other poster of events
        for (auto* e : events) std::free(e);
    }

    std::shared_ptr<Entry> find(const TopicId& id) const {
        std::lock_guard<std::mutex> lk(topics_mu);
        auto                        it = topics.find(id);
        return it == topics.end() ? nullptr : it->second;
    }

    void post(uconnect_event* e) noexcept {
        if (!e) return;
        try {
            std::lock_guard<std::mutex> lk(events_mu);
            events.push_back(e);
        } catch (...) {
            std::free(e);
            return;
        }
        events_cv.notify_one();
    }
};

namespace {

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------
thread_local std::string t_last_error;

void remember(const char* what) noexcept {
    try {
        t_last_error = what;
    } catch (...) {
        t_last_error.clear();  // no memory even for the message
    }
}

// Runs f, turning an exception into `fallback` and a message for
// uconnect_last_error. Every entry point that can fail goes through here.
template <typename R, typename F>
R guarded(R fallback, F&& f) noexcept {
    t_last_error.clear();
    try {
        return f();
    } catch (const std::exception& e) {
        remember(e.what());
    } catch (...) {
        remember("uconnect: unknown exception");
    }
    return fallback;
}

template <typename F>
void guarded_void(F&& f) noexcept {
    guarded(0, [&] {
        f();
        return 0;
    });
}

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------
std::array<uint8_t, 16> to_cpp(const uint8_t (&bytes)[16]) {
    std::array<uint8_t, 16> out;
    std::memcpy(out.data(), bytes, out.size());
    return out;
}

TopicId to_cpp(uconnect_topic_id id) { return to_cpp(id.bytes); }
DevId   to_cpp(uconnect_dev_id id) { return to_cpp(id.bytes); }

// TopicId and DevId are one type, so these cannot be overloads.
uconnect_topic_id to_c_topic(const TopicId& id) {
    uconnect_topic_id out;
    std::memcpy(out.bytes, id.data(), sizeof out.bytes);
    return out;
}

uconnect_dev_id to_c_dev(const DevId& id) {
    uconnect_dev_id out;
    std::memcpy(out.bytes, id.data(), sizeof out.bytes);
    return out;
}

TopicCreds to_cpp(const uconnect_topic_creds& c) {
    TopicCreds out;
    out.id = to_cpp(c.id);
    if (c.keyed) {
        Key k;
        std::memcpy(k.data(), c.key.bytes, k.size());
        out.key = k;
    }
    return out;
}

uconnect_topic_creds to_c(const TopicCreds& c) {
    uconnect_topic_creds out{};
    out.id    = to_c_topic(c.id);
    out.keyed = c.is_keyed();
    if (c.key) std::memcpy(out.key.bytes, c.key->data(), sizeof out.key.bytes);
    return out;
}

std::chrono::milliseconds ms(uint32_t timeout_ms) { return std::chrono::milliseconds(timeout_ms); }

// A (pointer, length) pair from C as a span; false for NULL with a length.
bool as_span(const uint8_t* data, size_t len, std::span<const uint8_t>& out) {
    if (!data && len) return false;
    out = data ? std::span<const uint8_t>(data, len) : std::span<const uint8_t>{};
    return true;
}

// snprintf-style: writes what fits, always NUL-terminated if cap > 0, and
// returns the full length.
size_t copy_string(const std::string& s, char* buf, size_t cap) {
    if (buf && cap) {
        const size_t k = std::min(s.size(), cap - 1);
        std::memcpy(buf, s.data(), k);
        buf[k] = '\0';
    }
    return s.size();
}

// Writes what fits of `ids` to out[0..cap) and returns how many there are.
template <typename C, typename Convert>
size_t copy_ids(const std::vector<std::array<uint8_t, 16>>& ids, C* out, size_t cap,
                Convert convert) {
    if (out) {
        const size_t k = std::min(ids.size(), cap);
        for (size_t i = 0; i < k; ++i) out[i] = convert(ids[i]);
    }
    return ids.size();
}

size_t copy_summaries(const std::vector<TopicSummary>& got, uconnect_topic_summary* out,
                      size_t cap) {
    if (!out) return 0;
    const size_t k = std::min(got.size(), cap);
    for (size_t i = 0; i < k; ++i) {
        out[i].id          = to_c_topic(got[i].id);
        out[i].mode        = static_cast<uconnect_topic_mode>(got[i].mode);
        out[i].peers       = got[i].peers;
        out[i].fresh_peers = got[i].fresh_peers;
    }
    return k;
}

bool valid_fallback(uconnect_datagram_fallback f) {
    return f == UCONNECT_DATAGRAM_FALLBACK_TCP || f == UCONNECT_DATAGRAM_FALLBACK_RELAY ||
           f == UCONNECT_DATAGRAM_FALLBACK_NONE;
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------
// One allocation per event, with the payload directly behind the struct, so
// that uconnect_event_free -- and a C caller -- need only free().
uconnect_event* make_event(uconnect_event_kind kind, const TopicId& topic, const DevId& dev,
                           std::span<const uint8_t> data = {}) noexcept {
    auto* e = static_cast<uconnect_event*>(std::malloc(sizeof(uconnect_event) + data.size()));
    if (!e) return nullptr;
    *e       = uconnect_event{};
    e->kind  = kind;
    e->topic = to_c_topic(topic);
    e->dev   = to_c_dev(dev);
    if (!data.empty()) {
        auto* body = reinterpret_cast<uint8_t*>(e + 1);
        std::memcpy(body, data.data(), data.size());
        e->data = body;
        e->len  = data.size();
    }
    return e;
}

// ---------------------------------------------------------------------------
// Topics by id
// ---------------------------------------------------------------------------
// Counts a call in an entry's `users` for as long as it lives, if the entry is
// alive; topic() is null if it was not.
class TopicUse {
public:
    explicit TopicUse(std::shared_ptr<uconnect_node::Entry> e) : e_(std::move(e)) {
        if (!e_) return;
        bool alive;
        {
            std::lock_guard<std::mutex> lk(e_->mu);
            alive = e_->alive;
            if (alive) ++e_->users;
        }
        if (!alive) e_.reset();  // outside the lock: this may be the last reference
    }
    ~TopicUse() {
        if (!e_) return;
        std::lock_guard<std::mutex> lk(e_->mu);
        if (--e_->users == 0) e_->idle.notify_all();
    }
    TopicUse(const TopicUse&)            = delete;
    TopicUse& operator=(const TopicUse&) = delete;

    Topic* topic() const { return e_ ? e_->topic : nullptr; }

private:
    std::shared_ptr<uconnect_node::Entry> e_;
};

// Turns new calls on the entry away, then waits for those in progress.
void retire(uconnect_node::Entry& e) {
    std::unique_lock<std::mutex> lk(e.mu);
    e.alive = false;
    e.idle.wait(lk, [&] { return e.users == 0; });
}

// Runs f on the topic named by id while holding it against leave and
// shutdown, or returns fallback if it is not joined.
template <typename R, typename F>
R with_topic(const uconnect_node* n, uconnect_topic_id id, R fallback, F&& f) noexcept {
    return guarded(fallback, [&]() -> R {
        if (!n) return fallback;
        TopicUse use{n->find(to_cpp(id))};
        if (!use.topic()) return fallback;
        return f(*use.topic());
    });
}

template <typename F>
void with_topic_void(const uconnect_node* n, uconnect_topic_id id, F&& f) noexcept {
    with_topic(n, id, 0, [&](Topic& t) {
        f(t);
        return 0;
    });
}

}  // namespace

// ---------------------------------------------------------------------------
// Value types
// ---------------------------------------------------------------------------
const char* uconnect_peer_state_name(uconnect_peer_state s) {
    return to_string(static_cast<PeerState>(s));
}

const char* uconnect_peer_gone_name(uconnect_peer_gone g) {
    return to_string(static_cast<PeerGone>(g));
}

const char* uconnect_datagram_path_name(uconnect_datagram_path p) {
    return to_string(static_cast<DatagramPath>(p));
}

size_t uconnect_max_message(void) { return Topic::max_message(); }
size_t uconnect_max_datagram(void) { return Topic::max_datagram(); }

const char* uconnect_last_error(void) { return t_last_error.c_str(); }

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------
bool uconnect_creds_generate(bool keyed, uconnect_topic_creds* out) {
    return guarded(false, [&] {
        if (!out) return false;
        *out = to_c(keyed ? TopicCreds::generate_keyed() : TopicCreds::generate_open());
        return true;
    });
}

bool uconnect_creds_parse(const char* uri, uconnect_topic_creds* out) {
    return guarded(false, [&] {
        if (!uri || !out) return false;
        auto c = TopicCreds::parse(uri);
        if (!c) return false;
        *out = to_c(*c);
        return true;
    });
}

size_t uconnect_creds_to_uri(const uconnect_topic_creds* c, char* buf, size_t cap) {
    return guarded<size_t>(0, [&]() -> size_t {
        if (!c) return 0;
        return copy_string(to_cpp(*c).to_uri(), buf, cap);
    });
}

// ---------------------------------------------------------------------------
// Peer lists
// ---------------------------------------------------------------------------
size_t uconnect_peer_list_size(const uconnect_peer_list* l) { return l ? l->peers.size() : 0; }

bool uconnect_peer_list_get(const uconnect_peer_list* l, size_t index, uconnect_peer_info* out) {
    if (!l || !out || index >= l->peers.size()) return false;
    const PeerInfo& p = l->peers[index];
    out->dev_id       = to_c_dev(p.dev_id);
    out->age_s        = static_cast<uint32_t>(p.age.count());
    out->stale        = p.stale;
    out->meta         = p.meta.empty() ? nullptr : p.meta.data();
    out->meta_len     = p.meta.size();
    return true;
}

void uconnect_peer_list_free(uconnect_peer_list* l) { delete l; }

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------
void uconnect_node_config_init(uconnect_node_config* c) {
    if (!c) return;
    const Node::Config d;
    c->server            = nullptr;
    c->bind_port         = d.bind_port;
    c->keepalive_s       = static_cast<uint32_t>(d.keepalive.count());
    c->max_total_peers   = d.max_total_peers;
    c->punch_timeout_s   = static_cast<uint32_t>(d.punch_timeout.count());
    c->force_relay       = d.force_relay;
    c->verbose           = d.verbose;
    c->datagram_fallback = static_cast<uconnect_datagram_fallback>(d.datagram_fallback);
    c->rekey_shift       = d.rekey_shift;
}

uconnect_node* uconnect_node_new(const uconnect_node_config* c) {
    return guarded<uconnect_node*>(nullptr, [&] {
        if (!c) throw std::invalid_argument("uconnect: no config");
        if (!c->server) throw std::invalid_argument("uconnect: config.server is required");
        if (!valid_fallback(c->datagram_fallback)) {
            throw std::invalid_argument("uconnect: config.datagram_fallback is out of range");
        }
        Node::Config cfg;
        cfg.server            = c->server;
        cfg.bind_port         = c->bind_port;
        cfg.keepalive         = std::chrono::seconds(c->keepalive_s);
        cfg.max_total_peers   = c->max_total_peers;
        cfg.punch_timeout     = std::chrono::seconds(c->punch_timeout_s);
        cfg.force_relay       = c->force_relay;
        cfg.verbose           = c->verbose;
        cfg.datagram_fallback = static_cast<DatagramFallback>(c->datagram_fallback);
        cfg.rekey_shift       = c->rekey_shift;

        auto n  = std::make_unique<uconnect_node>();
        n->node = std::make_unique<Node>(std::move(cfg));
        return n.release();
    });
}

void uconnect_node_free(uconnect_node* n) {
    if (!n) return;
    uconnect_node_shutdown(n);
    delete n;
}

// --- lifecycle -------------------------------------------------------------
void uconnect_node_run(uconnect_node* n) {
    guarded_void([&] {
        if (n) n->node->run();
    });
}

void uconnect_node_run_in_background(uconnect_node* n) {
    guarded_void([&] {
        if (n) n->node->run_in_background();
    });
}

void uconnect_node_shutdown(uconnect_node* n) {
    guarded_void([&] {
        if (!n) return;
        {
            // Retire every entry before Node destroys the topics behind them,
            // so that every later call finds the entry gone or dead.
            std::lock_guard<std::mutex> m(n->membership_mu);
            if (!n->closed) {
                n->closed = true;
                std::map<TopicId, std::shared_ptr<uconnect_node::Entry>> gone;
                {
                    std::lock_guard<std::mutex> lk(n->topics_mu);
                    gone.swap(n->topics);
                }
                for (auto& [id, e] : gone) {
                    (void)id;
                    retire(*e);
                }
            }
        }
        // Not under membership_mu: from another thread this joins the loop
        // thread, whose callbacks may be waiting on that very lock.
        n->node->shutdown();
        {
            std::lock_guard<std::mutex> lk(n->events_mu);
            n->events_closed = true;
        }
        n->events_cv.notify_all();
    });
}

bool uconnect_node_is_running(const uconnect_node* n) { return n && n->node->is_running(); }

uint16_t uconnect_node_local_port(const uconnect_node* n) { return n ? n->node->local_port() : 0; }

bool uconnect_node_reflexive(const uconnect_node* n, uconnect_endpoint* out) {
    return guarded(false, [&] {
        if (!n || !out) return false;
        auto ep = n->node->reflexive();
        if (!ep) return false;
        out->family = static_cast<uint8_t>(ep->ip.family);
        std::memcpy(out->addr, ep->ip.bytes.data(), sizeof out->addr);
        out->port = ep->port;
        return true;
    });
}

bool uconnect_node_server_connected(const uconnect_node* n) {
    return guarded(false, [&] { return n && n->node->server_connected(); });
}

size_t uconnect_node_pending_requests(const uconnect_node* n) {
    return guarded<size_t>(0, [&]() -> size_t { return n ? n->node->pending_requests() : 0; });
}

// --- discovery without joining ---------------------------------------------
size_t uconnect_node_explore(uconnect_node* n, uint32_t cursor, uconnect_topic_summary* out,
                             size_t cap, uint32_t timeout_ms) {
    return guarded<size_t>(0, [&]() -> size_t {
        if (!n || !out) return 0;
        return copy_summaries(n->node->explore(cursor, cap, ms(timeout_ms)), out, cap);
    });
}

bool uconnect_node_try_explore(uconnect_node* n, uint32_t cursor, uconnect_topic_summary* out,
                               size_t cap, uint32_t timeout_ms, size_t* count) {
    if (count) *count = 0;
    return guarded(false, [&] {
        if (!n || !out) return false;
        auto got = n->node->try_explore(cursor, cap, ms(timeout_ms));
        if (!got) return false;
        const size_t k = copy_summaries(*got, out, cap);
        if (count) *count = k;
        return true;
    });
}

bool uconnect_node_stats(uconnect_node* n, uint32_t timeout_ms, uconnect_server_stats* out) {
    return guarded(false, [&] {
        if (!n || !out) return false;
        auto s = n->node->stats(ms(timeout_ms));
        if (!s) return false;
        out->topics_total     = s->topics_total;
        out->topics_listed    = s->topics_listed;
        out->entries_total    = s->entries_total;
        out->entries_fresh    = s->entries_fresh;
        out->registers        = s->registers;
        out->lookups          = s->lookups;
        out->connects         = s->connects;
        out->expired          = s->expired;
        out->rej_quota        = s->rej_quota;
        out->rej_rate_limited = s->rej_rate_limited;
        out->relays_open      = s->relays_open;
        out->relays_allocated = s->relays_allocated;
        out->relay_bytes      = s->relay_bytes;
        out->connections      = s->connections;
        return true;
    });
}

// --- topics ----------------------------------------------------------------
namespace {

bool join(uconnect_node& n, const TopicCreds& creds) {
    std::lock_guard<std::mutex> m(n.membership_mu);
    if (n.closed) return false;
    Topic& t = n.node->join(creds);

    std::lock_guard<std::mutex> lk(n.topics_mu);
    if (!n.topics.count(creds.id)) {
        auto e   = std::make_shared<uconnect_node::Entry>();
        e->topic = &t;
        e->creds = creds;
        n.topics.emplace(creds.id, std::move(e));
    }
    return true;
}

}  // namespace

bool uconnect_node_join(uconnect_node* n, const uconnect_topic_creds* c) {
    return guarded(false, [&] { return n && c && join(*n, to_cpp(*c)); });
}

bool uconnect_node_create(uconnect_node* n, bool keyed, uconnect_topic_creds* out) {
    return guarded(false, [&] {
        if (!n || !out) return false;
        const TopicCreds creds = keyed ? TopicCreds::generate_keyed() : TopicCreds::generate_open();
        if (!join(*n, creds)) return false;
        *out = to_c(creds);
        return true;
    });
}

void uconnect_node_leave(uconnect_node* n, uconnect_topic_id id) {
    guarded_void([&] {
        if (!n) return;
        const TopicId               tid = to_cpp(id);
        std::lock_guard<std::mutex> m(n->membership_mu);

        std::shared_ptr<uconnect_node::Entry> e;
        {
            std::lock_guard<std::mutex> lk(n->topics_mu);
            auto                        it = n->topics.find(tid);
            if (it == n->topics.end()) return;
            e = std::move(it->second);
            n->topics.erase(it);
        }
        retire(*e);
        n->node->leave(tid);
    });
}

size_t uconnect_node_topics(const uconnect_node* n, uconnect_topic_id* out, size_t cap) {
    return guarded<size_t>(0, [&]() -> size_t {
        if (!n) return 0;
        std::vector<TopicId> ids;
        {
            std::lock_guard<std::mutex> lk(n->topics_mu);
            for (const auto& [id, e] : n->topics) {
                (void)e;
                ids.push_back(id);
            }
        }
        return copy_ids(ids, out, cap, to_c_topic);
    });
}

bool uconnect_node_creds(const uconnect_node* n, uconnect_topic_id id, uconnect_topic_creds* out) {
    return guarded(false, [&] {
        if (!n || !out) return false;
        auto e = n->find(to_cpp(id));
        if (!e) return false;
        *out = to_c(e->creds);
        return true;
    });
}

// ---------------------------------------------------------------------------
// Topic
// ---------------------------------------------------------------------------
// --- membership ------------------------------------------------------------
bool uconnect_topic_publish(uconnect_node* n, uconnect_topic_id id, const uint8_t* meta,
                            size_t meta_len, bool unlisted) {
    return with_topic(n, id, false, [&](Topic& t) {
        std::span<const uint8_t> m;
        return as_span(meta, meta_len, m) && t.publish(m, unlisted);
    });
}

void uconnect_topic_unpublish(uconnect_node* n, uconnect_topic_id id) {
    with_topic_void(n, id, [](Topic& t) { t.unpublish(); });
}

bool uconnect_topic_self(const uconnect_node* n, uconnect_topic_id id, uconnect_dev_id* out) {
    return with_topic(n, id, false, [&](Topic& t) {
        if (!out) return false;
        auto self = t.self();
        if (!self) return false;
        *out = to_c_dev(*self);
        return true;
    });
}

// --- discovery -------------------------------------------------------------
uconnect_peer_list* uconnect_topic_peers(uconnect_node* n, uconnect_topic_id id, uint8_t max,
                                         bool want_meta, uint32_t timeout_ms) {
    return with_topic<uconnect_peer_list*>(n, id, nullptr, [&](Topic& t) -> uconnect_peer_list* {
        auto got = t.try_peers(max, want_meta, ms(timeout_ms));
        if (!got) return nullptr;
        return new uconnect_peer_list{std::move(*got)};
    });
}

uconnect_peer_list* uconnect_topic_resolve(uconnect_node* n, uconnect_topic_id id,
                                           uconnect_dev_id dev, uint32_t timeout_ms) {
    return with_topic<uconnect_peer_list*>(n, id, nullptr, [&](Topic& t) -> uconnect_peer_list* {
        auto got = t.resolve(to_cpp(dev), ms(timeout_ms));
        if (!got) return nullptr;
        auto* l = new uconnect_peer_list;
        try {
            l->peers.push_back(std::move(*got));
        } catch (...) {
            delete l;
            throw;
        }
        return l;
    });
}

// --- connections -----------------------------------------------------------
void uconnect_topic_connect(uconnect_node* n, uconnect_topic_id id, uconnect_dev_id dev) {
    with_topic_void(n, id, [&](Topic& t) { t.connect(to_cpp(dev)); });
}

void uconnect_topic_connect_all(uconnect_node* n, uconnect_topic_id id, size_t max_peers) {
    with_topic_void(n, id, [&](Topic& t) { t.connect_all(max_peers); });
}

void uconnect_topic_disconnect(uconnect_node* n, uconnect_topic_id id, uconnect_dev_id dev) {
    with_topic_void(n, id, [&](Topic& t) { t.disconnect(to_cpp(dev)); });
}

void uconnect_topic_disconnect_all(uconnect_node* n, uconnect_topic_id id) {
    with_topic_void(n, id, [](Topic& t) { t.disconnect_all(); });
}

size_t uconnect_topic_connected(const uconnect_node* n, uconnect_topic_id id,
                                uconnect_dev_id* out, size_t cap) {
    return with_topic<size_t>(n, id, 0, [&](Topic& t) -> size_t {
        return copy_ids(t.connected(), out, cap, to_c_dev);
    });
}

uconnect_peer_state uconnect_topic_state(const uconnect_node* n, uconnect_topic_id id,
                                         uconnect_dev_id dev) {
    return with_topic(n, id, UCONNECT_PEER_UNKNOWN, [&](Topic& t) {
        return static_cast<uconnect_peer_state>(t.state(to_cpp(dev)));
    });
}

bool uconnect_topic_link(const uconnect_node* n, uconnect_topic_id id, uconnect_dev_id dev,
                         uconnect_link_info* out) {
    return with_topic(n, id, false, [&](Topic& t) {
        if (!out) return false;
        auto li = t.link(to_cpp(dev));
        if (!li) return false;
        out->relayed            = li->relayed;
        out->messages_sent      = li->messages_sent;
        out->messages_received  = li->messages_received;
        out->bytes_sent         = li->bytes_sent;
        out->bytes_received     = li->bytes_received;
        out->datagrams_sent     = li->datagrams_sent;
        out->datagrams_received = li->datagrams_received;
        return true;
    });
}

// --- messages --------------------------------------------------------------
bool uconnect_topic_send(uconnect_node* n, uconnect_topic_id id, uconnect_dev_id dev,
                         const uint8_t* data, size_t len) {
    return with_topic(n, id, false, [&](Topic& t) {
        std::span<const uint8_t> body;
        return as_span(data, len, body) && t.send(to_cpp(dev), body);
    });
}

size_t uconnect_topic_broadcast(uconnect_node* n, uconnect_topic_id id, const uint8_t* data,
                                size_t len) {
    return with_topic<size_t>(n, id, 0, [&](Topic& t) -> size_t {
        std::span<const uint8_t> body;
        return as_span(data, len, body) ? t.broadcast(body) : 0;
    });
}

// --- datagrams -------------------------------------------------------------
bool uconnect_topic_open_datagrams(uconnect_node* n, uconnect_topic_id id, uconnect_dev_id dev,
                                   uconnect_datagram_fallback fallback) {
    return with_topic(n, id, false, [&](Topic& t) {
        return valid_fallback(fallback) &&
               t.open_datagrams(to_cpp(dev), static_cast<DatagramFallback>(fallback));
    });
}

void uconnect_topic_close_datagrams(uconnect_node* n, uconnect_topic_id id, uconnect_dev_id dev) {
    with_topic_void(n, id, [&](Topic& t) { t.close_datagrams(to_cpp(dev)); });
}

uconnect_datagram_path uconnect_topic_datagram_path(const uconnect_node* n, uconnect_topic_id id,
                                                    uconnect_dev_id dev) {
    return with_topic(n, id, UCONNECT_DATAGRAM_PATH_NONE, [&](Topic& t) {
        return static_cast<uconnect_datagram_path>(t.datagram_path(to_cpp(dev)));
    });
}

bool uconnect_topic_send_datagram(uconnect_node* n, uconnect_topic_id id, uconnect_dev_id dev,
                                  const uint8_t* data, size_t len) {
    return with_topic(n, id, false, [&](Topic& t) {
        std::span<const uint8_t> body;
        return as_span(data, len, body) && t.send_datagram(to_cpp(dev), body);
    });
}

// --- callbacks -------------------------------------------------------------
void uconnect_topic_on_peer(uconnect_node* n, uconnect_topic_id id, uconnect_peer_fn fn,
                            void* user) {
    with_topic_void(n, id, [&](Topic& t) {
        if (!fn) return t.on_peer(nullptr);
        t.on_peer([fn, user](DevId dev, PeerState s) {
            fn(user, to_c_dev(dev), static_cast<uconnect_peer_state>(s));
        });
    });
}

void uconnect_topic_on_data(uconnect_node* n, uconnect_topic_id id, uconnect_bytes_fn fn,
                            void* user) {
    with_topic_void(n, id, [&](Topic& t) {
        if (!fn) return t.on_data(nullptr);
        t.on_data([fn, user](DevId dev, std::span<const uint8_t> d) {
            fn(user, to_c_dev(dev), d.data(), d.size());
        });
    });
}

void uconnect_topic_on_datagram(uconnect_node* n, uconnect_topic_id id, uconnect_bytes_fn fn,
                                void* user) {
    with_topic_void(n, id, [&](Topic& t) {
        if (!fn) return t.on_datagram(nullptr);
        t.on_datagram([fn, user](DevId dev, std::span<const uint8_t> d) {
            fn(user, to_c_dev(dev), d.data(), d.size());
        });
    });
}

void uconnect_topic_on_datagram_path(uconnect_node* n, uconnect_topic_id id,
                                     uconnect_datagram_path_fn fn, void* user) {
    with_topic_void(n, id, [&](Topic& t) {
        if (!fn) return t.on_datagram_path(nullptr);
        t.on_datagram_path([fn, user](DevId dev, DatagramPath p) {
            fn(user, to_c_dev(dev), static_cast<uconnect_datagram_path>(p));
        });
    });
}

void uconnect_topic_on_peer_closed(uconnect_node* n, uconnect_topic_id id,
                                   uconnect_peer_closed_fn fn, void* user) {
    with_topic_void(n, id, [&](Topic& t) {
        if (!fn) return t.on_peer_closed(nullptr);
        t.on_peer_closed([fn, user](DevId dev, PeerGone why) {
            fn(user, to_c_dev(dev), static_cast<uconnect_peer_gone>(why));
        });
    });
}

// --- policy ----------------------------------------------------------------
void uconnect_topic_set_max_peers(uconnect_node* n, uconnect_topic_id id, size_t max) {
    with_topic_void(n, id, [&](Topic& t) { t.set_max_peers(max); });
}

void uconnect_topic_set_auto_connect(uconnect_node* n, uconnect_topic_id id, bool on) {
    with_topic_void(n, id, [&](Topic& t) { t.set_auto_connect(on); });
}

// --- identity --------------------------------------------------------------
bool uconnect_topic_is_authenticated(const uconnect_node* n, uconnect_topic_id id) {
    return with_topic(n, id, false, [](Topic& t) { return t.is_authenticated(); });
}

size_t uconnect_topic_sas(const uconnect_node* n, uconnect_topic_id id, uconnect_dev_id dev,
                          char* buf, size_t cap) {
    return with_topic<size_t>(n, id, 0, [&](Topic& t) -> size_t {
        auto sas = t.sas(to_cpp(dev));
        return sas ? copy_string(*sas, buf, cap) : 0;
    });
}

bool uconnect_topic_channel_binding(const uconnect_node* n, uconnect_topic_id id,
                                    uconnect_dev_id dev, uint8_t out[32]) {
    return with_topic(n, id, false, [&](Topic& t) {
        if (!out) return false;
        auto cb = t.channel_binding(to_cpp(dev));
        if (!cb) return false;
        std::memcpy(out, cb->data(), cb->size());
        return true;
    });
}

// ---------------------------------------------------------------------------
// Event queue
// ---------------------------------------------------------------------------
void uconnect_topic_queue_events(uconnect_node* n, uconnect_topic_id id) {
    // Each handler captures the node, not the entry: the node outlives the
    // loop thread that calls them (see ~uconnect_node), where an entry may not.
    with_topic_void(n, id, [&](Topic& t) {
        const TopicId tid = t.id();
        t.on_peer([n, tid](DevId dev, PeerState s) {
            auto* e = make_event(UCONNECT_EVENT_PEER, tid, dev);
            if (e) e->peer_state = static_cast<uconnect_peer_state>(s);
            n->post(e);
        });
        t.on_data([n, tid](DevId dev, std::span<const uint8_t> d) {
            n->post(make_event(UCONNECT_EVENT_DATA, tid, dev, d));
        });
        t.on_datagram([n, tid](DevId dev, std::span<const uint8_t> d) {
            n->post(make_event(UCONNECT_EVENT_DATAGRAM, tid, dev, d));
        });
        t.on_datagram_path([n, tid](DevId dev, DatagramPath p) {
            auto* e = make_event(UCONNECT_EVENT_DATAGRAM_PATH, tid, dev);
            if (e) e->datagram_path = static_cast<uconnect_datagram_path>(p);
            n->post(e);
        });
        t.on_peer_closed([n, tid](DevId dev, PeerGone why) {
            auto* e = make_event(UCONNECT_EVENT_PEER_CLOSED, tid, dev);
            if (e) e->peer_gone = static_cast<uconnect_peer_gone>(why);
            n->post(e);
        });
    });
}

uconnect_event* uconnect_node_next_event(uconnect_node* n, uint32_t timeout_ms) {
    return guarded<uconnect_event*>(nullptr, [&]() -> uconnect_event* {
        if (!n) return nullptr;
        std::unique_lock<std::mutex> lk(n->events_mu);
        n->events_cv.wait_for(lk, ms(timeout_ms),
                              [&] { return !n->events.empty() || n->events_closed; });
        if (n->events.empty()) return nullptr;
        auto* e = n->events.front();
        n->events.pop_front();
        return e;
    });
}

void uconnect_event_free(uconnect_event* e) { std::free(e); }
