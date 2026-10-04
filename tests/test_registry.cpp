// Registry: the rendezvous server's state under control protocol v2, where a
// record belongs to the TCP connection that registered it.

#include <set>

#include "registry.hpp"
#include "testing.hpp"

using namespace uconnect;
using namespace uconnect::server;
using namespace std::chrono_literals;
using wire::ctl::RelayKind;
using wire::ctl::RelayToken;

namespace {

Instant t0() { return Instant{} + 1000000s; }

TopicId topic_of(uint8_t f) { TopicId t{}; t.fill(f); return t; }

Endpoint ep(uint8_t last, uint16_t port) { return Endpoint{IpAddr::v4(203, 0, 113, last), port}; }

Registry make(RegistryConfig cfg = {}) {
    crypto::SymKey secret{};
    secret.fill(0x42);
    return Registry{cfg, secret, 12345};
}

wire::ctl::Register reg(TopicId id, TopicMode mode = TopicMode::Keyed, bool unlisted = false) {
    wire::ctl::Register m;
    m.id       = id;
    m.mode     = mode;
    m.unlisted = unlisted;
    return m;
}

}  // namespace

// ---------------------------------------------------------------------------
// Ownership
// ---------------------------------------------------------------------------
TEST(registry_a_record_can_only_be_touched_by_its_connection) {
    auto r = make();
    auto a = r.register_entry(reg(topic_of(1)), ep(7, 4000), /*owner=*/1, t0());
    REQUIRE(a.code == ErrorCode::None);

    CHECK(r.refresh(a.dev_id, 1, t0() + 5s) == ErrorCode::None);
    CHECK(r.refresh(a.dev_id, 2, t0() + 5s) == ErrorCode::BadAuth);
    wire::ctl::Update u;
    u.dev_id = a.dev_id;
    CHECK(r.update(u, 2, t0()) == ErrorCode::BadAuth);
    CHECK(r.unregister(a.dev_id, 2) == ErrorCode::BadAuth);
    CHECK_EQ(r.size(), 1u);

    CHECK(r.unregister(a.dev_id, 1) == ErrorCode::None);
    CHECK_EQ(r.size(), 0u);
}

TEST(registry_closing_a_connection_removes_everything_it_owned) {
    // No expiry timer for records: they live exactly as long as the connection
    // that registered them.
    auto r = make();
    r.register_entry(reg(topic_of(1)), ep(7, 4000), 1, t0());
    r.register_entry(reg(topic_of(2)), ep(7, 4000), 1, t0());
    r.register_entry(reg(topic_of(1)), ep(8, 4000), 2, t0());
    CHECK_EQ(r.size(), 3u);

    CHECK_EQ(r.drop_owner(1), 2u);
    CHECK_EQ(r.size(), 1u);
    CHECK_EQ(r.topic_count(), 1u);  // topic 2 went with its last member
}

TEST(registry_a_closed_connection_releases_its_ip_quota) {
    RegistryConfig cfg;
    cfg.max_per_ip_total = 2;
    auto r = make(cfg);
    CHECK(r.register_entry(reg(topic_of(1)), ep(7, 4000), 1, t0()).code == ErrorCode::None);
    CHECK(r.register_entry(reg(topic_of(2)), ep(7, 4000), 1, t0()).code == ErrorCode::None);
    CHECK(r.register_entry(reg(topic_of(3)), ep(7, 4001), 2, t0()).code ==
          ErrorCode::QuotaExceeded);
    r.drop_owner(1);
    CHECK(r.register_entry(reg(topic_of(3)), ep(7, 4001), 2, t0()).code == ErrorCode::None);
}

TEST(registry_a_reconnecting_device_takes_its_record_over) {
    // Same topic, same address, new control connection: the old connection
    // is dead or dying, and the new one has just proved it holds the address.
    auto r  = make();
    auto a1 = r.register_entry(reg(topic_of(1)), ep(7, 4000), 1, t0());
    auto a2 = r.register_entry(reg(topic_of(1)), ep(7, 4000), 2, t0() + 1s);
    CHECK(a1.dev_id == a2.dev_id);
    CHECK_EQ(r.size(), 1u);
    CHECK(r.refresh(a1.dev_id, 2, t0() + 2s) == ErrorCode::None);
    // The old connection closing now must not take the record with it.
    CHECK_EQ(r.drop_owner(1), 0u);
    CHECK_EQ(r.size(), 1u);
}

// ---------------------------------------------------------------------------
// Topics and the listing
// ---------------------------------------------------------------------------
TEST(registry_a_topics_mode_is_set_by_whoever_created_it) {
    // #30: a later registrant could relabel a keyed topic as open.
    auto r = make();
    r.register_entry(reg(topic_of(1), TopicMode::Keyed), ep(7, 4000), 1, t0());
    r.register_entry(reg(topic_of(1), TopicMode::Open), ep(8, 4000), 2, t0());
    auto l = r.list_topics(0, 10, t0());
    REQUIRE(l.topics.size() == 1);
    CHECK(l.topics[0].mode == TopicMode::Keyed);
}

TEST(issue24_listing_fresh_counts_follow_refresh_update_expiry_and_removal) {
    auto r = make();
    auto a = r.register_entry(reg(topic_of(1)), ep(7, 4000), 1, t0());
    auto b = r.register_entry(reg(topic_of(1)), ep(8, 4000), 2, t0() + 10s);
    REQUIRE(a.code == ErrorCode::None && b.code == ErrorCode::None);
    CHECK_EQ(r.list_topics(0, 10, t0() + 44s).topics[0].fresh_peers, 2u);
    CHECK_EQ(r.list_topics(0, 10, t0() + 45s).topics[0].fresh_peers, 1u);
    r.refresh(a.dev_id, 1, t0() + 46s);
    CHECK_EQ(r.list_topics(0, 10, t0() + 55s).topics[0].fresh_peers, 1u);
    wire::ctl::Update update;
    update.dev_id = b.dev_id;
    r.update(update, 2, t0() + 56s);
    CHECK_EQ(r.stats(t0() + 56s).entries_fresh, 2u);
    r.unregister(a.dev_id, 1);
    CHECK_EQ(r.list_topics(0, 10, t0() + 56s).topics[0].fresh_peers, 1u);
    r.register_entry(reg(topic_of(1)), ep(8, 4000), 2, t0() + 60s);
    CHECK_EQ(r.list_topics(0, 10, t0() + 101s).topics[0].fresh_peers, 1u);
    CHECK_EQ(r.list_topics(0, 10, t0() + 105s).topics[0].fresh_peers, 0u);
    r.drop_owner(2);
    CHECK(r.list_topics(0, 10, t0() + 106s).topics.empty());
    CHECK_EQ(r.stats(t0() + 106s).entries_fresh, 0u);
}

TEST(registry_the_listing_cursor_survives_topics_disappearing) {
    // #24: the cursor used to be an index, so a topic vanishing before it
    // shifted every page after -- skipping or repeating topics.
    auto r = make();
    for (uint8_t i = 1; i <= 6; ++i) {
        r.register_entry(reg(topic_of(i)), ep(i, 4000), i, t0());
    }
    auto first = r.list_topics(0, 3, t0());
    REQUIRE(first.topics.size() == 3);
    REQUIRE(first.next_cursor != 0);

    r.drop_owner(1);  // topic 1, already listed, disappears
    r.drop_owner(2);

    auto second = r.list_topics(first.next_cursor, 10, t0());
    std::set<uint8_t> seen;
    for (const auto& t : second.topics) seen.insert(t.id[0]);
    CHECK(seen == std::set<uint8_t>({4, 5, 6}));
    CHECK_EQ(second.next_cursor, 0u);
}

TEST(registry_unlisted_topics_are_hidden_but_still_found_by_id) {
    auto r = make();
    r.register_entry(reg(topic_of(1), TopicMode::Keyed, /*unlisted=*/true), ep(7, 4000), 1, t0());
    CHECK(r.list_topics(0, 10, t0()).topics.empty());
    CHECK_EQ(r.lookup(topic_of(1), 30, false, t0()).entries.size(), 1u);
}

TEST(registry_lookup_puts_the_observed_address_first_and_flags_stale_records) {
    auto r = make();
    wire::ctl::Register m = reg(topic_of(1));
    m.host_cands.push_back(Candidate{Candidate::Kind::Host, ep(99, 5000)});
    auto a = r.register_entry(m, ep(7, 4000), 1, t0());
    r.register_entry(reg(topic_of(1)), ep(8, 4000), 2, t0() + 40s);

    auto l = r.lookup(topic_of(1), 30, false, t0() + 60s);
    REQUIRE(l.entries.size() == 2);
    // Fresh before stale.
    CHECK(!l.entries[0].stale);
    CHECK(l.entries[1].stale);
    CHECK(l.entries[1].dev_id == a.dev_id);
    REQUIRE(l.entries[1].cands.size() == 2);
    CHECK(l.entries[1].cands[0].kind == Candidate::Kind::Srflx);
    CHECK(l.entries[1].cands[0].ep == ep(7, 4000));
}

TEST(registry_connect_stays_within_a_topic_and_needs_the_owner) {
    auto r = make();
    auto a = r.register_entry(reg(topic_of(1)), ep(7, 4000), 1, t0());
    auto b = r.register_entry(reg(topic_of(1)), ep(8, 4000), 2, t0());
    auto c = r.register_entry(reg(topic_of(2)), ep(9, 4000), 3, t0());

    auto to_b = r.connect_target(a.dev_id, b.dev_id, 1);
    REQUIRE(to_b.has_value());
    CHECK_EQ(*to_b, 2u);
    CHECK(!r.connect_target(a.dev_id, b.dev_id, 3).has_value());  // not a's connection
    CHECK(!r.connect_target(a.dev_id, c.dev_id, 1).has_value());  // another topic
}

// ---------------------------------------------------------------------------
// Relays
// ---------------------------------------------------------------------------
TEST(registry_relay_sides_hold_different_tokens_and_the_id_alone_admits_nobody) {
    auto r = make();
    auto a = r.register_entry(reg(topic_of(1)), ep(7, 4000), 1, t0());
    auto b = r.register_entry(reg(topic_of(1)), ep(8, 4000), 2, t0());

    auto g = r.relay_alloc(a.dev_id, b.dev_id, RelayKind::Tcp, 1, ep(7, 4000), t0());
    REQUIRE(g.code == ErrorCode::None);
    CHECK(!(g.token == g.peer_token));
    CHECK_EQ(g.peer_owner, 2u);

    CHECK(r.relay_side(g.id, g.token) == std::optional<int>(0));
    CHECK(r.relay_side(g.id, g.peer_token) == std::optional<int>(1));
    CHECK(!r.relay_side(g.id, RelayToken{}).has_value());
}

TEST(registry_asking_again_from_either_side_returns_the_same_binding) {
    // Both peers may ask when punching fails; that must yield one binding, and
    // each side its own token.
    auto r = make();
    auto a = r.register_entry(reg(topic_of(1)), ep(7, 4000), 1, t0());
    auto b = r.register_entry(reg(topic_of(1)), ep(8, 4000), 2, t0());

    auto ga = r.relay_alloc(a.dev_id, b.dev_id, RelayKind::Tcp, 1, ep(7, 4000), t0());
    auto gb = r.relay_alloc(b.dev_id, a.dev_id, RelayKind::Tcp, 2, ep(8, 4000), t0());
    CHECK_EQ(ga.id, gb.id);
    CHECK(gb.token == ga.peer_token);
    CHECK_EQ(r.relay_count(), 1u);

    // A different kind is a different binding.
    auto gu = r.relay_alloc(a.dev_id, b.dev_id, RelayKind::Udp, 1, ep(7, 4000), t0());
    CHECK(gu.id != ga.id);
}

TEST(registry_relay_quota_is_released_under_the_ip_that_was_charged) {
    // #21: counts were released under whatever address a peer had moved to.
    RegistryConfig cfg;
    cfg.max_relays_per_ip = 1;
    auto r = make(cfg);
    auto a = r.register_entry(reg(topic_of(1)), ep(7, 4000), 1, t0());
    auto b = r.register_entry(reg(topic_of(1)), ep(8, 4000), 2, t0());
    auto c = r.register_entry(reg(topic_of(1)), ep(7, 4001), 3, t0());

    REQUIRE(r.relay_alloc(a.dev_id, b.dev_id, RelayKind::Tcp, 1, ep(7, 4000), t0()).code ==
            ErrorCode::None);
    CHECK(r.relay_alloc(c.dev_id, b.dev_id, RelayKind::Tcp, 3, ep(7, 4001), t0()).code ==
          ErrorCode::QuotaExceeded);
    // Asking again for the binding it already holds is never refused for quota.
    CHECK(r.relay_alloc(a.dev_id, b.dev_id, RelayKind::Tcp, 1, ep(7, 4000), t0()).code ==
          ErrorCode::None);

    r.drop_owner(1);  // A's connection closes; its binding goes with it
    CHECK(r.relay_alloc(c.dev_id, b.dev_id, RelayKind::Tcp, 3, ep(7, 4001), t0()).code ==
          ErrorCode::None);
}

TEST(registry_a_spent_relay_is_refused_not_handed_back) {
    RegistryConfig cfg;
    cfg.relay_max_bytes = 1000;
    auto r = make(cfg);
    auto a = r.register_entry(reg(topic_of(1)), ep(7, 4000), 1, t0());
    auto b = r.register_entry(reg(topic_of(1)), ep(8, 4000), 2, t0());
    auto g = r.relay_alloc(a.dev_id, b.dev_id, RelayKind::Tcp, 1, ep(7, 4000), t0());

    CHECK(r.relay_charge(g.id, 600, t0()));
    CHECK(!r.relay_charge(g.id, 600, t0()));
    CHECK(r.relay_alloc(b.dev_id, a.dev_id, RelayKind::Tcp, 2, ep(8, 4000), t0()).code ==
          ErrorCode::QuotaExceeded);
}

TEST(registry_udp_relay_forwards_only_between_bound_sides) {
    auto r = make();
    auto a = r.register_entry(reg(topic_of(1)), ep(7, 4000), 1, t0());
    auto b = r.register_entry(reg(topic_of(1)), ep(8, 4000), 2, t0());
    auto g = r.relay_alloc(a.dev_id, b.dev_id, RelayKind::Udp, 1, ep(7, 4000), t0());

    const Endpoint ua = ep(7, 51000), ub = ep(8, 52000), stranger = ep(66, 1);
    CHECK(!r.udp_bind(g.id, RelayToken{}, stranger, t0()));  // wrong token
    REQUIRE(r.udp_bind(g.id, g.token, ua, t0()));
    CHECK(!r.udp_forward(g.id, ua, 100, t0()).has_value());   // the far side has not bound
    REQUIRE(r.udp_bind(g.id, g.peer_token, ub, t0()));

    auto to_b = r.udp_forward(g.id, ua, 100, t0());
    REQUIRE(to_b.has_value());
    CHECK(*to_b == ub);
    auto to_a = r.udp_forward(g.id, ub, 100, t0());
    REQUIRE(to_a.has_value());
    CHECK(*to_a == ua);
    CHECK(!r.udp_forward(g.id, stranger, 100, t0()).has_value());
}

TEST(registry_idle_relays_expire) {
    RegistryConfig cfg;
    cfg.relay_expiry = 90s;
    auto r = make(cfg);
    auto a = r.register_entry(reg(topic_of(1)), ep(7, 4000), 1, t0());
    auto b = r.register_entry(reg(topic_of(1)), ep(8, 4000), 2, t0());
    r.relay_alloc(a.dev_id, b.dev_id, RelayKind::Tcp, 1, ep(7, 4000), t0());
    r.sweep(t0() + 30s);
    CHECK_EQ(r.relay_count(), 1u);
    r.sweep(t0() + 200s);
    CHECK_EQ(r.relay_count(), 0u);
}
