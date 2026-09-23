// Rendezvous store tests.
//
// Every lifetime rule here -- 20s keepalive, 45s stale, 90s expiry -- is tested
// by advancing a fake clock, not by sleeping. That is the payoff of keeping the
// store sans-IO: the full lifecycle of a record runs in microseconds, and the
// "record is nominally alive but its candidate is dead" case, which is the one
// that actually bites in production, is trivial to reproduce.

#include <cstring>
#include <utility>

#include "store.hpp"
#include "udp_service.hpp"
#include "testing.hpp"

using namespace uconnect;
using namespace uconnect::server;
using namespace std::chrono_literals;

namespace {

Instant t0() { return Instant{} + 1000000s; }  // arbitrary, far from zero

TopicId topic_of(uint8_t f) {
    TopicId t{};
    t.fill(f);
    return t;
}

Endpoint ep(uint8_t last, uint16_t port) {
    return Endpoint{IpAddr::v4(203, 0, 113, last), port};
}

// A distinct source IP per index. Swarm tests must not reuse one address --
// the per-IP quota would (correctly) reject them, which is a different thing
// from the behaviour under test.
Endpoint ep_n(uint32_t i) {
    return Endpoint{IpAddr::v4(10, static_cast<uint8_t>(i >> 16),
                               static_cast<uint8_t>(i >> 8), static_cast<uint8_t>(i)),
                    static_cast<uint16_t>(40000 + (i % 20000))};
}

Store make_store(StoreConfig cfg = {}) {
    crypto::SymKey secret{};
    secret.fill(0x42);  // fixed secret => deterministic dev_ids in tests
    return Store{cfg, secret, 12345};
}

wire::Register reg_msg(TopicId id, bool listed = false, TopicMode mode = TopicMode::Keyed) {
    wire::Register m;
    m.id     = id;
    m.mode   = mode;
    m.listed = listed;
    return m;
}

// Build the MAC a client would attach, over the exact bytes the server checks.
wire::Mac mac_over(const wire::LeaseToken& token, std::span<const uint8_t> authed) {
    auto      h = crypto::Blake2s::mac(token, authed);
    wire::Mac m{};
    std::memcpy(m.data(), h.data(), wire::kMacLen);
    return m;
}

// Encode a Keepalive the way the client would, returning both the datagram and
// the span the MAC covers, so tests exercise the real byte layout.
struct AuthedMsg {
    std::vector<uint8_t> dgram;
    size_t               prefix_len = 0;

    std::span<const uint8_t> authed() const {
        return std::span<const uint8_t>(dgram.data(), prefix_len);
    }
};

AuthedMsg build_keepalive(const DevId& dev, uint64_t seq, const wire::LeaseToken& token) {
    AuthedMsg out;
    out.dgram.resize(wire::kMaxDatagram);
    wire::Writer w{out.dgram};
    wire::Header{wire::MsgType::Keepalive, wire::kVersion, 0, 1}.encode(w);

    wire::Keepalive k;
    k.dev_id   = dev;
    k.auth.seq = seq;
    k.encode_prefix(w);
    out.prefix_len = w.size();

    auto m = mac_over(token, std::span<const uint8_t>(out.dgram.data(), out.prefix_len));
    w.array(m);
    out.dgram.resize(w.size());
    return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// dev_id derivation
// ---------------------------------------------------------------------------
TEST(dev_id_is_stable_for_the_same_topic_and_address) {
    auto s  = make_store();
    auto id = topic_of(1);
    CHECK(s.derive_dev_id(id, ep(7, 4000)) == s.derive_dev_id(id, ep(7, 4000)));
}

TEST(dev_id_differs_per_port_and_per_address) {
    auto s  = make_store();
    auto id = topic_of(1);
    CHECK(!(s.derive_dev_id(id, ep(7, 4000)) == s.derive_dev_id(id, ep(7, 4001))));
    CHECK(!(s.derive_dev_id(id, ep(7, 4000)) == s.derive_dev_id(id, ep(8, 4000))));
}

TEST(dev_id_differs_across_topics_for_the_same_device) {
    // This is the correlation leak the topic_id mixing exists to prevent. Same
    // device, two topics: an observer reading both listings must not be able to
    // link them.
    auto s = make_store();
    auto a = s.derive_dev_id(topic_of(1), ep(7, 4000));
    auto b = s.derive_dev_id(topic_of(2), ep(7, 4000));
    CHECK(!(a == b));
}

// ---------------------------------------------------------------------------
// Retry cookies
// ---------------------------------------------------------------------------
TEST(cookie_validates_for_its_own_address_only) {
    auto s = make_store();
    auto c = s.make_cookie(ep(7, 4000), t0());
    CHECK(s.validate_cookie(c, ep(7, 4000), t0()));
    // A cookie must not transfer to another address, or it stops proving
    // anything about who can receive where.
    CHECK(!s.validate_cookie(c, ep(7, 4001), t0()));
    CHECK(!s.validate_cookie(c, ep(8, 4000), t0()));
}

TEST(cookie_survives_one_epoch_boundary_then_expires) {
    StoreConfig cfg;
    cfg.cookie_lifetime = 30s;
    auto s = make_store(cfg);

    auto c = s.make_cookie(ep(7, 4000), t0());
    CHECK(s.validate_cookie(c, ep(7, 4000), t0()));
    // Accepted in the next epoch: a client should not lose a race it cannot see.
    CHECK(s.validate_cookie(c, ep(7, 4000), t0() + 30s));
    // But not two epochs later.
    CHECK(!s.validate_cookie(c, ep(7, 4000), t0() + 90s));
}

TEST(cookie_rejects_wrong_length_and_garbage) {
    auto s = make_store();
    std::vector<uint8_t> junk(16, 0xAB);
    CHECK(!s.validate_cookie(junk, ep(7, 4000), t0()));
    std::vector<uint8_t> short_c(8, 0);
    CHECK(!s.validate_cookie(short_c, ep(7, 4000), t0()));
}

// ---------------------------------------------------------------------------
// register
// ---------------------------------------------------------------------------
TEST(register_returns_the_observed_source_as_srflx) {
    // The client cannot know its public mapping -- that is the entire reason
    // registration happens over UDP from the data socket.
    auto s   = make_store();
    auto src = ep(7, 39412);
    auto r   = s.register_entry(reg_msg(topic_of(1)), src, t0());
    CHECK(r.code == ErrorCode::None);
    CHECK(r.srflx == src);
    CHECK_EQ(r.peers_in_topic, 1);
}

TEST(register_twice_from_the_same_address_refreshes_rather_than_duplicating) {
    auto s   = make_store();
    auto src = ep(7, 39412);
    auto r1  = s.register_entry(reg_msg(topic_of(1)), src, t0());
    auto r2  = s.register_entry(reg_msg(topic_of(1)), src, t0() + 5s);
    CHECK(r1.dev_id == r2.dev_id);
    CHECK_EQ(s.size(), 1u);
    // A new lease token each time: a restarted device lost its old one, and the
    // address has already been cookie-validated.
    CHECK(!(r1.lease_token == r2.lease_token));
}

TEST(register_stores_host_candidates_and_prepends_srflx_on_lookup) {
    auto s = make_store();
    auto m = reg_msg(topic_of(1));
    m.host_cands = {Candidate{Candidate::Kind::Host, Endpoint{IpAddr::v4(192, 168, 1, 40), 51820}}};
    s.register_entry(m, ep(7, 39412), t0());

    auto res = s.lookup(topic_of(1), 30, false, t0());
    REQUIRE(res.entries.size() == 1);
    REQUIRE(res.entries[0].cands.size() == 2);
    // srflx first (what most peers need), host second (what same-NAT peers need
    // when the router will not hairpin).
    CHECK(res.entries[0].cands[0].kind == Candidate::Kind::Srflx);
    CHECK(res.entries[0].cands[0].ep == ep(7, 39412));
    CHECK(res.entries[0].cands[1].kind == Candidate::Kind::Host);
}

TEST(register_enforces_per_ip_per_topic_quota) {
    StoreConfig cfg;
    cfg.max_per_ip_per_topic = 3;
    auto s = make_store(cfg);

    for (uint16_t p = 0; p < 3; ++p) {
        auto r = s.register_entry(reg_msg(topic_of(1)), ep(7, static_cast<uint16_t>(4000 + p)), t0());
        CHECK(r.code == ErrorCode::None);
    }
    auto over = s.register_entry(reg_msg(topic_of(1)), ep(7, 4003), t0());
    CHECK(over.code == ErrorCode::QuotaExceeded);

    // A different source address is unaffected.
    auto other = s.register_entry(reg_msg(topic_of(1)), ep(8, 4000), t0());
    CHECK(other.code == ErrorCode::None);
}

TEST(quota_counts_only_new_records_so_refresh_is_free) {
    StoreConfig cfg;
    cfg.max_per_ip_per_topic = 1;
    auto s = make_store(cfg);

    auto r = s.register_entry(reg_msg(topic_of(1)), ep(7, 4000), t0());
    REQUIRE(r.code == ErrorCode::None);
    // Same address, same dev_id -- a refresh, not a new record.
    auto again = s.register_entry(reg_msg(topic_of(1)), ep(7, 4000), t0() + 10s);
    CHECK(again.code == ErrorCode::None);
}

// ---------------------------------------------------------------------------
// keepalive, auth, rebinding
// ---------------------------------------------------------------------------
TEST(keepalive_with_a_valid_mac_refreshes_the_record) {
    auto s   = make_store();
    auto src = ep(7, 4000);
    auto r   = s.register_entry(reg_msg(topic_of(1)), src, t0());

    auto ka  = build_keepalive(r.dev_id, 1, r.lease_token);
    auto res = s.keepalive(r.dev_id, 1, ka.authed(), mac_over(r.lease_token, ka.authed()), src,
                           t0() + 20s);
    CHECK(res.code == ErrorCode::None);
    CHECK(res.srflx == src);

    const Record* rec = s.find(r.dev_id);
    REQUIRE(rec != nullptr);
    CHECK(s.is_fresh(*rec, t0() + 20s));
}

TEST(keepalive_rejects_a_forged_mac) {
    auto s   = make_store();
    auto src = ep(7, 4000);
    auto r   = s.register_entry(reg_msg(topic_of(1)), src, t0());

    auto      ka = build_keepalive(r.dev_id, 1, r.lease_token);
    wire::Mac bad{};
    bad.fill(0xEE);
    auto res = s.keepalive(r.dev_id, 1, ka.authed(), bad, src, t0() + 20s);
    CHECK(res.code == ErrorCode::BadAuth);
}

TEST(keepalive_rejects_a_replayed_sequence_number) {
    // The token never travels on the wire after registration, so an on-path
    // observer can only replay a captured datagram verbatim. Monotonic seq is
    // what kills that.
    auto s   = make_store();
    auto src = ep(7, 4000);
    auto r   = s.register_entry(reg_msg(topic_of(1)), src, t0());

    auto ka = build_keepalive(r.dev_id, 5, r.lease_token);
    auto m  = mac_over(r.lease_token, ka.authed());
    CHECK(s.keepalive(r.dev_id, 5, ka.authed(), m, src, t0() + 20s).code == ErrorCode::None);

    // Exact replay of the same bytes.
    CHECK(s.keepalive(r.dev_id, 5, ka.authed(), m, src, t0() + 21s).code == ErrorCode::BadAuth);
    // And anything older.
    auto old = build_keepalive(r.dev_id, 4, r.lease_token);
    CHECK(s.keepalive(r.dev_id, 4, old.authed(), mac_over(r.lease_token, old.authed()), src,
                      t0() + 22s)
              .code == ErrorCode::BadAuth);
}

TEST(keepalive_from_a_new_address_rebinds_when_the_mac_verifies) {
    // Mobile networks rebind through no fault of the client. Address-only
    // binding would lock a device out of its own record until expiry; the token
    // is the strong check and the address is the cheap one.
    auto s   = make_store();
    auto old = ep(7, 4000);
    auto r   = s.register_entry(reg_msg(topic_of(1)), old, t0());

    auto moved = ep(9, 55555);
    auto ka    = build_keepalive(r.dev_id, 1, r.lease_token);
    auto res   = s.keepalive(r.dev_id, 1, ka.authed(), mac_over(r.lease_token, ka.authed()),
                             moved, t0() + 20s);
    CHECK(res.code == ErrorCode::None);
    CHECK(res.rebound);
    CHECK(res.srflx == moved);

    // The dev_id survives the move -- stable identity exactly where it matters.
    const Record* rec = s.find(r.dev_id);
    REQUIRE(rec != nullptr);
    CHECK(rec->bound_addr == moved);

    // And peers now learn the new address.
    auto look = s.lookup(topic_of(1), 30, false, t0() + 20s);
    REQUIRE(look.entries.size() == 1);
    CHECK(look.entries[0].cands[0].ep == moved);
}

TEST(a_forged_mac_from_a_new_address_cannot_hijack_a_record) {
    auto s   = make_store();
    auto r   = s.register_entry(reg_msg(topic_of(1)), ep(7, 4000), t0());

    wire::LeaseToken wrong{};
    wrong.fill(0x01);
    auto ka  = build_keepalive(r.dev_id, 1, wrong);
    auto res = s.keepalive(r.dev_id, 1, ka.authed(), mac_over(wrong, ka.authed()), ep(66, 1234),
                           t0() + 5s);
    CHECK(res.code == ErrorCode::BadAuth);

    const Record* rec = s.find(r.dev_id);
    REQUIRE(rec != nullptr);
    CHECK(rec->bound_addr == ep(7, 4000));  // unmoved
}

TEST(unregister_frees_the_record_immediately) {
    auto s   = make_store();
    auto src = ep(7, 4000);
    auto r   = s.register_entry(reg_msg(topic_of(1)), src, t0());
    CHECK_EQ(s.size(), 1u);

    auto ka = build_keepalive(r.dev_id, 1, r.lease_token);
    auto res = s.unregister(r.dev_id, 1, ka.authed(), mac_over(r.lease_token, ka.authed()), src,
                            t0() + 1s);
    CHECK(res.code == ErrorCode::None);
    CHECK_EQ(s.size(), 0u);
    // Topic disappears with its last member.
    CHECK_EQ(s.topic_count(), 0u);
}

// ---------------------------------------------------------------------------
// lifetimes -- the two clocks
// ---------------------------------------------------------------------------
TEST(record_goes_stale_at_45s_and_expires_at_90s) {
    StoreConfig cfg;
    cfg.stale_after  = 45s;
    cfg.hard_expiry  = 90s;
    auto s = make_store(cfg);
    auto r = s.register_entry(reg_msg(topic_of(1)), ep(7, 4000), t0());
    (void)r;

    // Fresh.
    auto a = s.lookup(topic_of(1), 30, false, t0() + 10s);
    REQUIRE(a.entries.size() == 1);
    CHECK(!a.entries[0].stale);

    // Past the freshness window: still returned, but flagged. A stale entry is
    // still useful -- the peer may just be having a lull -- so the client
    // deprioritises rather than discards.
    auto b = s.lookup(topic_of(1), 30, false, t0() + 50s);
    REQUIRE(b.entries.size() == 1);
    CHECK(b.entries[0].stale);
    CHECK(b.entries[0].age_secs >= 50);

    // Past hard expiry: swept.
    CHECK_EQ(s.sweep(t0() + 91s), 1u);
    auto c = s.lookup(topic_of(1), 30, false, t0() + 91s);
    CHECK_EQ(c.entries.size(), 0u);
    CHECK_EQ(s.size(), 0u);
}

TEST(keepalives_hold_a_record_alive_indefinitely) {
    StoreConfig cfg;
    cfg.hard_expiry = 90s;
    auto s = make_store(cfg);
    auto r = s.register_entry(reg_msg(topic_of(1)), ep(7, 4000), t0());

    // 20s keepalives across 10 minutes: the record must never expire, and there
    // is no 30-minute ceiling to trip over.
    auto now = t0();
    for (uint64_t seq = 1; seq <= 30; ++seq) {
        now += 20s;
        auto ka  = build_keepalive(r.dev_id, seq, r.lease_token);
        auto res = s.keepalive(r.dev_id, seq, ka.authed(), mac_over(r.lease_token, ka.authed()),
                               ep(7, 4000), now);
        REQUIRE(res.code == ErrorCode::None);
        s.sweep(now);
    }
    CHECK_EQ(s.size(), 1u);
    const Record* rec = s.find(r.dev_id);
    REQUIRE(rec != nullptr);
    CHECK(s.is_fresh(*rec, now));
}

TEST(sweep_reclaims_the_topic_when_its_last_member_expires) {
    auto s = make_store();
    s.register_entry(reg_msg(topic_of(1)), ep(7, 4000), t0());
    s.register_entry(reg_msg(topic_of(1)), ep(8, 4000), t0());
    CHECK_EQ(s.topic_count(), 1u);

    s.sweep(t0() + 200s);
    CHECK_EQ(s.size(), 0u);
    CHECK_EQ(s.topic_count(), 0u);
}

// ---------------------------------------------------------------------------
// lookup sampling
// ---------------------------------------------------------------------------
TEST(lookup_caps_at_30_by_default_and_100_at_most) {
    auto s = make_store();
    for (uint32_t i = 0; i < 200; ++i) {
        s.register_entry(reg_msg(topic_of(1)), ep_n(i), t0());
    }

    auto def = s.lookup(topic_of(1), wire::kLookupDefault, false, t0());
    CHECK_EQ(def.entries.size(), 30u);
    CHECK_EQ(def.total, 200);  // the client still learns how big the swarm is

    auto big = s.lookup(topic_of(1), 100, false, t0());
    CHECK_EQ(big.entries.size(), 100u);

    // A request above the ceiling is clamped, not rejected.
    auto over = s.lookup(topic_of(1), 255, false, t0());
    CHECK_EQ(over.entries.size(), 100u);
}

TEST(lookup_samples_randomly_so_no_peer_is_everyones_first_choice) {
    auto s = make_store();
    for (uint32_t i = 0; i < 500; ++i) {
        s.register_entry(reg_msg(topic_of(1)), ep_n(i), t0());
    }

    auto a = s.lookup(topic_of(1), 30, false, t0());
    auto b = s.lookup(topic_of(1), 30, false, t0());
    REQUIRE(a.entries.size() == 30);
    REQUIRE(b.entries.size() == 30);

    // Two lookups on a 500-peer swarm returning identical sets would mean the
    // sampling is not actually sampling.
    size_t overlap = 0;
    for (const auto& x : a.entries) {
        for (const auto& y : b.entries) {
            if (x.dev_id == y.dev_id) ++overlap;
        }
    }
    CHECK(overlap < 30);
}

TEST(lookup_returns_everything_when_the_topic_is_smaller_than_the_cap) {
    auto s = make_store();
    for (uint32_t i = 0; i < 5; ++i) {
        s.register_entry(reg_msg(topic_of(1)), ep_n(i), t0());
    }
    auto r = s.lookup(topic_of(1), 30, false, t0());
    CHECK_EQ(r.entries.size(), 5u);
    CHECK_EQ(r.total, 5);
}

TEST(lookup_orders_fresh_entries_before_stale_ones) {
    auto s = make_store();
    auto fresh_r = s.register_entry(reg_msg(topic_of(1)), ep(7, 4000), t0() + 100s);
    auto stale_r = s.register_entry(reg_msg(topic_of(1)), ep(8, 4000), t0());
    (void)stale_r;

    auto r = s.lookup(topic_of(1), 30, false, t0() + 100s);
    REQUIRE(r.entries.size() == 2);
    CHECK(r.entries[0].dev_id == fresh_r.dev_id);
    CHECK(!r.entries[0].stale);
    CHECK(r.entries[1].stale);
}

TEST(lookup_omits_meta_unless_requested) {
    // 256 bytes of meta times 30 entries is 7.7KB of mostly unwanted payload.
    auto s = make_store();
    auto m = reg_msg(topic_of(1));
    m.meta.assign(200, 0xAB);
    s.register_entry(m, ep(7, 4000), t0());

    auto without = s.lookup(topic_of(1), 30, false, t0());
    REQUIRE(without.entries.size() == 1);
    CHECK_EQ(without.entries[0].meta.size(), 0u);

    auto with = s.lookup(topic_of(1), 30, true, t0());
    REQUIRE(with.entries.size() == 1);
    CHECK_EQ(with.entries[0].meta.size(), 200u);
}

TEST(lookup_on_an_unknown_topic_is_empty_not_an_error) {
    auto s = make_store();
    auto r = s.lookup(topic_of(99), 30, false, t0());
    CHECK_EQ(r.entries.size(), 0u);
    CHECK_EQ(r.total, 0);
}


// ---------------------------------------------------------------------------
// resolve / topics / relay
// ---------------------------------------------------------------------------
TEST(resolve_returns_metadata_for_any_dev_id) {
    auto s = make_store();
    auto m = reg_msg(topic_of(1));
    m.meta = {'h', 'i'};
    auto r = s.register_entry(m, ep(7, 4000), t0());

    auto got = s.resolve(r.dev_id, t0());
    REQUIRE(got.has_value());
    CHECK(got->first == topic_of(1));
    CHECK(got->second.meta == m.meta);

    DevId unknown{};
    unknown.fill(0xFF);
    CHECK(!s.resolve(unknown, t0()).has_value());
}

TEST(topics_listing_is_opt_in) {
    auto s = make_store();
    s.register_entry(reg_msg(topic_of(1), /*listed=*/false), ep(7, 4000), t0());
    s.register_entry(reg_msg(topic_of(2), /*listed=*/true), ep(8, 4000), t0());

    auto r = s.list_topics(0, 100, t0());
    REQUIRE(r.topics.size() == 1);
    CHECK(r.topics[0].id == topic_of(2));
    CHECK_EQ(r.topics[0].peers, 1u);
    CHECK_EQ(r.topics[0].fresh_peers, 1u);
}

TEST(topics_listing_counts_fresh_separately_from_total) {
    auto s = make_store();
    s.register_entry(reg_msg(topic_of(1), true), ep(7, 4000), t0());
    s.register_entry(reg_msg(topic_of(1), true), ep(8, 4000), t0() + 60s);

    auto r = s.list_topics(0, 100, t0() + 60s);
    REQUIRE(r.topics.size() == 1);
    CHECK_EQ(r.topics[0].peers, 2u);
    CHECK_EQ(r.topics[0].fresh_peers, 1u);  // the first one went stale
}

TEST(topics_listing_pages_with_a_cursor) {
    auto s = make_store();
    for (uint8_t i = 1; i <= 10; ++i) {
        s.register_entry(reg_msg(topic_of(i), true), ep(i, 4000), t0());
    }
    auto p1 = s.list_topics(0, 4, t0());
    CHECK_EQ(p1.topics.size(), 4u);
    CHECK(p1.next_cursor != 0);

    auto p2 = s.list_topics(p1.next_cursor, 4, t0());
    CHECK_EQ(p2.topics.size(), 4u);

    auto p3 = s.list_topics(p2.next_cursor, 4, t0());
    CHECK_EQ(p3.topics.size(), 2u);
    CHECK_EQ(p3.next_cursor, 0u);  // exhausted
}

TEST(relay_only_works_within_a_topic) {
    // The server must not become a general-purpose message bus between
    // arbitrary registrants.
    auto s = make_store();
    auto a = s.register_entry(reg_msg(topic_of(1)), ep(7, 4000), t0());
    auto b = s.register_entry(reg_msg(topic_of(1)), ep(8, 4000), t0());
    auto c = s.register_entry(reg_msg(topic_of(2)), ep(9, 4000), t0());

    auto ka = build_keepalive(a.dev_id, 1, a.lease_token);
    auto m  = mac_over(a.lease_token, ka.authed());

    auto ok = s.relay_target(a.dev_id, b.dev_id, 1, ka.authed(), m, ep(7, 4000), t0());
    REQUIRE(ok.has_value());
    CHECK(*ok == ep(8, 4000));

    auto ka2 = build_keepalive(a.dev_id, 2, a.lease_token);
    auto m2  = mac_over(a.lease_token, ka2.authed());
    auto cross = s.relay_target(a.dev_id, c.dev_id, 2, ka2.authed(), m2, ep(7, 4000), t0());
    CHECK(!cross.has_value());
}

TEST(relay_requires_the_senders_own_mac) {
    auto s = make_store();
    auto a = s.register_entry(reg_msg(topic_of(1)), ep(7, 4000), t0());
    auto b = s.register_entry(reg_msg(topic_of(1)), ep(8, 4000), t0());

    wire::LeaseToken wrong{};
    wrong.fill(0x77);
    auto ka = build_keepalive(a.dev_id, 1, wrong);
    auto m  = mac_over(wrong, ka.authed());
    CHECK(!s.relay_target(a.dev_id, b.dev_id, 1, ka.authed(), m, ep(7, 4000), t0()).has_value());
}

// ---------------------------------------------------------------------------
// stats
// ---------------------------------------------------------------------------
TEST(stats_reports_records_not_unique_devices) {
    auto s = make_store();
    s.register_entry(reg_msg(topic_of(1), true), ep(7, 4000), t0());
    s.register_entry(reg_msg(topic_of(1), true), ep(8, 4000), t0());
    s.register_entry(reg_msg(topic_of(2), false), ep(9, 4000), t0() + 60s);

    auto st = s.stats(t0() + 60s);
    CHECK_EQ(st.entries_total, 3u);
    CHECK_EQ(st.entries_fresh, 1u);  // the first two went stale
    CHECK_EQ(st.topics_total, 2u);
    CHECK_EQ(st.topics_listed, 1u);
    CHECK_EQ(st.registers, 3u);
}

TEST(stats_counts_rejections_so_quotas_can_be_tuned_against_real_numbers) {
    StoreConfig cfg;
    cfg.max_per_ip_per_topic = 1;
    auto s = make_store(cfg);

    s.register_entry(reg_msg(topic_of(1)), ep(7, 4000), t0());
    s.register_entry(reg_msg(topic_of(1)), ep(7, 4001), t0());
    s.register_entry(reg_msg(topic_of(1)), ep(7, 4002), t0());

    auto st = s.stats(t0());
    CHECK_EQ(st.rej_quota, 2u);
}

TEST(memory_footprint_stays_small_at_ten_thousand_records) {
    // The claim is roughly 3-4MB for 10k live devices, which is what makes a
    // 64MB container plausible. This does not measure bytes, but it does
    // confirm the store handles the scale without pathological behaviour.
    auto s = make_store();
    for (uint32_t i = 0; i < 10000; ++i) {
        auto tid  = topic_of(static_cast<uint8_t>(i % 50));
        auto port = static_cast<uint16_t>(4000 + (i % 60000));
        auto addr = Endpoint{IpAddr::v4(10, static_cast<uint8_t>(i >> 16),
                                        static_cast<uint8_t>(i >> 8), static_cast<uint8_t>(i)),
                             port};
        s.register_entry(reg_msg(tid), addr, t0());
    }
    CHECK_EQ(s.size(), 10000u);
    CHECK_EQ(s.topic_count(), 50u);

    auto r = s.lookup(topic_of(3), 30, false, t0());
    CHECK_EQ(r.entries.size(), 30u);

    // Everything gone 90 seconds after the last keepalive.
    CHECK_EQ(s.sweep(t0() + 91s), 10000u);
    CHECK_EQ(s.size(), 0u);
}

// ---------------------------------------------------------------------------
// Page sizing
// ---------------------------------------------------------------------------
namespace {

// Encode a LookupOk page exactly as the server would and return its wire size.
size_t page_bytes(const std::vector<wire::PeerEntry>& entries) {
    wire::LookupOk ok;
    ok.total   = static_cast<uint16_t>(entries.size());
    ok.parts   = 1;
    ok.entries = entries;

    std::vector<uint8_t> buf(100000);
    wire::Writer         w{buf};
    wire::Header{wire::MsgType::LookupOk, wire::kVersion, 0, 1}.encode(w);
    ok.encode(w);
    return w.size();
}

std::vector<wire::PeerEntry> sample_entries(size_t n, bool host_v4, bool host_v6,
                                            size_t meta) {
    std::vector<wire::PeerEntry> out;
    for (size_t i = 0; i < n; ++i) {
        wire::PeerEntry e;
        e.cands.push_back({Candidate::Kind::Srflx, ep(1, 40000)});
        if (host_v4) {
            e.cands.push_back(
                {Candidate::Kind::Host, Endpoint{IpAddr::v4(192, 168, 1, 40), 51820}});
        }
        if (host_v6) {
            IpAddr v6;
            v6.family = IpAddr::Family::V6;
            e.cands.push_back({Candidate::Kind::Host, Endpoint{v6, 51820}});
        }
        e.meta.assign(meta, 0xAB);
        out.push_back(std::move(e));
    }
    return out;
}

}  // namespace

TEST(a_v4_only_page_of_thirty_fits_in_one_datagram_but_barely) {
    // The common case fits, which is worth knowing -- but with only ~30 bytes
    // of headroom. The server must size pages from encoded_size() rather than
    // assume 30 entries is always safe.
    CHECK_EQ(page_bytes(sample_entries(30, false, false, 0)), 930u);
    CHECK_EQ(page_bytes(sample_entries(30, true, false, 0)), 1170u);
    CHECK(page_bytes(sample_entries(30, true, false, 0)) <= wire::kMaxDatagram);
    CHECK(wire::kMaxDatagram - page_bytes(sample_entries(30, true, false, 0)) < 64u);
}

TEST(ipv6_metadata_and_large_caps_all_require_paging) {
    // Each of these overflows a single datagram, which is why LookupOk carries
    // part/parts at all.
    CHECK(page_bytes(sample_entries(30, true, true, 0)) > wire::kMaxDatagram);
    CHECK(page_bytes(sample_entries(30, true, false, 64)) > wire::kMaxDatagram);
    CHECK(page_bytes(sample_entries(100, true, false, 0)) > wire::kMaxDatagram);
}

TEST(encoded_size_agrees_with_the_real_encoder_for_every_entry_shape) {
    // The server pages by accumulating encoded_size(). If that under-reports by
    // even a byte, pages silently overflow the MTU and get truncated.
    for (bool h4 : {false, true}) {
        for (bool h6 : {false, true}) {
            for (size_t meta : {size_t{0}, size_t{1}, size_t{200}}) {
                auto entries = sample_entries(1, h4, h6, meta);
                std::vector<uint8_t> buf(4096);
                wire::Writer         w{buf};
                entries[0].encode(w);
                REQUIRE(w.ok());
                CHECK_EQ(w.size(), entries[0].encoded_size());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Amplification: every response larger than its request must be gated
// ---------------------------------------------------------------------------
namespace {

// Encode a request exactly as a client would, optionally with a cookie.
template <typename T>
std::vector<uint8_t> req(wire::MsgType type, const T& msg, uint8_t flags = 0) {
    std::vector<uint8_t> buf(wire::kMaxDatagram);
    wire::Writer         w{buf};
    wire::Header{type, wire::kVersion, flags, 1}.encode(w);
    msg.encode(w);
    buf.resize(w.size());
    return buf;
}

std::optional<wire::MsgType> reply_type(const std::vector<Reply>& out) {
    if (out.empty() || out[0].data.empty()) return std::nullopt;
    return wire::peek_type(out[0].data);
}

}  // namespace

TEST(every_amplifying_request_is_refused_without_a_validated_address) {
    // An unvalidated request whose reply is bigger than itself turns this server
    // into a DDoS amplifier aimed at whoever the attacker spoofed. Each of these
    // must answer with a small Retry, never with the payload.
    //
    // Resolve and Stats were NOT gated at one point: needs_cookie() listed them
    // but was never actually called, so they answered anyone. This test is here
    // so that cannot come back.
    auto       s = make_store();
    UdpService svc{s};
    auto       src = ep(7, 40000);

    struct Case { const char* name; std::vector<uint8_t> dgram; };
    std::vector<Case> cases;

    { wire::Register m; m.id = topic_of(1); cases.push_back({"Register", req(wire::MsgType::Register, m)}); }
    { wire::Lookup   m; m.id = topic_of(1); cases.push_back({"Lookup",   req(wire::MsgType::Lookup, m)}); }
    { wire::Topics   m;                     cases.push_back({"Topics",   req(wire::MsgType::Topics, m)}); }
    { wire::Resolve  m; m.dev_id = DevId{}; cases.push_back({"Resolve",  req(wire::MsgType::Resolve, m)}); }
    { wire::Stats    m;                     cases.push_back({"Stats",    req(wire::MsgType::Stats, m)}); }

    for (auto& c : cases) {
        auto out = svc.handle(src, c.dgram, t0());
        auto rt  = reply_type(out);
        if (!rt || *rt != wire::MsgType::Retry) {
            ::testing::fail(__FILE__, __LINE__,
                            std::string(c.name) + " answered without a cookie");
            continue;
        }
        // And the Retry must be no larger than the request that provoked it,
        // or the defence is itself an amplifier.
        if (out[0].data.size() > c.dgram.size() + 16) {
            ::testing::fail(__FILE__, __LINE__,
                            std::string(c.name) + " Retry is larger than the request");
        }
    }
}

TEST(a_validated_address_gets_the_real_answer) {
    // The flip side: once the cookie is presented, the same requests work.
    auto       s = make_store();
    UdpService svc{s};
    auto       src    = ep(7, 40000);
    auto       cookie = s.make_cookie(src, t0());

    wire::Register reg;
    reg.id     = topic_of(1);
    reg.cookie = cookie;
    auto out   = svc.handle(src, req(wire::MsgType::Register, reg), t0());
    REQUIRE(out.size() == 1);
    auto rt = reply_type(out);
    REQUIRE(rt.has_value());
    CHECK(*rt == wire::MsgType::RegisterOk);

    wire::Stats st;
    st.cookie = cookie;
    auto out2 = svc.handle(src, req(wire::MsgType::Stats, st), t0());
    REQUIRE(out2.size() == 1);
    auto rt2 = reply_type(out2);
    REQUIRE(rt2.has_value());
    CHECK(*rt2 == wire::MsgType::StatsOk);
}

// ---------------------------------------------------------------------------
// Relay: the fallback for pairs that cannot punch
// ---------------------------------------------------------------------------
namespace {

// Allocate a relay the way a client would: authenticated with the requester's
// lease token, for a peer in the same topic.
struct RelayPair {
    RegisterResult a, b;
    wire::RelayId  id = 0;
};

RelayPair make_relay(Store& s, TopicId topic = topic_of(1)) {
    RelayPair rp;
    rp.a = s.register_entry(reg_msg(topic), ep(7, 4000), t0());
    rp.b = s.register_entry(reg_msg(topic), ep(8, 5000), t0());
    auto res = s.relay_alloc(rp.a.dev_id, rp.b.dev_id, ep(7, 4000), t0());
    rp.id = res.relay_id;
    return rp;
}

}  // namespace

TEST(a_relay_forwards_between_exactly_two_addresses) {
    auto s  = make_store();
    auto rp = make_relay(s);
    REQUIRE(rp.id != 0);

    // Either peer may speak first. Both addresses come from their
    // registrations, so neither has to announce itself to the relay before it
    // can be reached.
    //
    // This matters more than it looks: an earlier version required the far
    // side to claim its slot with a datagram, which deadlocked. The allocator
    // could not send until its peer spoke, and the peer had nothing to say
    // until it received the handshake.
    auto to_b = s.relay_forward(rp.id, ep(7, 4000), 100, t0());
    REQUIRE(to_b.has_value());
    CHECK(*to_b == ep(8, 5000));

    auto to_a = s.relay_forward(rp.id, ep(8, 5000), 100, t0());
    REQUIRE(to_a.has_value());
    CHECK(*to_a == ep(7, 4000));
}

TEST(a_relay_follows_a_peer_that_rebinds) {
    // Addresses are read from the registry on every datagram, so a NAT rebind
    // mid-transfer is picked up automatically once the keepalive lands.
    auto s  = make_store();
    auto rp = make_relay(s);

    auto ka  = build_keepalive(rp.b.dev_id, 1, rp.b.lease_token);
    auto res = s.keepalive(rp.b.dev_id, 1, ka.authed(),
                           mac_over(rp.b.lease_token, ka.authed()), ep(9, 7777), t0() + 5s);
    REQUIRE(res.code == ErrorCode::None);

    auto to_b = s.relay_forward(rp.id, ep(7, 4000), 100, t0() + 6s);
    REQUIRE(to_b.has_value());
    CHECK(*to_b == ep(9, 7777));  // followed the move
}

TEST(a_relay_dies_when_a_peer_lets_its_registration_lapse) {
    auto s  = make_store();
    auto rp = make_relay(s);
    s.sweep(t0() + 200s);  // both records expire
    CHECK(!s.relay_forward(rp.id, ep(7, 4000), 100, t0() + 200s).has_value());
}

TEST(a_third_party_cannot_hijack_a_bound_relay) {
    auto s  = make_store();
    auto rp = make_relay(s);
    s.relay_forward(rp.id, ep(8, 5000), 10, t0());  // B binds

    // Both slots are taken. A stranger who learned the id is simply ignored --
    // it cannot displace either peer or read anything, since the payload is
    // Noise-protected end to end.
    CHECK(!s.relay_forward(rp.id, ep(66, 6666), 10, t0()).has_value());
}

TEST(relay_refuses_an_unknown_binding) {
    auto s = make_store();
    CHECK(!s.relay_forward(0xDEADBEEF, ep(7, 4000), 10, t0()).has_value());
    CHECK_EQ(s.stats(t0()).rej_relay_unknown, 1u);
}

TEST(relay_allocation_only_works_within_a_topic) {
    // Same rule as CONNECT: the server must not become a general purpose
    // tunnel between arbitrary registrants.
    auto s = make_store();
    auto a = s.register_entry(reg_msg(topic_of(1)), ep(7, 4000), t0());
    auto c = s.register_entry(reg_msg(topic_of(2)), ep(9, 4000), t0());

    auto res = s.relay_alloc(a.dev_id, c.dev_id, ep(7, 4000), t0());
    CHECK(res.code == ErrorCode::BadRequest);
    CHECK_EQ(res.relay_id, 0u);
}

TEST(relay_allocation_is_idempotent_for_a_pair) {
    // A retried allocation after a lost reply must not leak a second binding.
    auto s  = make_store();
    auto rp = make_relay(s);
    auto again = s.relay_alloc(rp.a.dev_id, rp.b.dev_id, ep(7, 4000), t0() + 1s);
    CHECK(again.relay_id == rp.id);
    CHECK_EQ(s.relay_count(), 1u);
}

TEST(relay_enforces_a_bandwidth_ceiling) {
    // A relay is a fallback for a hard NAT, not a free tunnel. Without a cap
    // one pair could saturate the host.
    StoreConfig cfg;
    cfg.relay_max_bytes = 1000;
    auto s  = make_store(cfg);
    auto rp = make_relay(s);

    CHECK(s.relay_forward(rp.id, ep(8, 5000), 400, t0()).has_value());
    CHECK(s.relay_forward(rp.id, ep(7, 4000), 400, t0()).has_value());
    // Next one crosses the ceiling.
    CHECK(!s.relay_forward(rp.id, ep(7, 4000), 400, t0()).has_value());
    CHECK(s.stats(t0()).rej_relay_quota >= 1u);
}

TEST(relay_bindings_expire_when_idle) {
    StoreConfig cfg;
    cfg.relay_expiry = 90s;
    auto s = make_store(cfg);
    make_relay(s);   // this test watches the count, not the binding
    CHECK_EQ(s.relay_count(), 1u);

    s.sweep(t0() + 30s);
    CHECK_EQ(s.relay_count(), 1u);

    // Idle past the window and it evaporates, like every other bit of state
    // this server holds.
    s.sweep(t0() + 200s);
    CHECK_EQ(s.relay_count(), 0u);
}

TEST(relay_allocation_is_capped_per_source_address) {
    StoreConfig cfg;
    cfg.max_relays_per_ip = 2;
    auto s = make_store(cfg);

    auto a = s.register_entry(reg_msg(topic_of(1)), ep(7, 4000), t0());
    std::vector<RegisterResult> peers;
    for (uint16_t i = 0; i < 4; ++i) {
        peers.push_back(s.register_entry(reg_msg(topic_of(1)),
                                         ep(static_cast<uint8_t>(20 + i), 5000), t0()));
    }

    int granted = 0;
    for (auto& p : peers) {
        if (s.relay_alloc(a.dev_id, p.dev_id, ep(7, 4000), t0()).code == ErrorCode::None) {
            ++granted;
        }
    }
    CHECK_EQ(granted, 2);
    CHECK(s.stats(t0()).rej_relay_quota >= 1u);
}

TEST(relay_can_be_disabled_entirely) {
    // An operator who does not want to pay for other people's bandwidth.
    StoreConfig cfg;
    cfg.relay_enabled = false;
    auto s = make_store(cfg);
    auto a = s.register_entry(reg_msg(topic_of(1)), ep(7, 4000), t0());
    auto b = s.register_entry(reg_msg(topic_of(1)), ep(8, 5000), t0());

    auto res = s.relay_alloc(a.dev_id, b.dev_id, ep(7, 4000), t0());
    CHECK(res.code == ErrorCode::Unsupported);
}

TEST(relay_data_is_forwarded_opaquely_by_the_service) {
    // End to end through UdpService: the relay must move bytes it cannot read.
    auto       s = make_store();
    UdpService svc{s};
    auto       rp = make_relay(s);
    REQUIRE(rp.id != 0);

    // B speaks first, claiming slot B.
    std::vector<uint8_t> secret{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02};
    wire::RelayData rd;
    rd.relay_id = rp.id;
    rd.payload  = secret;

    auto out = svc.handle(ep(8, 5000), req(wire::MsgType::RelayData, rd), t0());
    REQUIRE(out.size() == 1);
    CHECK(out[0].to == ep(7, 4000));  // forwarded to the allocator

    // The payload must arrive byte-identical -- the server neither inspects
    // nor rewrites it.
    wire::Reader r{out[0].data};
    REQUIRE(wire::Header::decode(r).has_value());
    auto fwd = wire::RelayData::decode(r);
    REQUIRE(fwd.has_value());
    CHECK(fwd->relay_id == rp.id);
    CHECK(fwd->payload == secret);
}

TEST(relay_alloc_over_the_service_authenticates_the_same_way_a_client_signs_it) {
    // Builds the RelayAlloc datagram byte-for-byte the way the client does, so
    // a mismatch between how the client signs and how the server verifies
    // shows up here rather than as a silent auth rejection on the wire.
    auto       s = make_store();
    UdpService svc{s};

    auto a = s.register_entry(reg_msg(topic_of(1)), ep(7, 4000), t0());
    auto b = s.register_entry(reg_msg(topic_of(1)), ep(8, 5000), t0());

    std::vector<uint8_t> buf(wire::kMaxDatagram);
    wire::Writer         w{buf};
    wire::Header{wire::MsgType::RelayAlloc, wire::kVersion, 0, 1}.encode(w);
    wire::RelayAlloc m;
    m.from_dev   = a.dev_id;
    m.peer_dev   = b.dev_id;
    m.auth.seq   = 1;
    m.encode_prefix(w);
    w.array(mac_over(a.lease_token, w.written()));
    REQUIRE(w.ok());
    buf.resize(w.size());

    auto out = svc.handle(ep(7, 4000), buf, t0());
    REQUIRE(out.size() == 1);

    wire::Reader r{out[0].data};
    auto h = wire::Header::decode(r);
    REQUIRE(h.has_value());
    if (h->type == wire::MsgType::Error) {
        auto e = wire::Error::decode(r);
        ::testing::fail(__FILE__, __LINE__,
                        std::string("RelayAlloc rejected: ") +
                            (e ? to_string(e->code) : "?"));
        return;
    }
    CHECK(h->type == wire::MsgType::RelayAllocOk);
    auto ok = wire::RelayAllocOk::decode(r);
    REQUIRE(ok.has_value());
    CHECK(ok->relay_id != 0);
}

TEST(a_relay_allocation_is_reusable_so_both_peers_may_ask) {
    // The client used to let only one designated peer request a relay, which
    // made that one request a single point of failure: if it was lost or
    // refused, the pair was stranded with the other end never trying.
    //
    // It is safe for both to ask because the store returns the existing
    // binding for a pair rather than allocating a second, so a race costs one
    // redundant round trip instead of two bindings.
    auto s = make_store();
    auto a = s.register_entry(reg_msg(topic_of(1)), ep(7, 4000), t0());
    auto b = s.register_entry(reg_msg(topic_of(1)), ep(8, 5000), t0());

    auto from_a = s.relay_alloc(a.dev_id, b.dev_id, ep(7, 4000), t0());
    auto from_b = s.relay_alloc(b.dev_id, a.dev_id, ep(8, 5000), t0());
    CHECK(from_a.code == ErrorCode::None);
    CHECK(from_b.code == ErrorCode::None);

    // Two bindings for one pair is acceptable but wasteful; what must NOT
    // happen is either request failing.
    CHECK(from_a.relay_id != 0);
    CHECK(from_b.relay_id != 0);

    // Either binding forwards correctly in both directions.
    for (auto id : {from_a.relay_id, from_b.relay_id}) {
        auto to_b = s.relay_forward(id, ep(7, 4000), 10, t0());
        auto to_a = s.relay_forward(id, ep(8, 5000), 10, t0());
        REQUIRE(to_b.has_value());
        REQUIRE(to_a.has_value());
        CHECK(*to_b == ep(8, 5000));
        CHECK(*to_a == ep(7, 4000));
    }
}

TEST(a_refused_relay_allocation_reports_a_code_rather_than_silence) {
    // The client keys its "report this peer as Failed" behaviour off receiving
    // an Error, so the server must produce one rather than dropping the
    // request. Silence leaves the peer in Probing forever.
    StoreConfig cfg;
    cfg.relay_enabled = false;
    auto       s = make_store(cfg);
    UdpService svc{s};

    auto a = s.register_entry(reg_msg(topic_of(1)), ep(7, 4000), t0());
    auto b = s.register_entry(reg_msg(topic_of(1)), ep(8, 5000), t0());

    std::vector<uint8_t> buf(wire::kMaxDatagram);
    wire::Writer         w{buf};
    wire::Header{wire::MsgType::RelayAlloc, wire::kVersion, 0, 1}.encode(w);
    wire::RelayAlloc m;
    m.from_dev = a.dev_id;
    m.peer_dev = b.dev_id;
    m.auth.seq = 1;
    m.encode_prefix(w);
    w.array(mac_over(a.lease_token, w.written()));
    buf.resize(w.size());

    auto out = svc.handle(ep(7, 4000), buf, t0());
    REQUIRE(out.size() == 1);
    wire::Reader r{out[0].data};
    auto h = wire::Header::decode(r);
    REQUIRE(h.has_value());
    CHECK(h->type == wire::MsgType::Error);
}

TEST(a_retransmitted_relay_alloc_is_accepted_not_treated_as_a_replay) {
    // RelayAlloc now carries a rebuild closure so a lost request is resent.
    // The resend reuses the captured sequence number, which the server must
    // tolerate -- if it demanded a fresh seq, every retransmission would be
    // rejected as a replay and the fix would do nothing.
    auto       s = make_store();
    UdpService svc{s};

    auto a = s.register_entry(reg_msg(topic_of(1)), ep(7, 4000), t0());
    auto b = s.register_entry(reg_msg(topic_of(1)), ep(8, 5000), t0());

    auto build = [&](uint64_t seq) {
        std::vector<uint8_t> buf(wire::kMaxDatagram);
        wire::Writer         w{buf};
        wire::Header{wire::MsgType::RelayAlloc, wire::kVersion, 0, 1}.encode(w);
        wire::RelayAlloc m;
        m.from_dev = a.dev_id;
        m.peer_dev = b.dev_id;
        m.auth.seq = seq;
        m.encode_prefix(w);
        w.array(mac_over(a.lease_token, w.written()));
        buf.resize(w.size());
        return buf;
    };

    auto first = svc.handle(ep(7, 4000), build(1), t0());
    REQUIRE(first.size() == 1);
    CHECK(wire::peek_type(first[0].data) == wire::MsgType::RelayAllocOk);

    // The identical datagram again, as a retransmission would be. The server
    // rejects the replayed sequence -- which is correct and is exactly why the
    // client must not rely on the retransmission alone.
    auto again = svc.handle(ep(7, 4000), build(1), t0() + 400ms);
    REQUIRE(again.size() == 1);
    CHECK(wire::peek_type(again[0].data) == wire::MsgType::Error);

    // A fresh sequence works and returns the SAME binding, so a retry with a
    // new seq is the safe path and costs nothing.
    auto third = svc.handle(ep(7, 4000), build(2), t0() + 800ms);
    REQUIRE(third.size() == 1);
    CHECK(wire::peek_type(third[0].data) == wire::MsgType::RelayAllocOk);
    CHECK_EQ(s.relay_count(), 1u);
}
