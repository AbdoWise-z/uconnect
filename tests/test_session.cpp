#include "session.hpp"
#include "testing.hpp"

using namespace uconnect;
using namespace uconnect::session;
using namespace std::chrono_literals;

namespace {

Instant t0() { return Instant{} + 1000000s; }

TopicId topic_of(uint8_t f) {
    TopicId t{};
    t.fill(f);
    return t;
}

DevId dev_of(uint8_t f) {
    DevId d{};
    d.fill(f);
    return d;
}

Endpoint ep(uint8_t last, uint16_t port) {
    return Endpoint{IpAddr::v4(203, 0, 113, last), port};
}

crypto::SymKey psk_of(uint8_t f) {
    crypto::SymKey k{};
    k.fill(f);
    return k;
}

wire::ProbeTxn txn_of(uint8_t f) {
    wire::ProbeTxn t{};
    t.fill(f);
    return t;
}

std::vector<uint8_t> bytes(std::string_view s) {
    return {reinterpret_cast<const uint8_t*>(s.data()),
            reinterpret_cast<const uint8_t*>(s.data()) + s.size()};
}

// Establish a session pair. Returns nullopt if the responder rejected.
struct Pair {
    Session a;
    Session b;
};

std::optional<Pair> establish(const crypto::SymKey* psk_a, const crypto::SymKey* psk_b,
                              TopicId topic_a = topic_of(1), TopicId topic_b = topic_of(1),
                              wire::ProbeTxn txn_a = txn_of(9),
                              wire::ProbeTxn txn_b = txn_of(9), uint8_t epoch_a = 0,
                              uint8_t epoch_b = 0) {
    auto a = Session::initiate(SessionConfig{}, topic_a, epoch_a, psk_a, dev_of(2),
                               ep(5, 5000), txn_a, t0());
    auto init = a.poll_transmit();
    if (!init) return std::nullopt;

    auto b = Session::accept(SessionConfig{}, topic_b, epoch_b, psk_b, dev_of(1),
                             ep(4, 4000), txn_b, init->data, t0() + 5ms);
    if (!b) return std::nullopt;

    auto resp = b->poll_transmit();
    if (!resp) return std::nullopt;
    a.on_datagram(ep(5, 5000), resp->data, t0() + 10ms);

    if (a.state() != SessionState::Established) return std::nullopt;
    return Pair{std::move(a), std::move(*b)};
}

}  // namespace

// ---------------------------------------------------------------------------
// Replay window
// ---------------------------------------------------------------------------
TEST(replay_window_accepts_in_order_counters) {
    ReplayWindow w;
    for (uint64_t i = 0; i < 1000; ++i) CHECK(w.accept(i));
}

TEST(replay_window_rejects_exact_duplicates) {
    ReplayWindow w;
    CHECK(w.accept(0));
    CHECK(!w.accept(0));
    CHECK(w.accept(5));
    CHECK(!w.accept(5));
    CHECK(w.accept(3));   // a genuine reorder inside the window
    CHECK(!w.accept(3));  // but only once
}

TEST(replay_window_tolerates_reordering_within_its_width) {
    // UDP reorders. A strictly-increasing check would drop legitimate packets.
    ReplayWindow w;
    CHECK(w.accept(100));
    for (uint64_t i = 99; i > 100 - ReplayWindow::kWidth; --i) CHECK(w.accept(i));
    // And none of them a second time.
    for (uint64_t i = 99; i > 100 - ReplayWindow::kWidth; --i) CHECK(!w.accept(i));
}

TEST(replay_window_rejects_anything_older_than_its_width) {
    ReplayWindow w;
    CHECK(w.accept(1000));
    CHECK(!w.accept(1000 - ReplayWindow::kWidth));
    CHECK(!w.accept(0));
}

TEST(replay_window_handles_a_large_forward_jump) {
    ReplayWindow w;
    CHECK(w.accept(1));
    CHECK(w.accept(1'000'000));   // window slides wholesale
    CHECK(!w.accept(2));          // now far too old
    CHECK(w.accept(999'999));     // but recent history still works
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------
TEST(keyed_handshake_establishes_and_both_sides_agree_on_the_hash) {
    auto psk = psk_of(0x5A);
    auto p   = establish(&psk, &psk);
    REQUIRE(p.has_value());
    CHECK(p->a.state() == SessionState::Established);
    CHECK(p->b.state() == SessionState::Established);
    CHECK(p->a.handshake_hash() == p->b.handshake_hash());
    CHECK(p->a.is_authenticated());
    CHECK(p->a.conn_id() == p->b.conn_id());
}

TEST(a_peer_without_the_key_cannot_complete_the_handshake) {
    // The property the whole keyed design rests on: the rendezvous server does
    // not hold K, so it cannot impersonate a member no matter what it serves.
    auto good = psk_of(0x5A);
    auto bad  = psk_of(0x11);
    CHECK(!establish(&good, &bad).has_value());
}

TEST(a_mismatched_topic_id_fails_the_handshake) {
    // topic_id is in the prologue, so this fails cryptographically rather than
    // via a comparison someone might forget.
    auto psk = psk_of(0x5A);
    CHECK(!establish(&psk, &psk, topic_of(1), topic_of(2)).has_value());
}

TEST(a_mismatched_key_epoch_fails_the_handshake) {
    auto psk = psk_of(0x5A);
    CHECK(!establish(&psk, &psk, topic_of(1), topic_of(1), txn_of(9), txn_of(9), 0, 1).has_value());
}

TEST(a_handshake_bound_to_a_different_probe_txn_is_rejected) {
    // This is what makes a replayed HandshakeInit useless: it arrives bound to
    // a transaction the responder never issued.
    auto psk = psk_of(0x5A);
    CHECK(!establish(&psk, &psk, topic_of(1), topic_of(1), txn_of(9), txn_of(7)).has_value());
}

TEST(open_topic_handshake_establishes_without_a_psk) {
    auto p = establish(nullptr, nullptr);
    REQUIRE(p.has_value());
    CHECK(p->a.state() == SessionState::Established);
    CHECK(!p->a.is_authenticated());  // and says so
}

TEST(a_keyed_initiator_cannot_be_downgraded_by_an_open_responder) {
    // Silent downgrade is how sound protocols get broken. A Session built with
    // a PSK must fail closed.
    auto psk = psk_of(0x5A);
    auto a   = Session::initiate(SessionConfig{}, topic_of(1), 0, &psk, dev_of(2), ep(5, 5000),
                                 txn_of(9), t0());
    auto init = a.poll_transmit();
    REQUIRE(init.has_value());

    auto b = Session::accept(SessionConfig{}, topic_of(1), 0, nullptr, dev_of(1), ep(4, 4000),
                             txn_of(9), init->data, t0() + 5ms);
    // NN's reader may consume the message, but the hashes diverge, so no shared
    // key can result and the initiator will reject the response.
    if (b) {
        auto resp = b->poll_transmit();
        REQUIRE(resp.has_value());
        a.on_datagram(ep(5, 5000), resp->data, t0() + 10ms);
        CHECK(a.state() != SessionState::Established);
    }
}

TEST(a_tampered_handshake_init_is_rejected_silently) {
    auto psk = psk_of(0x5A);
    auto a   = Session::initiate(SessionConfig{}, topic_of(1), 0, &psk, dev_of(2), ep(5, 5000),
                                 txn_of(9), t0());
    auto init = a.poll_transmit();
    REQUIRE(init.has_value());

    for (size_t i = wire::Header::kSize + 4 + wire::kProbeTxnLen; i < init->data.size(); ++i) {
        auto bad = init->data;
        bad[i] ^= 0x01;
        auto b = Session::accept(SessionConfig{}, topic_of(1), 0, &psk, dev_of(1), ep(4, 4000),
                                 txn_of(9), bad, t0() + 5ms);
        if (b.has_value()) {
            ::testing::fail(__FILE__, __LINE__,
                            "tampered byte " + std::to_string(i) + " was accepted");
        }
    }
}

TEST(handshake_retries_then_gives_up) {
    SessionConfig cfg;
    cfg.handshake_timeout = 1s;
    cfg.handshake_retries = 3;

    auto psk = psk_of(0x5A);
    auto a   = Session::initiate(cfg, topic_of(1), 0, &psk, dev_of(2), ep(5, 5000), txn_of(9),
                                 t0());

    int sends = 0;
    while (a.poll_transmit()) ++sends;
    CHECK_EQ(sends, 1);

    Instant now = t0();
    for (int i = 0; i < 5; ++i) {
        now += 1s;
        a.on_timeout(now);
        while (a.poll_transmit()) ++sends;
    }
    CHECK(sends <= cfg.handshake_retries);
    CHECK(a.state() == SessionState::Closed);
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------
TEST(data_flows_in_both_directions) {
    auto psk = psk_of(0x5A);
    auto p   = establish(&psk, &psk);
    REQUIRE(p.has_value());
    while (p->a.poll_event()) {}
    while (p->b.poll_event()) {}

    auto msg = bytes("hello from A");
    CHECK(p->a.send(msg, t0() + 20ms));
    auto dg = p->a.poll_transmit();
    REQUIRE(dg.has_value());
    p->b.on_datagram(ep(4, 4000), dg->data, t0() + 25ms);

    auto e = p->b.poll_event();
    REQUIRE(e.has_value());
    CHECK(e->kind == SessionEvent::Kind::Data);
    CHECK(e->data == msg);

    auto reply = bytes("hello back");
    CHECK(p->b.send(reply, t0() + 30ms));
    auto dg2 = p->b.poll_transmit();
    REQUIRE(dg2.has_value());
    p->a.on_datagram(ep(5, 5000), dg2->data, t0() + 35ms);

    auto e2 = p->a.poll_event();
    REQUIRE(e2.has_value());
    CHECK(e2->kind == SessionEvent::Kind::Data);
    CHECK(e2->data == reply);
}

TEST(a_forged_transport_datagram_is_dropped) {
    auto psk = psk_of(0x5A);
    auto p   = establish(&psk, &psk);
    REQUIRE(p.has_value());
    while (p->b.poll_event()) {}

    p->a.send(bytes("secret"), t0() + 20ms);
    auto dg = p->a.poll_transmit();
    REQUIRE(dg.has_value());

    auto forged = dg->data;
    forged[forged.size() - 1] ^= 0xFF;  // corrupt the tag
    p->b.on_datagram(ep(4, 4000), forged, t0() + 25ms);
    CHECK(!p->b.poll_event().has_value());

    // And the genuine one still works afterwards -- a forgery must not
    // desynchronise the stream.
    p->b.on_datagram(ep(4, 4000), dg->data, t0() + 26ms);
    auto e = p->b.poll_event();
    REQUIRE(e.has_value());
    CHECK(e->kind == SessionEvent::Kind::Data);
}

TEST(a_replayed_transport_datagram_is_dropped) {
    auto psk = psk_of(0x5A);
    auto p   = establish(&psk, &psk);
    REQUIRE(p.has_value());
    while (p->b.poll_event()) {}

    p->a.send(bytes("once"), t0() + 20ms);
    auto dg = p->a.poll_transmit();
    REQUIRE(dg.has_value());

    p->b.on_datagram(ep(4, 4000), dg->data, t0() + 25ms);
    REQUIRE(p->b.poll_event().has_value());

    // Byte-identical replay.
    p->b.on_datagram(ep(4, 4000), dg->data, t0() + 26ms);
    CHECK(!p->b.poll_event().has_value());
}

TEST(out_of_order_delivery_is_accepted) {
    auto psk = psk_of(0x5A);
    auto p   = establish(&psk, &psk);
    REQUIRE(p.has_value());
    while (p->b.poll_event()) {}

    std::vector<std::vector<uint8_t>> dgrams;
    for (int i = 0; i < 5; ++i) {
        p->a.send(bytes("m" + std::to_string(i)), t0() + 20ms);
        auto d = p->a.poll_transmit();
        REQUIRE(d.has_value());
        dgrams.push_back(d->data);
    }

    // Deliver in reverse.
    for (int i = 4; i >= 0; --i) {
        p->b.on_datagram(ep(4, 4000), dgrams[static_cast<size_t>(i)], t0() + 25ms);
    }

    int got = 0;
    while (auto e = p->b.poll_event()) {
        if (e->kind == SessionEvent::Kind::Data) ++got;
    }
    CHECK_EQ(got, 5);
}

TEST(a_datagram_for_another_conn_id_is_ignored) {
    auto psk = psk_of(0x5A);
    auto p   = establish(&psk, &psk);
    REQUIRE(p.has_value());
    while (p->b.poll_event()) {}

    p->a.send(bytes("x"), t0() + 20ms);
    auto dg = p->a.poll_transmit();
    REQUIRE(dg.has_value());

    // Rewrite conn_id in place (immediately after the 8-byte header).
    auto other = dg->data;
    other[wire::Header::kSize] ^= 0xFF;
    p->b.on_datagram(ep(4, 4000), other, t0() + 25ms);
    CHECK(!p->b.poll_event().has_value());
}

// ---------------------------------------------------------------------------
// Path migration
// ---------------------------------------------------------------------------
TEST(a_session_survives_the_peer_changing_address) {
    // Matching on conn_id rather than the 4-tuple is what makes a NAT rebind or
    // a Wi-Fi to LTE handoff survivable without a rehandshake.
    auto psk = psk_of(0x5A);
    auto p   = establish(&psk, &psk);
    REQUIRE(p.has_value());
    while (p->b.poll_event()) {}

    p->a.send(bytes("from the new address"), t0() + 20ms);
    auto dg = p->a.poll_transmit();
    REQUIRE(dg.has_value());

    Endpoint moved = ep(99, 55555);
    p->b.on_datagram(moved, dg->data, t0() + 25ms);

    bool saw_change = false, saw_data = false;
    while (auto e = p->b.poll_event()) {
        if (e->kind == SessionEvent::Kind::PathChanged) {
            saw_change = true;
            CHECK(e->path == moved);
        }
        if (e->kind == SessionEvent::Kind::Data) saw_data = true;
    }
    CHECK(saw_change);
    CHECK(saw_data);
    CHECK(p->b.path() == moved);
    CHECK(p->b.state() == SessionState::Established);  // no rehandshake needed
}

TEST(a_forged_datagram_cannot_move_the_path) {
    // Migration happens only after the AEAD verifies. Otherwise anyone could
    // redirect a session by spoofing one packet.
    auto psk = psk_of(0x5A);
    auto p   = establish(&psk, &psk);
    REQUIRE(p.has_value());
    while (p->b.poll_event()) {}

    p->a.send(bytes("x"), t0() + 20ms);
    auto dg = p->a.poll_transmit();
    REQUIRE(dg.has_value());
    auto forged = dg->data;
    forged[forged.size() - 2] ^= 0xFF;

    Endpoint attacker = ep(66, 6666);
    p->b.on_datagram(attacker, forged, t0() + 25ms);
    CHECK(!p->b.poll_event().has_value());
    CHECK(p->b.path() == ep(4, 4000));  // unmoved
}

// ---------------------------------------------------------------------------
// Timers
// ---------------------------------------------------------------------------
TEST(keepalives_are_emitted_on_the_peer_path) {
    // The rendezvous keepalive does nothing for a peer path -- on many NATs
    // those are separate mappings with separate timers.
    SessionConfig cfg;
    cfg.keepalive = 20s;

    auto psk = psk_of(0x5A);
    auto a   = Session::initiate(cfg, topic_of(1), 0, &psk, dev_of(2), ep(5, 5000), txn_of(9),
                                 t0());
    auto init = a.poll_transmit();
    REQUIRE(init.has_value());
    auto b = Session::accept(cfg, topic_of(1), 0, &psk, dev_of(1), ep(4, 4000), txn_of(9),
                             init->data, t0() + 5ms);
    REQUIRE(b.has_value());
    auto resp = b->poll_transmit();
    REQUIRE(resp.has_value());
    a.on_datagram(ep(5, 5000), resp->data, t0() + 10ms);
    REQUIRE(a.state() == SessionState::Established);
    while (a.poll_transmit()) {}

    a.on_timeout(t0() + 10s);
    CHECK(!a.poll_transmit().has_value());  // not due yet

    a.on_timeout(t0() + 21s);
    auto ka = a.poll_transmit();
    REQUIRE(ka.has_value());

    // An empty payload is a keepalive: it decrypts, refreshes liveness, and
    // surfaces no Data event.
    b->on_datagram(ep(4, 4000), ka->data, t0() + 22s);
    while (auto e = b->poll_event()) {
        CHECK(e->kind != SessionEvent::Kind::Data);
    }
    CHECK(b->state() == SessionState::Established);
}

TEST(an_idle_session_closes_after_the_idle_timeout) {
    SessionConfig cfg;
    cfg.idle_timeout = 90s;
    cfg.max_lifetime = 1h;

    auto psk = psk_of(0x5A);
    auto p   = establish(&psk, &psk);
    REQUIRE(p.has_value());

    p->b.on_timeout(t0() + 60s);
    CHECK(p->b.state() == SessionState::Established);

    p->b.on_timeout(t0() + 200s);
    CHECK(p->b.state() == SessionState::Closed);
}

TEST(a_session_asks_for_a_rehandshake_at_its_lifetime_limit) {
    // No in-place rekey in v1: both ends stepping a key in lockstep is easy to
    // get wrong, and the failure looks like packet loss. A fresh handshake on
    // an already-validated path is cheap.
    SessionConfig cfg;
    cfg.max_lifetime = 15min;
    cfg.idle_timeout = 1h;

    auto psk  = psk_of(0x5A);
    auto a    = Session::initiate(cfg, topic_of(1), 0, &psk, dev_of(2), ep(5, 5000), txn_of(9),
                                  t0());
    auto init = a.poll_transmit();
    REQUIRE(init.has_value());
    auto b = Session::accept(cfg, topic_of(1), 0, &psk, dev_of(1), ep(4, 4000), txn_of(9),
                             init->data, t0() + 5ms);
    REQUIRE(b.has_value());
    auto resp = b->poll_transmit();
    REQUIRE(resp.has_value());
    a.on_datagram(ep(5, 5000), resp->data, t0() + 10ms);
    REQUIRE(a.state() == SessionState::Established);
    while (a.poll_event()) {}

    a.on_timeout(t0() + 14min);
    CHECK(a.state() == SessionState::Established);

    a.on_timeout(t0() + 16min);
    CHECK(a.state() == SessionState::NeedsRehandshake);

    bool asked = false;
    while (auto e = a.poll_event()) {
        if (e->kind == SessionEvent::Kind::NeedsRehandshake) asked = true;
    }
    CHECK(asked);
    // And it stops accepting new sends, so nothing goes out under an old key.
    CHECK(!a.send(bytes("too late"), t0() + 16min));
}

// ---------------------------------------------------------------------------
// SAS
// ---------------------------------------------------------------------------
TEST(both_ends_derive_the_same_sas_and_a_mitm_would_not) {
    auto psk = psk_of(0x5A);
    auto p   = establish(&psk, &psk);
    REQUIRE(p.has_value());
    CHECK(p->a.sas() == p->b.sas());

    // A separate session -- as an interposed attacker would necessarily run --
    // produces a different string.
    auto q = establish(&psk, &psk);
    REQUIRE(q.has_value());
    CHECK(p->a.sas() != q->a.sas());
}
