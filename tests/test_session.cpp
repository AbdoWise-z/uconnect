#include <string_view>
#include <utility>

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
    auto a = Session::initiate(SessionConfig{}, topic_a, epoch_a, psk_a, dev_of(1), dev_of(2),
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
    auto a   = Session::initiate(SessionConfig{}, topic_of(1), 0, &psk, dev_of(1), dev_of(2), ep(5, 5000),
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
    auto a   = Session::initiate(SessionConfig{}, topic_of(1), 0, &psk, dev_of(1), dev_of(2), ep(5, 5000),
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
    auto a   = Session::initiate(cfg, topic_of(1), 0, &psk, dev_of(1), dev_of(2), ep(5, 5000), txn_of(9),
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
    auto a   = Session::initiate(cfg, topic_of(1), 0, &psk, dev_of(1), dev_of(2), ep(5, 5000), txn_of(9),
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
    auto a    = Session::initiate(cfg, topic_of(1), 0, &psk, dev_of(1), dev_of(2), ep(5, 5000), txn_of(9),
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

// ---------------------------------------------------------------------------
// Peer identity
// ---------------------------------------------------------------------------
TEST(the_responder_learns_the_initiators_dev_id_from_the_handshake) {
    // The responder must NOT have to guess who connected from the source
    // address. Behind a symmetric NAT the handshake arrives from a different
    // mapping than the peer advertised, so address matching fails and the
    // session ends up filed under a synthetic identity -- which surfaced as one
    // peer appearing twice, under its real dev_id and a made-up one.
    auto psk = psk_of(0x5A);

    auto a = Session::initiate(SessionConfig{}, topic_of(1), 0, &psk,
                               dev_of(0xAA),  // who we are
                               dev_of(0xBB), ep(5, 5000), txn_of(9), t0());
    auto init = a.poll_transmit();
    REQUIRE(init.has_value());

    // Deliberately accept from an address that matches NO advertised candidate,
    // and pass a fallback that is deliberately wrong.
    auto b = Session::accept(SessionConfig{}, topic_of(1), 0, &psk,
                             dev_of(0xEE),               // wrong fallback
                             ep(99, 61234),              // unexpected source
                             txn_of(9), init->data, t0() + 5ms);
    REQUIRE(b.has_value());

    // It must report the initiator's real dev_id, not the fallback.
    CHECK(b->peer() == dev_of(0xAA));
    CHECK(!(b->peer() == dev_of(0xEE)));
}

TEST(a_forged_dev_id_cannot_be_injected_on_a_keyed_topic) {
    // The dev_id rides inside the Noise payload, so on a keyed topic it is
    // encrypted under the PSK and covered by the AEAD tag. Flipping a bit in it
    // must make the whole handshake fail, not silently change who we think the
    // peer is.
    auto psk = psk_of(0x5A);
    auto a = Session::initiate(SessionConfig{}, topic_of(1), 0, &psk, dev_of(0xAA),
                               dev_of(0xBB), ep(5, 5000), txn_of(9), t0());
    auto init = a.poll_transmit();
    REQUIRE(init.has_value());

    // The payload sits after header + conn_id + probe_txn + the 32-byte
    // ephemeral; flip a byte there.
    size_t payload_off = wire::Header::kSize + 4 + wire::kProbeTxnLen + 32;
    REQUIRE(init->data.size() > payload_off);
    auto tampered = init->data;
    tampered[payload_off] ^= 0xFF;

    CHECK(!Session::accept(SessionConfig{}, topic_of(1), 0, &psk, dev_of(0xEE),
                           ep(5, 5000), txn_of(9), tampered, t0() + 5ms)
               .has_value());
}

// ---------------------------------------------------------------------------
// Wire-level close
// ---------------------------------------------------------------------------
namespace {
// Drain a session's outbound queue into the other end.
size_t deliver(Session& from, Session& to, Endpoint via, Instant now) {
    size_t n = 0;
    while (auto o = from.poll_transmit()) {
        to.on_datagram(via, o->data, now);
        ++n;
    }
    return n;
}

std::optional<SessionEvent> take(Session& s, SessionEvent::Kind want) {
    while (auto e = s.poll_event()) {
        if (e->kind == want) return e;
    }
    return std::nullopt;
}
}  // namespace

TEST(a_closing_peer_is_reported_in_one_round_trip_not_after_the_idle_timeout) {
    // The whole point: a deliberate disconnect should not look identical to a
    // cable being pulled, which costs the peer 90s of holding a NAT binding.
    auto psk = psk_of(0x5A);
    auto p   = establish(&psk, &psk);
    REQUIRE(p.has_value());

    p->a.close_with_notice(wire::close_reason::kShutdown, t0() + 1s);
    CHECK(p->a.state() == SessionState::Closed);

    REQUIRE(deliver(p->a, p->b, ep(5, 5000), t0() + 1s) > 0);

    // Immediately, not at t0()+90s.
    CHECK(p->b.state() == SessionState::Closed);
    auto ev = take(p->b, SessionEvent::Kind::Closed);
    REQUIRE(ev.has_value());
    CHECK(ev->cause == CloseCause::PeerNotice);
    CHECK_EQ(ev->peer_reason, wire::close_reason::kShutdown);
}

TEST(a_vanished_peer_is_distinguishable_from_one_that_said_goodbye) {
    // The cause is ours, never the peer's: a hostile peer supplies only a
    // reason code, so it cannot dress its own disappearance up as our timer.
    SessionConfig cfg;
    cfg.idle_timeout = 90s;
    cfg.max_lifetime = 1h;

    auto psk = psk_of(0x5A);

    {   // silence
        auto p = establish(&psk, &psk);
        REQUIRE(p.has_value());
        p->b.on_timeout(t0() + 200s);
        auto ev = take(p->b, SessionEvent::Kind::Closed);
        REQUIRE(ev.has_value());
        CHECK(ev->cause == CloseCause::TimedOut);
    }
    {   // our own call
        auto p = establish(&psk, &psk);
        REQUIRE(p.has_value());
        p->b.close(t0() + 1s);
        auto ev = take(p->b, SessionEvent::Kind::Closed);
        REQUIRE(ev.has_value());
        CHECK(ev->cause == CloseCause::Local);
    }
}

TEST(a_close_is_sent_more_than_once_so_one_drop_does_not_lose_it) {
    // Nothing acknowledges a close, so the only defence against loss is
    // repetition plus the peer's idle timeout as a backstop.
    auto psk = psk_of(0x5A);
    auto p   = establish(&psk, &psk);
    REQUIRE(p.has_value());

    p->a.close_with_notice(wire::close_reason::kGoingAway, t0() + 1s);

    std::vector<std::vector<uint8_t>> dgrams;
    while (auto o = p->a.poll_transmit()) dgrams.push_back(o->data);
    REQUIRE(dgrams.size() >= 2);

    // Drop every copy but the last: the peer must still learn.
    p->b.on_datagram(ep(5, 5000), dgrams.back(), t0() + 1s);
    CHECK(p->b.state() == SessionState::Closed);
}

TEST(a_data_packet_cannot_be_retyped_into_a_close) {
    // The header is not covered by the AEAD tag. If a close were sealed with
    // the same associated data as a data packet, anyone on path could flip
    // 0x40 to 0x41 and tear down a session they cannot read.
    auto psk = psk_of(0x5A);
    auto p   = establish(&psk, &psk);
    REQUIRE(p.has_value());

    REQUIRE(p->a.send(bytes("ordinary data"), t0() + 1s).has_value());
    auto o = p->a.poll_transmit();
    REQUIRE(o.has_value());

    auto forged = o->data;
    REQUIRE(forged[0] == static_cast<uint8_t>(wire::MsgType::Transport));
    forged[0] = static_cast<uint8_t>(wire::MsgType::Close);

    p->b.on_datagram(ep(5, 5000), forged, t0() + 1s);

    CHECK(p->b.state() == SessionState::Established);   // survived
    CHECK(!take(p->b, SessionEvent::Kind::Closed).has_value());
}

TEST(a_close_cannot_be_retyped_into_data) {
    // The same binding in the other direction, so the two kinds really are
    // separated rather than merely distinguished by a byte anyone can edit.
    auto psk = psk_of(0x5A);
    auto p   = establish(&psk, &psk);
    REQUIRE(p.has_value());

    p->a.close_with_notice(wire::close_reason::kGoingAway, t0() + 1s);
    auto o = p->a.poll_transmit();
    REQUIRE(o.has_value());

    auto forged = o->data;
    forged[0] = static_cast<uint8_t>(wire::MsgType::Transport);
    p->b.on_datagram(ep(5, 5000), forged, t0() + 1s);

    CHECK(p->b.state() == SessionState::Established);
    CHECK(!take(p->b, SessionEvent::Kind::Data).has_value());
}

TEST(a_close_from_the_wrong_session_is_ignored) {
    // conn_id and the keys both have to match, so a close captured from one
    // session is inert against another.
    auto psk = psk_of(0x5A);
    auto p1  = establish(&psk, &psk);
    auto p2  = establish(&psk, &psk, topic_of(1), topic_of(1), txn_of(3), txn_of(3));
    REQUIRE(p1.has_value());
    REQUIRE(p2.has_value());

    p1->a.close_with_notice(wire::close_reason::kGoingAway, t0() + 1s);
    auto o = p1->a.poll_transmit();
    REQUIRE(o.has_value());

    p2->b.on_datagram(ep(5, 5000), o->data, t0() + 1s);
    CHECK(p2->b.state() == SessionState::Established);
}

TEST(a_replayed_close_cannot_reopen_the_question) {
    // A close consumes a counter like any other packet, so replaying it is
    // caught by the same window rather than needing its own defence.
    auto psk = psk_of(0x5A);
    auto p   = establish(&psk, &psk);
    REQUIRE(p.has_value());

    // Capture a close without letting the session go: send it from a clone of
    // the same stream position by closing and keeping the datagrams.
    p->a.close_with_notice(wire::close_reason::kGoingAway, t0() + 1s);
    std::vector<std::vector<uint8_t>> dgrams;
    while (auto o = p->a.poll_transmit()) dgrams.push_back(o->data);
    REQUIRE(!dgrams.empty());

    p->b.on_datagram(ep(5, 5000), dgrams[0], t0() + 1s);
    CHECK(p->b.state() == SessionState::Closed);

    // Feeding it again changes nothing and must not emit a second event.
    (void)take(p->b, SessionEvent::Kind::Closed);
    p->b.on_datagram(ep(5, 5000), dgrams[0], t0() + 2s);
    CHECK(!take(p->b, SessionEvent::Kind::Closed).has_value());
}

TEST(a_close_before_the_handshake_completes_puts_nothing_on_the_wire) {
    // There are no keys yet, so there is no way to authenticate a goodbye --
    // and an unauthenticated one would be a teardown primitive for anybody.
    auto psk = psk_of(0x5A);
    auto a   = Session::initiate(SessionConfig{}, topic_of(1), 0, &psk, dev_of(1), dev_of(2),
                                 ep(5, 5000), txn_of(9), t0());
    while (a.poll_transmit()) {}   // discard the handshake init

    a.close_with_notice(wire::close_reason::kGoingAway, t0() + 1s);
    CHECK(a.state() == SessionState::Closed);
    CHECK(!a.poll_transmit().has_value());
}

// ---------------------------------------------------------------------------
// Counter-derived key ratchet
// ---------------------------------------------------------------------------
namespace {

// A pair with a deliberately tiny generation so boundaries are reachable in a
// handful of packets. Production uses 2^16.
std::optional<Pair> establish_with(SessionConfig cfg) {
    auto psk = psk_of(0x5A);
    auto a = Session::initiate(cfg, topic_of(1), 0, &psk, dev_of(1), dev_of(2),
                               ep(5, 5000), txn_of(9), t0());
    auto init = a.poll_transmit();
    if (!init) return std::nullopt;
    auto b = Session::accept(cfg, topic_of(1), 0, &psk, dev_of(1), ep(4, 4000),
                             txn_of(9), init->data, t0() + 5ms);
    if (!b) return std::nullopt;
    auto resp = b->poll_transmit();
    if (!resp) return std::nullopt;
    a.on_datagram(ep(5, 5000), resp->data, t0() + 10ms);
    if (a.state() != SessionState::Established) return std::nullopt;
    return Pair{std::move(a), std::move(*b)};
}

std::vector<std::string> drain_data(Session& s) {
    std::vector<std::string> out;
    while (auto e = s.poll_event()) {
        if (e->kind == SessionEvent::Kind::Data) {
            out.emplace_back(e->data.begin(), e->data.end());
        }
    }
    return out;
}

}  // namespace

TEST(traffic_survives_many_key_generation_boundaries) {
    // The ratchet is driven by the packet counter, so both ends compute the
    // same generation from a value that arrived with the packet. Nothing is
    // negotiated, so there is nothing to desynchronise -- and a desynchronised
    // rekey would show up here as silent total loss, since a key mismatch fails
    // the AEAD tag and a failed tag is dropped without a word.
    SessionConfig cfg;
    cfg.rekey_shift = 2;          // a new generation every 4 packets
    auto p = establish_with(cfg);
    REQUIRE(p.has_value());

    std::vector<std::string> sent;
    for (int i = 0; i < 40; ++i) {          // ten generations
        sent.push_back("payload-" + std::to_string(i));
        REQUIRE(p->a.send(bytes(sent.back()), t0() + 1s).has_value());
    }
    REQUIRE(deliver(p->a, p->b, ep(5, 5000), t0() + 1s) > 0);

    auto got = drain_data(p->b);
    CHECK_EQ(got.size(), sent.size());
    CHECK(got == sent);
}

TEST(a_straggler_from_the_previous_generation_still_decrypts) {
    // Reordering across a boundary is the case that needs the old key kept.
    // One previous generation is provably enough: the replay window refuses
    // anything more than 64 counters behind, so a straggler cannot be two
    // generations old once a generation exceeds 64 packets.
    SessionConfig cfg;
    cfg.rekey_shift = 2;
    auto p = establish_with(cfg);
    REQUIRE(p.has_value());

    // Counters 0..3 are generation 0; counter 4 opens generation 1.
    std::vector<std::vector<uint8_t>> dgrams;
    for (int i = 0; i < 5; ++i) {
        REQUIRE(p->a.send(bytes("m" + std::to_string(i)), t0() + 1s).has_value());
        auto o = p->a.poll_transmit();
        REQUIRE(o.has_value());
        dgrams.push_back(o->data);
    }

    // Deliver the first of the new generation, then the last of the old one.
    p->b.on_datagram(ep(5, 5000), dgrams[4], t0() + 1s);
    p->b.on_datagram(ep(5, 5000), dgrams[3], t0() + 1s);

    auto got = drain_data(p->b);
    REQUIRE(got.size() == 2);
    CHECK(got[0] == "m4");
    CHECK(got[1] == "m3");   // decrypted under the retained previous key
}

TEST(a_peer_that_jumps_too_many_generations_is_not_followed) {
    // Key selection happens before the AEAD can verify anything, so an
    // unauthenticated counter decides how much derivation work to do. The cap
    // is what stops a packet claiming a far-future counter from walking the
    // ratchet arbitrarily far.
    SessionConfig cfg;
    cfg.rekey_shift            = 2;
    cfg.max_generations_ahead  = 2;
    auto p = establish_with(cfg);
    REQUIRE(p.has_value());

    // Burn counters without delivering them: the sender races ahead.
    std::vector<uint8_t> far;
    for (int i = 0; i < 40; ++i) {
        REQUIRE(p->a.send(bytes("skipped"), t0() + 1s).has_value());
        auto o = p->a.poll_transmit();
        REQUIRE(o.has_value());
        far = o->data;             // the last one is ~generation 9
    }

    p->b.on_datagram(ep(5, 5000), far, t0() + 1s);
    CHECK(drain_data(p->b).empty());       // beyond the cap: dropped unread
    CHECK(p->b.state() == SessionState::Established);   // and harmless
}

TEST(a_generation_jump_within_the_cap_is_followed) {
    // The other side of the same bound: losing a generation's worth of packets
    // must not end the session, so a jump inside the cap has to be accepted.
    SessionConfig cfg;
    cfg.rekey_shift           = 2;
    cfg.max_generations_ahead = 2;
    auto p = establish_with(cfg);
    REQUIRE(p.has_value());

    std::vector<uint8_t> ahead;
    for (int i = 0; i < 6; ++i) {           // counters 0..5 -> generation 1
        REQUIRE(p->a.send(bytes("m" + std::to_string(i)), t0() + 1s).has_value());
        auto o = p->a.poll_transmit();
        REQUIRE(o.has_value());
        ahead = o->data;
    }

    p->b.on_datagram(ep(5, 5000), ahead, t0() + 1s);
    auto got = drain_data(p->b);
    REQUIRE(got.size() == 1);
    CHECK(got[0] == "m5");
}

TEST(a_forged_far_future_counter_cannot_derail_the_key_schedule) {
    // The rule that makes any of this safe: nothing mutates before the AEAD
    // verifies. A forged packet must cost a dropped packet and nothing more --
    // not an advanced generation, and not a discarded key real traffic needs.
    SessionConfig cfg;
    cfg.rekey_shift = 2;
    auto p = establish_with(cfg);
    REQUIRE(p.has_value());

    REQUIRE(p->a.send(bytes("before"), t0() + 1s).has_value());
    auto good = p->a.poll_transmit();
    REQUIRE(good.has_value());

    // Same packet, counter rewritten to a wild value. The counter is the AEAD
    // nonce as well as the generation selector, so this fails twice over.
    auto forged = good->data;
    wire::Reader probe{forged};
    auto h = wire::Header::decode(probe);
    REQUIRE(h.has_value());
    const size_t counter_off = forged.size() - probe.remaining() + 4;  // after conn_id
    for (int i = 0; i < 8; ++i) forged[counter_off + i] = 0x7F;

    p->b.on_datagram(ep(5, 5000), forged, t0() + 1s);
    CHECK(drain_data(p->b).empty());

    // The real packet, and everything after it, still works.
    p->b.on_datagram(ep(5, 5000), good->data, t0() + 1s);
    auto got = drain_data(p->b);
    REQUIRE(got.size() == 1);
    CHECK(got[0] == "before");

    for (int i = 0; i < 12; ++i) {
        REQUIRE(p->a.send(bytes("after" + std::to_string(i)), t0() + 2s).has_value());
    }
    REQUIRE(deliver(p->a, p->b, ep(5, 5000), t0() + 2s) > 0);
    CHECK_EQ(drain_data(p->b).size(), 12u);
}
