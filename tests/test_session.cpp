// The UDP datagram channel: sealed datagrams keyed from the TCP session.
// Sessions here are built straight from keys, as the Node builds them from
// TcpSession::datagram_keys(); the handshake that produces those keys is
// tested in test_tcp_session.cpp.

#include <string_view>
#include <utility>

#include "session.hpp"
#include "testing.hpp"

using namespace uconnect;
using namespace uconnect::session;
using namespace std::chrono_literals;

namespace {

Instant t0() { return Instant{} + 1000000s; }

DevId dev_of(uint8_t f) {
    DevId d{};
    d.fill(f);
    return d;
}

Endpoint ep(uint8_t last, uint16_t port) {
    return Endpoint{IpAddr::v4(203, 0, 113, last), port};
}

crypto::SymKey key_of(uint8_t f) {
    crypto::SymKey k{};
    k.fill(f);
    return k;
}

std::vector<uint8_t> bytes(std::string_view s) {
    return {reinterpret_cast<const uint8_t*>(s.data()),
            reinterpret_cast<const uint8_t*>(s.data()) + s.size()};
}

// A matched pair: A sends under one key and B receives under it, and the other
// way round. A reaches B at ep(4, 4000); B reaches A at ep(5, 5000).
struct Pair {
    Session a;
    Session b;
};

Pair establish(SessionConfig cfg = {}, uint8_t salt = 0, wire::ConnId conn_id = 0xC0FFEE) {
    const auto a2b = key_of(static_cast<uint8_t>(0xA0 + salt));
    const auto b2a = key_of(static_cast<uint8_t>(0xB0 + salt));
    return Pair{Session{cfg, dev_of(2), ep(4, 4000), a2b, b2a, conn_id, t0()},
                Session{cfg, dev_of(1), ep(5, 5000), b2a, a2b, conn_id, t0()}};
}

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

std::vector<std::string> drain_data(Session& s) {
    std::vector<std::string> out;
    while (auto e = s.poll_event()) {
        if (e->kind == SessionEvent::Kind::Data) out.emplace_back(e->data.begin(), e->data.end());
    }
    return out;
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
// Transport
// ---------------------------------------------------------------------------
TEST(data_flows_in_both_directions) {
    auto p = establish();

    auto msg = bytes("hello from A");
    CHECK(p.a.send(msg, t0() + 20ms));
    auto dg = p.a.poll_transmit();
    REQUIRE(dg.has_value());
    CHECK(dg->to == ep(4, 4000));
    p.b.on_datagram(ep(5, 5000), dg->data, t0() + 25ms);

    auto e = p.b.poll_event();
    REQUIRE(e.has_value());
    CHECK(e->kind == SessionEvent::Kind::Data);
    CHECK(e->data == msg);

    auto reply = bytes("hello back");
    CHECK(p.b.send(reply, t0() + 30ms));
    auto dg2 = p.b.poll_transmit();
    REQUIRE(dg2.has_value());
    p.a.on_datagram(ep(4, 4000), dg2->data, t0() + 35ms);

    auto e2 = p.a.poll_event();
    REQUIRE(e2.has_value());
    CHECK(e2->kind == SessionEvent::Kind::Data);
    CHECK(e2->data == reply);
}

TEST(sessions_keyed_differently_cannot_read_each_other) {
    // The keys are the whole of the authentication: a channel keyed from
    // another TCP session is a stranger.
    auto p = establish({}, 0);
    auto q = establish({}, 1);
    p.a.send(bytes("for p only"), t0());
    auto dg = p.a.poll_transmit();
    REQUIRE(dg.has_value());
    q.b.on_datagram(ep(5, 5000), dg->data, t0());
    CHECK(!q.b.poll_event().has_value());
}

TEST(a_forged_transport_datagram_is_dropped) {
    auto p = establish();

    p.a.send(bytes("secret"), t0() + 20ms);
    auto dg = p.a.poll_transmit();
    REQUIRE(dg.has_value());

    auto forged = dg->data;
    forged[forged.size() - 1] ^= 0xFF;  // corrupt the tag
    p.b.on_datagram(ep(5, 5000), forged, t0() + 25ms);
    CHECK(!p.b.poll_event().has_value());

    // And the genuine one still works afterwards -- a forgery must not
    // desynchronise anything.
    p.b.on_datagram(ep(5, 5000), dg->data, t0() + 26ms);
    auto e = p.b.poll_event();
    REQUIRE(e.has_value());
    CHECK(e->kind == SessionEvent::Kind::Data);
}

TEST(a_replayed_transport_datagram_is_dropped) {
    auto p = establish();

    p.a.send(bytes("once"), t0() + 20ms);
    auto dg = p.a.poll_transmit();
    REQUIRE(dg.has_value());

    p.b.on_datagram(ep(5, 5000), dg->data, t0() + 25ms);
    REQUIRE(p.b.poll_event().has_value());

    // Byte-identical replay.
    p.b.on_datagram(ep(5, 5000), dg->data, t0() + 26ms);
    CHECK(!p.b.poll_event().has_value());
}

TEST(out_of_order_delivery_is_accepted) {
    auto p = establish();

    std::vector<std::vector<uint8_t>> dgrams;
    for (int i = 0; i < 5; ++i) {
        p.a.send(bytes("m" + std::to_string(i)), t0() + 20ms);
        auto d = p.a.poll_transmit();
        REQUIRE(d.has_value());
        dgrams.push_back(d->data);
    }

    // Deliver in reverse.
    for (int i = 4; i >= 0; --i) {
        p.b.on_datagram(ep(5, 5000), dgrams[static_cast<size_t>(i)], t0() + 25ms);
    }
    CHECK_EQ(drain_data(p.b).size(), 5u);
}

TEST(a_datagram_for_another_conn_id_is_ignored) {
    auto p = establish();

    p.a.send(bytes("x"), t0() + 20ms);
    auto dg = p.a.poll_transmit();
    REQUIRE(dg.has_value());

    // Rewrite conn_id in place (immediately after the 8-byte header).
    auto other = dg->data;
    other[wire::Header::kSize] ^= 0xFF;
    p.b.on_datagram(ep(5, 5000), other, t0() + 25ms);
    CHECK(!p.b.poll_event().has_value());
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------
TEST(a_session_survives_the_peer_changing_address) {
    // Matching on conn_id rather than the 4-tuple is what makes a NAT rebind or
    // a Wi-Fi to LTE handoff survivable.
    auto p = establish();

    p.a.send(bytes("from the new address"), t0() + 20ms);
    auto dg = p.a.poll_transmit();
    REQUIRE(dg.has_value());

    Endpoint moved = ep(99, 55555);
    p.b.on_datagram(moved, dg->data, t0() + 25ms);

    bool saw_change = false, saw_data = false;
    while (auto e = p.b.poll_event()) {
        if (e->kind == SessionEvent::Kind::PathChanged) {
            saw_change = true;
            CHECK(e->path == moved);
        }
        if (e->kind == SessionEvent::Kind::Data) saw_data = true;
    }
    CHECK(saw_change);
    CHECK(saw_data);
    CHECK(p.b.path() == moved);
    CHECK(p.b.state() == SessionState::Established);
}

TEST(a_forged_datagram_cannot_move_the_path) {
    // Migration happens only after the AEAD verifies. Otherwise anyone could
    // redirect a session by spoofing one packet.
    auto p = establish();

    p.a.send(bytes("x"), t0() + 20ms);
    auto dg = p.a.poll_transmit();
    REQUIRE(dg.has_value());
    auto forged = dg->data;
    forged[forged.size() - 2] ^= 0xFF;

    Endpoint attacker = ep(66, 6666);
    p.b.on_datagram(attacker, forged, t0() + 25ms);
    CHECK(!p.b.poll_event().has_value());
    CHECK(p.b.path() == ep(5, 5000));  // unmoved
}

TEST(moving_the_path_keeps_the_counters_and_so_never_reuses_a_nonce) {
    // The channel moves from a punched path to the relay and back without new
    // keys. If the counter restarted, the same nonce would seal two different
    // packets under one key -- and the peer's replay window would drop the
    // second anyway, so the failure would look like loss.
    auto p = establish();
    p.a.send(bytes("direct"), t0());
    auto first = p.a.poll_transmit();
    REQUIRE(first.has_value());

    p.a.set_path(ep(7, 7000), t0() + 1s);
    p.a.send(bytes("relayed"), t0() + 1s);
    auto second = p.a.poll_transmit();
    REQUIRE(second.has_value());
    CHECK(second->to == ep(7, 7000));

    p.b.on_datagram(ep(5, 5000), first->data, t0() + 1s);
    p.b.on_datagram(ep(7, 7000), second->data, t0() + 1s);
    auto got = drain_data(p.b);
    REQUIRE(got.size() == 2);
    CHECK(got[1] == "relayed");
    CHECK_EQ(p.a.messages_sent(), 2u);
}

// ---------------------------------------------------------------------------
// Timers
// ---------------------------------------------------------------------------
TEST(keepalives_are_emitted_on_the_peer_path) {
    // The TCP connection's traffic does nothing for a UDP mapping -- it has
    // its own timer.
    SessionConfig cfg;
    cfg.keepalive = 20s;
    auto p        = establish(cfg);

    p.a.on_timeout(t0() + 10s);
    CHECK(!p.a.poll_transmit().has_value());  // not due yet

    p.a.on_timeout(t0() + 21s);
    auto ka = p.a.poll_transmit();
    REQUIRE(ka.has_value());

    // An empty payload is a keepalive: it decrypts, refreshes liveness, and
    // surfaces no Data event.
    p.b.on_datagram(ep(5, 5000), ka->data, t0() + 22s);
    while (auto e = p.b.poll_event()) CHECK(e->kind != SessionEvent::Kind::Data);
    CHECK(p.b.last_received() == t0() + 22s);
}

TEST(a_new_path_is_kept_open_at_once) {
    // Setting a path sends a keepalive on the next timer, not 20s later: the
    // NAT mapping on the new path has to be opened from our side too.
    auto p = establish();
    p.a.set_path(ep(8, 8000), t0() + 1s);
    p.a.on_timeout(t0() + 1s);
    auto ka = p.a.poll_transmit();
    REQUIRE(ka.has_value());
    CHECK(ka->to == ep(8, 8000));
}

TEST(an_idle_session_closes_after_the_idle_timeout) {
    SessionConfig cfg;
    cfg.idle_timeout = 90s;
    auto p           = establish(cfg);

    p.b.on_timeout(t0() + 60s);
    CHECK(p.b.state() == SessionState::Established);

    p.b.on_timeout(t0() + 200s);
    CHECK(p.b.state() == SessionState::Closed);
}

// ---------------------------------------------------------------------------
// Wire-level close
// ---------------------------------------------------------------------------
TEST(a_closing_peer_is_reported_in_one_round_trip_not_after_the_idle_timeout) {
    auto p = establish();

    p.a.close_with_notice(wire::close_reason::kShutdown, t0() + 1s);
    CHECK(p.a.state() == SessionState::Closed);

    REQUIRE(deliver(p.a, p.b, ep(5, 5000), t0() + 1s) > 0);

    CHECK(p.b.state() == SessionState::Closed);
    auto ev = take(p.b, SessionEvent::Kind::Closed);
    REQUIRE(ev.has_value());
    CHECK(ev->cause == CloseCause::PeerNotice);
    CHECK_EQ(ev->peer_reason, wire::close_reason::kShutdown);
}

TEST(a_vanished_peer_is_distinguishable_from_one_that_said_goodbye) {
    // The cause is ours, never the peer's: a hostile peer supplies only a
    // reason code, so it cannot dress its own disappearance up as our timer.
    {   // silence
        auto p = establish();
        p.b.on_timeout(t0() + 200s);
        auto ev = take(p.b, SessionEvent::Kind::Closed);
        REQUIRE(ev.has_value());
        CHECK(ev->cause == CloseCause::TimedOut);
    }
    {   // our own call
        auto p = establish();
        p.b.close(t0() + 1s);
        auto ev = take(p.b, SessionEvent::Kind::Closed);
        REQUIRE(ev.has_value());
        CHECK(ev->cause == CloseCause::Local);
    }
}

TEST(a_close_is_sent_more_than_once_so_one_drop_does_not_lose_it) {
    auto p = establish();
    p.a.close_with_notice(wire::close_reason::kGoingAway, t0() + 1s);

    std::vector<std::vector<uint8_t>> dgrams;
    while (auto o = p.a.poll_transmit()) dgrams.push_back(o->data);
    REQUIRE(dgrams.size() >= 2);

    // Drop every copy but the last: the peer must still learn.
    p.b.on_datagram(ep(5, 5000), dgrams.back(), t0() + 1s);
    CHECK(p.b.state() == SessionState::Closed);
}

TEST(a_data_packet_cannot_be_retyped_into_a_close) {
    // The header is not covered by the AEAD tag. If a close were sealed with
    // the same associated data as a data packet, anyone on path could flip
    // 0x40 to 0x41 and tear down a session they cannot read.
    auto p = establish();
    REQUIRE(p.a.send(bytes("ordinary data"), t0() + 1s).has_value());
    auto o = p.a.poll_transmit();
    REQUIRE(o.has_value());

    auto forged = o->data;
    REQUIRE(forged[0] == static_cast<uint8_t>(wire::MsgType::Transport));
    forged[0] = static_cast<uint8_t>(wire::MsgType::Close);
    p.b.on_datagram(ep(5, 5000), forged, t0() + 1s);

    CHECK(p.b.state() == SessionState::Established);
    CHECK(!take(p.b, SessionEvent::Kind::Closed).has_value());
}

TEST(a_close_cannot_be_retyped_into_data) {
    auto p = establish();
    p.a.close_with_notice(wire::close_reason::kGoingAway, t0() + 1s);
    auto o = p.a.poll_transmit();
    REQUIRE(o.has_value());

    auto forged = o->data;
    forged[0] = static_cast<uint8_t>(wire::MsgType::Transport);
    p.b.on_datagram(ep(5, 5000), forged, t0() + 1s);

    CHECK(p.b.state() == SessionState::Established);
    CHECK(!take(p.b, SessionEvent::Kind::Data).has_value());
}

TEST(a_close_from_the_wrong_session_is_ignored) {
    // conn_id and the keys both have to match, so a close captured from one
    // session is inert against another.
    auto p1 = establish({}, 0);
    auto p2 = establish({}, 3);

    p1.a.close_with_notice(wire::close_reason::kGoingAway, t0() + 1s);
    auto o = p1.a.poll_transmit();
    REQUIRE(o.has_value());

    p2.b.on_datagram(ep(5, 5000), o->data, t0() + 1s);
    CHECK(p2.b.state() == SessionState::Established);
}

TEST(a_replayed_close_cannot_reopen_the_question) {
    auto p = establish();
    p.a.close_with_notice(wire::close_reason::kGoingAway, t0() + 1s);
    std::vector<std::vector<uint8_t>> dgrams;
    while (auto o = p.a.poll_transmit()) dgrams.push_back(o->data);
    REQUIRE(!dgrams.empty());

    p.b.on_datagram(ep(5, 5000), dgrams[0], t0() + 1s);
    CHECK(p.b.state() == SessionState::Closed);

    (void)take(p.b, SessionEvent::Kind::Closed);
    p.b.on_datagram(ep(5, 5000), dgrams[0], t0() + 2s);
    CHECK(!take(p.b, SessionEvent::Kind::Closed).has_value());
}

// ---------------------------------------------------------------------------
// Counter-derived key ratchet
// ---------------------------------------------------------------------------
namespace {
// A deliberately tiny generation so boundaries are reachable in a handful of
// packets. Production uses 2^16.
SessionConfig tiny_generations() {
    SessionConfig cfg;
    cfg.rekey_shift = 2;  // a new generation every 4 packets
    return cfg;
}
}  // namespace

TEST(traffic_survives_many_key_generation_boundaries) {
    // The ratchet is driven by the packet counter, so both ends compute the
    // same generation from a value that arrived with the packet. Nothing is
    // negotiated, so there is nothing to desynchronise.
    auto p = establish(tiny_generations());

    std::vector<std::string> sent;
    for (int i = 0; i < 40; ++i) {          // ten generations
        sent.push_back("payload-" + std::to_string(i));
        REQUIRE(p.a.send(bytes(sent.back()), t0() + 1s).has_value());
    }
    REQUIRE(deliver(p.a, p.b, ep(5, 5000), t0() + 1s) > 0);

    auto got = drain_data(p.b);
    CHECK_EQ(got.size(), sent.size());
    CHECK(got == sent);
}

TEST(a_straggler_from_the_previous_generation_still_decrypts) {
    // Reordering across a boundary is the case that needs the old key kept.
    auto p = establish(tiny_generations());

    // Counters 0..3 are generation 0; counter 4 opens generation 1.
    std::vector<std::vector<uint8_t>> dgrams;
    for (int i = 0; i < 5; ++i) {
        REQUIRE(p.a.send(bytes("m" + std::to_string(i)), t0() + 1s).has_value());
        auto o = p.a.poll_transmit();
        REQUIRE(o.has_value());
        dgrams.push_back(o->data);
    }

    p.b.on_datagram(ep(5, 5000), dgrams[4], t0() + 1s);
    p.b.on_datagram(ep(5, 5000), dgrams[3], t0() + 1s);

    auto got = drain_data(p.b);
    REQUIRE(got.size() == 2);
    CHECK(got[0] == "m4");
    CHECK(got[1] == "m3");   // decrypted under the retained previous key
}

TEST(a_peer_that_jumps_too_many_generations_is_not_followed) {
    // Key selection happens before the AEAD can verify anything, so the cap is
    // what stops a far-future counter from walking the ratchet arbitrarily.
    SessionConfig cfg          = tiny_generations();
    cfg.max_generations_ahead  = 2;
    auto p = establish(cfg);

    std::vector<uint8_t> far;
    for (int i = 0; i < 40; ++i) {
        REQUIRE(p.a.send(bytes("skipped"), t0() + 1s).has_value());
        auto o = p.a.poll_transmit();
        REQUIRE(o.has_value());
        far = o->data;             // the last one is ~generation 9
    }

    p.b.on_datagram(ep(5, 5000), far, t0() + 1s);
    CHECK(drain_data(p.b).empty());
    CHECK(p.b.state() == SessionState::Established);
}

TEST(a_generation_jump_within_the_cap_is_followed) {
    SessionConfig cfg         = tiny_generations();
    cfg.max_generations_ahead = 2;
    auto p = establish(cfg);

    std::vector<uint8_t> ahead;
    for (int i = 0; i < 6; ++i) {           // counters 0..5 -> generation 1
        REQUIRE(p.a.send(bytes("m" + std::to_string(i)), t0() + 1s).has_value());
        auto o = p.a.poll_transmit();
        REQUIRE(o.has_value());
        ahead = o->data;
    }

    p.b.on_datagram(ep(5, 5000), ahead, t0() + 1s);
    auto got = drain_data(p.b);
    REQUIRE(got.size() == 1);
    CHECK(got[0] == "m5");
}

TEST(a_forged_far_future_counter_cannot_derail_the_key_schedule) {
    // Nothing mutates before the AEAD verifies. A forged packet must cost a
    // dropped packet and nothing more.
    auto p = establish(tiny_generations());

    REQUIRE(p.a.send(bytes("before"), t0() + 1s).has_value());
    auto good = p.a.poll_transmit();
    REQUIRE(good.has_value());

    auto forged = good->data;
    wire::Reader probe{forged};
    auto h = wire::Header::decode(probe);
    REQUIRE(h.has_value());
    const size_t counter_off = forged.size() - probe.remaining() + 4;  // after conn_id
    for (int i = 0; i < 8; ++i) forged[counter_off + i] = 0x7F;

    p.b.on_datagram(ep(5, 5000), forged, t0() + 1s);
    CHECK(drain_data(p.b).empty());

    p.b.on_datagram(ep(5, 5000), good->data, t0() + 1s);
    auto got = drain_data(p.b);
    REQUIRE(got.size() == 1);
    CHECK(got[0] == "before");

    for (int i = 0; i < 12; ++i) {
        REQUIRE(p.a.send(bytes("after" + std::to_string(i)), t0() + 2s).has_value());
    }
    REQUIRE(deliver(p.a, p.b, ep(5, 5000), t0() + 2s) > 0);
    CHECK_EQ(drain_data(p.b).size(), 12u);
}

TEST(a_rekey_shift_as_wide_as_the_counter_means_never_rekey) {
    // #27. Shifting a 64-bit value by 64 or more is undefined; on x86 it
    // quietly becomes a shift by zero -- a new key for every packet.
    SessionConfig cfg;
    cfg.rekey_shift = 64;
    auto p          = establish(cfg);

    std::vector<std::vector<uint8_t>> dgrams;
    for (int i = 0; i < 3; ++i) {
        REQUIRE(p.a.send(bytes("m" + std::to_string(i)), t0() + 1s).has_value());
        auto o = p.a.poll_transmit();
        REQUIRE(o.has_value());
        dgrams.push_back(o->data);
    }

    p.b.on_datagram(ep(5, 5000), dgrams[2], t0() + 1s);
    p.b.on_datagram(ep(5, 5000), dgrams[0], t0() + 1s);
    p.b.on_datagram(ep(5, 5000), dgrams[1], t0() + 1s);
    CHECK_EQ(drain_data(p.b).size(), 3u);
}
