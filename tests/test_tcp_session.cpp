// TcpSession: the Noise handshake and sealed records over a TCP byte stream.
// Two sessions are joined by an in-memory pipe, so every test is deterministic
// and the clock is a parameter.

#include "tcp_session.hpp"
#include "testing.hpp"

using namespace uconnect;
using namespace uconnect::session;
using namespace std::chrono_literals;

namespace {

Instant t0() { return Instant{} + 1000000s; }

TopicId        topic_of(uint8_t f) { TopicId t{}; t.fill(f); return t; }
DevId          dev_of(uint8_t f)   { DevId d{};   d.fill(f); return d; }
crypto::SymKey psk_of(uint8_t f)   { crypto::SymKey k{}; k.fill(f); return k; }
AttemptNonce   nonce_of(uint8_t f) { AttemptNonce n{}; n.fill(f); return n; }

struct Pair {
    TcpSession a;  // initiator: the smaller dev_id
    TcpSession b;
};

Pair session_pair(const crypto::SymKey* psk_a = nullptr, const crypto::SymKey* psk_b = nullptr,
               AttemptNonce na = nonce_of(9), AttemptNonce nb = nonce_of(9),
               TcpSessionConfig cfg = {}) {
    return Pair{TcpSession::initiate(cfg, topic_of(1), 0, psk_a, dev_of(1), dev_of(2), na, t0()),
                TcpSession::respond(cfg, topic_of(1), 0, psk_b, dev_of(2), dev_of(1), nb, t0())};
}

// Move whatever each side has written to the other, `chunk` bytes at a time.
void pump(Pair& p, Instant now = t0(), size_t chunk = SIZE_MAX) {
    for (int round = 0; round < 8; ++round) {
        for (auto [from, to] : {std::pair{&p.a, &p.b}, std::pair{&p.b, &p.a}}) {
            auto bytes = from->take_output();
            for (size_t off = 0; off < bytes.size(); off += chunk) {
                size_t n = std::min(chunk, bytes.size() - off);
                to->on_bytes(std::span(bytes).subspan(off, n), now);
            }
        }
    }
}

std::vector<TcpEvent> drain(TcpSession& s) {
    std::vector<TcpEvent> out;
    while (auto e = s.poll_event()) out.push_back(std::move(*e));
    return out;
}

bool saw(const std::vector<TcpEvent>& ev, TcpEvent::Kind k) {
    for (const auto& e : ev) {
        if (e.kind == k) return true;
    }
    return false;
}

std::vector<uint8_t> bytes(std::string_view s) { return {s.begin(), s.end()}; }

}  // namespace

TEST(tcp_session_keyed_handshake_establishes_and_both_agree) {
    auto psk = psk_of(0x5A);
    auto p   = session_pair(&psk, &psk);
    pump(p);
    CHECK(p.a.state() == TcpSession::State::Established);
    CHECK(p.b.state() == TcpSession::State::Established);
    CHECK(p.a.handshake_hash() == p.b.handshake_hash());
    CHECK(p.a.sas() == p.b.sas());
}

TEST(tcp_session_records_flow_both_ways_in_order_across_any_chunking) {
    auto p = session_pair();  // open topic, Noise NN
    pump(p, t0(), 1);      // one byte at a time, as TCP is free to deliver
    REQUIRE(p.a.state() == TcpSession::State::Established);
    drain(p.a);
    drain(p.b);

    for (int i = 0; i < 20; ++i) {
        REQUIRE(p.a.send(0x10, bytes("a" + std::to_string(i)), t0()));
        REQUIRE(p.b.send(0x11, bytes("b" + std::to_string(i)), t0()));
    }
    pump(p, t0(), 7);

    auto ea = drain(p.a), eb = drain(p.b);
    REQUIRE(eb.size() == 20);
    REQUIRE(ea.size() == 20);
    for (int i = 0; i < 20; ++i) {
        CHECK(eb[i].record_kind == 0x10);
        CHECK(eb[i].body == bytes("a" + std::to_string(i)));
        CHECK(ea[i].record_kind == 0x11);
        CHECK(ea[i].body == bytes("b" + std::to_string(i)));
    }
}

TEST(tcp_session_carries_a_record_of_the_maximum_size) {
    auto p = session_pair();
    pump(p);
    drain(p.b);
    std::vector<uint8_t> big(1u << 20);
    for (size_t i = 0; i < big.size(); ++i) big[i] = static_cast<uint8_t>(i * 31);
    REQUIRE(p.a.send(0x10, big, t0()));
    CHECK(!p.a.send(0x10, std::vector<uint8_t>((1u << 20) + 1), t0()));
    pump(p, t0(), 1400);
    auto ev = drain(p.b);
    REQUIRE(ev.size() == 1);
    CHECK(ev[0].body == big);
}

TEST(tcp_session_a_wrong_key_never_completes) {
    auto k1 = psk_of(1), k2 = psk_of(2);
    auto p  = session_pair(&k1, &k2);
    pump(p);
    CHECK(p.b.state() == TcpSession::State::Closed);
    CHECK(p.a.state() != TcpSession::State::Established);
}

TEST(tcp_session_a_connection_for_another_attempt_is_refused) {
    // The responder was built for attempt 9; this initiator answers attempt 8.
    auto p = session_pair(nullptr, nullptr, nonce_of(8), nonce_of(9));
    pump(p);
    CHECK(p.b.state() == TcpSession::State::Closed);
}

TEST(tcp_session_a_different_peer_claiming_the_attempt_is_refused) {
    // An attempt is issued for one peer. Another initiator bearing the nonce
    // -- say one that saw it on the wire -- is not that peer.
    TcpSessionConfig cfg;
    TcpSession impostor = TcpSession::initiate(cfg, topic_of(1), 0, nullptr, dev_of(3),
                                               dev_of(2), nonce_of(9), t0());
    TcpSession b = TcpSession::respond(cfg, topic_of(1), 0, nullptr, dev_of(2), dev_of(1),
                                       nonce_of(9), t0());
    auto first = impostor.take_output();
    b.on_bytes(first, t0());
    CHECK(b.state() == TcpSession::State::Closed);
    CHECK(!b.has_output());
}

TEST(tcp_session_peek_finds_the_attempt_in_the_first_frame) {
    auto p     = session_pair(nullptr, nullptr, nonce_of(0x44), nonce_of(0x44));
    auto first = p.a.take_output();
    CHECK(!TcpSession::peek_attempt(std::span(first).first(10)).has_value());  // not yet
    auto n = TcpSession::peek_attempt(first);
    REQUIRE(n.has_value());
    CHECK(*n == nonce_of(0x44));
}

TEST(tcp_session_a_tampered_record_ends_the_session) {
    auto p = session_pair();
    pump(p);
    drain(p.b);
    REQUIRE(p.a.send(0x10, bytes("hello"), t0()));
    auto wire = p.a.take_output();
    wire.back() ^= 0x01;
    p.b.on_bytes(wire, t0());
    CHECK(p.b.state() == TcpSession::State::Closed);
    auto ev = drain(p.b);
    CHECK(!saw(ev, TcpEvent::Kind::Record));
}

TEST(tcp_session_an_oversized_length_is_refused_before_it_is_buffered) {
    TcpSessionConfig cfg;
    cfg.max_record = 1000;
    auto p         = session_pair(nullptr, nullptr, nonce_of(9), nonce_of(9), cfg);
    pump(p);
    const std::array<uint8_t, 4> huge{0x7F, 0xFF, 0xFF, 0xFF};
    p.b.on_bytes(huge, t0());
    CHECK(p.b.state() == TcpSession::State::Closed);
}

TEST(tcp_session_close_tells_the_peer_why) {
    auto p = session_pair();
    pump(p);
    drain(p.a);
    drain(p.b);
    p.a.close(2, t0());
    pump(p);
    auto ev = drain(p.b);
    REQUIRE(ev.size() == 1);
    CHECK(ev[0].kind == TcpEvent::Kind::Closed);
    CHECK(ev[0].cause == CloseCause::PeerNotice);
    CHECK_EQ(ev[0].peer_reason, 2);
    CHECK(p.b.state() == TcpSession::State::Closed);
}

TEST(tcp_session_a_connection_ending_without_a_close_reads_as_gone) {
    auto p = session_pair();
    pump(p);
    drain(p.b);
    p.b.on_eof(t0());
    auto ev = drain(p.b);
    REQUIRE(ev.size() == 1);
    CHECK(ev[0].cause == CloseCause::TimedOut);
}

TEST(tcp_session_keepalives_hold_it_open_and_silence_ends_it) {
    auto p = session_pair();
    pump(p);
    // Traffic both ways every 20s keeps both alive well past the timeout.
    for (int i = 1; i <= 10; ++i) {
        const Instant now = t0() + std::chrono::seconds(20 * i);
        p.a.on_timeout(now);
        p.b.on_timeout(now);
        pump(p, now);
    }
    CHECK(p.a.state() == TcpSession::State::Established);
    CHECK(p.b.state() == TcpSession::State::Established);

    // Then silence from A: B gives up after the idle timeout.
    const Instant last = t0() + 200s;
    p.b.on_timeout(last + 91s);
    CHECK(p.b.state() == TcpSession::State::Closed);
}

TEST(tcp_session_a_handshake_that_never_finishes_times_out) {
    auto p = session_pair();
    p.a.take_output();  // message 1 lost in a dead connection
    p.a.on_timeout(t0() + 11s);
    CHECK(p.a.state() == TcpSession::State::Closed);
}

TEST(tcp_session_keys_ratchet_without_losing_step) {
    TcpSessionConfig cfg;
    cfg.rekey_every = 4;
    auto p          = session_pair(nullptr, nullptr, nonce_of(9), nonce_of(9), cfg);
    pump(p);
    drain(p.b);
    for (int i = 0; i < 50; ++i) REQUIRE(p.a.send(0x10, bytes(std::to_string(i)), t0()));
    pump(p);
    CHECK_EQ(drain(p.b).size(), 50u);
    CHECK(p.b.state() == TcpSession::State::Established);
}

TEST(tcp_session_the_layer_above_cannot_forge_the_sessions_own_records) {
    auto p = session_pair();
    pump(p);
    CHECK(!p.a.send(0x02, bytes("\x00\x01"), t0()));  // kClose
    CHECK(!p.a.send(0x0F, {}, t0()));
}

TEST(tcp_session_datagram_keys_pair_up_and_share_nothing_with_each_other) {
    auto psk = psk_of(3);
    auto p   = session_pair(&psk, &psk);
    pump(p);
    auto ka = p.a.datagram_keys(), kb = p.b.datagram_keys();
    CHECK(ka.send == kb.recv);
    CHECK(ka.recv == kb.send);
    CHECK(!(ka.send == ka.recv));
    CHECK(ka.probe == kb.probe);
    CHECK(!(ka.probe == ka.send));
    CHECK_EQ(ka.conn_id, kb.conn_id);

    // And another session's keys are different.
    auto q = session_pair(&psk, &psk);
    pump(q);
    CHECK(!(q.a.datagram_keys().send == ka.send));
}

TEST(tcp_session_each_datagram_epoch_has_keys_of_its_own) {
    // A reopened channel counts its packets from zero again; under the same
    // keys that would reuse every nonce. Both ends must still agree per epoch.
    auto p = session_pair();
    pump(p);
    auto a1 = p.a.datagram_keys(1), a2 = p.a.datagram_keys(2);
    auto b2 = p.b.datagram_keys(2);
    CHECK(!(a1.send == a2.send));
    CHECK(!(a1.probe == a2.probe));
    CHECK(a1.conn_id != a2.conn_id);
    CHECK(a2.send == b2.recv);
    CHECK(a2.conn_id == b2.conn_id);
}
