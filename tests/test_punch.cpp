// Hole punching tests, driven against the simulated network in netsim.hpp.
//
// Every case here is one that cannot be reproduced on demand against the real
// internet: a symmetric NAT on both ends, a router that refuses to hairpin,
// 30% packet loss during the exact window where the two peers have to overlap.
// That is the whole argument for keeping this layer sans-IO.

#include "netsim.hpp"
#include "punch.hpp"
#include "testing.hpp"

using namespace uconnect;
using namespace uconnect::path;
using namespace netsim;
using namespace std::chrono_literals;

namespace {

Instant t0() { return Instant{} + 1000000s; }

DevId dev_of(uint8_t f) {
    DevId d{};
    d.fill(f);
    return d;
}

Candidate host(Endpoint e) { return Candidate{Candidate::Kind::Host, e}; }
Candidate srflx(Endpoint e) { return Candidate{Candidate::Kind::Srflx, e}; }

crypto::SymKey a_key() {
    crypto::SymKey k{};
    k.fill(0x5A);
    return k;
}

// Drive two punch sessions against each other through the network until both
// settle or the deadline passes. Returns true if both nominated a path.
struct PunchOutcome {
    bool                    a_ok = false;
    bool                    b_ok = false;
    std::optional<Endpoint> a_path, b_path;
    Instant                 settled_at{};
};

PunchOutcome run_punch(Network& net, PunchSession& a, PunchSession& b, Instant start,
                       Duration limit = 12s) {
    PunchOutcome out;
    Instant      now = start;
    a.begin(now);
    b.begin(now);

    const Instant deadline = start + limit;
    while (now < deadline) {
        // Flush both sides' outbound queues into the network.
        while (auto o = a.poll_transmit()) net.send("A", o->to, std::move(o->data), now);
        while (auto o = b.poll_transmit()) net.send("B", o->to, std::move(o->data), now);

        for (auto& d : net.advance(now)) {
            if (d.to == "A") a.on_datagram(d.from, d.data, now);
            else if (d.to == "B") b.on_datagram(d.from, d.data, now);
        }

        while (auto e = a.poll_event()) {
            if (e->kind == PunchEvent::Kind::Nominated) { out.a_ok = true; out.a_path = e->path; }
        }
        while (auto e = b.poll_event()) {
            if (e->kind == PunchEvent::Kind::Nominated) { out.b_ok = true; out.b_path = e->path; }
        }

        if (out.a_ok && out.b_ok) { out.settled_at = now; return out; }

        // Advance to the next interesting instant rather than stepping blindly.
        std::optional<Instant> next;
        auto consider = [&](std::optional<Instant> t) {
            if (t && (!next || *t < *next)) next = t;
        };
        consider(a.next_timeout());
        consider(b.next_timeout());
        consider(net.next_delivery());
        if (!next || *next <= now) now += 1ms;
        else now = *next;

        a.on_timeout(now);
        b.on_timeout(now);
    }
    out.settled_at = now;
    return out;
}

// Simulate registration with the rendezvous server, and return the srflx the
// server observes.
//
// This step is not optional in a realistic simulation. The registration packet
// consumes a NAT mapping, and on a SYMMETRIC NAT the next packet -- the one
// aimed at a peer -- gets a DIFFERENT external port. That gap between "the port
// the server saw" and "the port the peer must hit" is precisely what defeats
// punching there, and a test that skips registration accidentally hands both
// sides the right port and shows a success that cannot happen in practice.
Endpoint register_with_server(Network& net, const std::string& host, Instant now) {
    static const Endpoint kServer = ep4(192, 0, 2, 10, 4433);
    net.send(host, kServer, std::vector<uint8_t>{0x01}, now);
    for (auto& d : net.advance(now + 100ms)) {
        if (d.to == "S") return d.from;
    }
    return Endpoint{};
}

}  // namespace

// ---------------------------------------------------------------------------
// Candidate ranking
// ---------------------------------------------------------------------------
TEST(ranking_prefers_host_over_srflx_over_relay) {
    std::vector<Candidate> cands = {
        Candidate{Candidate::Kind::Relay, ep4(198, 51, 100, 1, 3478)},
        srflx(ep4(203, 0, 113, 5, 40000)),
        host(ep4(192, 168, 1, 40, 51820)),
    };
    auto key = a_key();
    PunchSession s{PunchConfig{}, dev_of(1), cands, LocalView{}, &key, 1234};
    CHECK_EQ(s.pair_count(), 3u);
    // Order is not directly observable, but the first probe emitted goes to the
    // top-ranked candidate.
    s.begin(t0());
    auto first = s.poll_transmit();
    REQUIRE(first.has_value());
    CHECK(first->to == ep4(192, 168, 1, 40, 51820));
}

TEST(ranking_demotes_srflx_when_the_peer_shares_our_public_ip) {
    // Same public IP means same NAT, and there the srflx pair needs the router
    // to hairpin -- which many will not do. The host candidate is the only one
    // that can work.
    LocalView local;
    local.our_srflx = ep4(203, 0, 113, 7, 40001);

    std::vector<Candidate> cands = {
        srflx(ep4(203, 0, 113, 7, 40002)),   // same public IP as us
        host(ep4(192, 168, 1, 41, 51820)),
    };
    auto key = a_key();
    PunchSession s{PunchConfig{}, dev_of(1), cands, local, &key, 1234};
    s.begin(t0());
    auto first = s.poll_transmit();
    REQUIRE(first.has_value());
    CHECK(first->to == ep4(192, 168, 1, 41, 51820));
}

TEST(loopback_and_zero_port_candidates_are_discarded) {
    std::vector<Candidate> cands = {
        host(ep4(127, 0, 0, 1, 51820)),      // loopback, never routable
        host(ep4(192, 168, 1, 40, 0)),       // port 0
        srflx(ep4(203, 0, 113, 5, 40000)),   // the only usable one
    };
    auto key = a_key();
    PunchSession s{PunchConfig{}, dev_of(1), cands, LocalView{}, &key, 1234};
    CHECK_EQ(s.pair_count(), 1u);
}

TEST(a_session_with_no_usable_candidates_fails_immediately) {
    auto key = a_key();
    PunchSession s{PunchConfig{}, dev_of(1), {}, LocalView{}, &key, 1234};
    s.begin(t0());
    auto e = s.poll_event();
    REQUIRE(e.has_value());
    CHECK(e->kind == PunchEvent::Kind::Failed);
    CHECK(s.state() == PunchState::Failed);
}

// ---------------------------------------------------------------------------
// Probe tags
// ---------------------------------------------------------------------------
TEST(a_non_member_cannot_elicit_a_probe_response_on_a_keyed_topic) {
    // You should not confirm your own existence to a scanner.
    auto key   = a_key();
    auto wrong = crypto::SymKey{};
    wrong.fill(0x11);

    wire::ProbeTxn txn{};
    txn.fill(0x33);
    auto bad_tag = PunchSession::probe_tag(&wrong, txn, false);

    std::vector<uint8_t> buf(wire::kMaxDatagram);
    wire::Writer         w{buf};
    wire::Header{wire::MsgType::Probe, wire::kVersion, 0, 1}.encode(w);
    wire::Probe{txn, bad_tag}.encode(w);
    buf.resize(w.size());

    CHECK(!PunchSession::answer_probe(ep4(1, 2, 3, 4, 5000), buf, &key, 1).has_value());

    // The correct tag does get a response.
    auto good_tag = PunchSession::probe_tag(&key, txn, false);
    std::vector<uint8_t> buf2(wire::kMaxDatagram);
    wire::Writer         w2{buf2};
    wire::Header{wire::MsgType::Probe, wire::kVersion, 0, 1}.encode(w2);
    wire::Probe{txn, good_tag}.encode(w2);
    buf2.resize(w2.size());
    CHECK(PunchSession::answer_probe(ep4(1, 2, 3, 4, 5000), buf2, &key, 1).has_value());
}

TEST(open_topics_accept_any_probe) {
    wire::ProbeTxn txn{};
    txn.fill(0x44);
    std::vector<uint8_t> buf(wire::kMaxDatagram);
    wire::Writer         w{buf};
    wire::Header{wire::MsgType::Probe, wire::kVersion, 0, 1}.encode(w);
    wire::Probe{txn, wire::ProbeTag{}}.encode(w);
    buf.resize(w.size());

    // No key: anyone may participate, which is what "open" means.
    CHECK(PunchSession::answer_probe(ep4(1, 2, 3, 4, 5000), buf, nullptr, 1).has_value());
}

TEST(probe_tags_are_domain_separated_between_request_and_response) {
    // Otherwise a captured request could be replayed as a response.
    auto           key = a_key();
    wire::ProbeTxn txn{};
    txn.fill(0x55);
    CHECK(!(PunchSession::probe_tag(&key, txn, false) ==
            PunchSession::probe_tag(&key, txn, true)));
}

// ---------------------------------------------------------------------------
// Punching across NAT types
// ---------------------------------------------------------------------------
TEST(punch_succeeds_between_two_port_restricted_nats) {
    // The common residential case, and the one punching exists for.
    Network net{{20ms, 5ms, 0.0, 7}};
    Nat     nat_a{NatType::PortRestricted, IpAddr::v4(203, 0, 113, 1)};
    Nat     nat_b{NatType::PortRestricted, IpAddr::v4(198, 51, 100, 1)};

    net.add_host("A", ep4(192, 168, 1, 10, 51820), &nat_a);
    net.add_host("B", ep4(10, 0, 0, 5, 51820), &nat_b);

    // Each side learned the other's srflx from the rendezvous server. Those
    // ports are what the NATs allocated on the registration packet.
    auto key = a_key();
    PunchSession a{PunchConfig{}, dev_of(2), {srflx(ep4(198, 51, 100, 1, 40000))},
                   LocalView{ep4(203, 0, 113, 1, 40000)}, &key, 1234};
    PunchSession b{PunchConfig{}, dev_of(1), {srflx(ep4(203, 0, 113, 1, 40000))},
                   LocalView{ep4(198, 51, 100, 1, 40000)}, &key, 1234};

    auto r = run_punch(net, a, b, t0());
    CHECK(r.a_ok);
    CHECK(r.b_ok);
}

TEST(punch_succeeds_between_full_cone_nats) {
    Network net{{20ms, 5ms, 0.0, 3}};
    Nat     nat_a{NatType::FullCone, IpAddr::v4(203, 0, 113, 1)};
    Nat     nat_b{NatType::FullCone, IpAddr::v4(198, 51, 100, 1)};
    net.add_host("A", ep4(192, 168, 1, 10, 51820), &nat_a);
    net.add_host("B", ep4(10, 0, 0, 5, 51820), &nat_b);

    auto key = a_key();
    PunchSession a{PunchConfig{}, dev_of(2), {srflx(ep4(198, 51, 100, 1, 40000))},
                   LocalView{}, &key, 1234};
    PunchSession b{PunchConfig{}, dev_of(1), {srflx(ep4(203, 0, 113, 1, 40000))},
                   LocalView{}, &key, 1234};

    auto r = run_punch(net, a, b, t0());
    CHECK(r.a_ok);
    CHECK(r.b_ok);
}

TEST(punch_survives_heavy_packet_loss) {
    // The early packets are expected to be lost even on a clean link, because
    // neither NAT has a reason to let the other in yet. Retransmission with
    // backoff is what makes this work at all.
    Network net{{30ms, 10ms, 0.30, 11}};
    Nat     nat_a{NatType::PortRestricted, IpAddr::v4(203, 0, 113, 1)};
    Nat     nat_b{NatType::PortRestricted, IpAddr::v4(198, 51, 100, 1)};
    net.add_host("A", ep4(192, 168, 1, 10, 51820), &nat_a);
    net.add_host("B", ep4(10, 0, 0, 5, 51820), &nat_b);

    auto key = a_key();
    PunchSession a{PunchConfig{}, dev_of(2), {srflx(ep4(198, 51, 100, 1, 40000))},
                   LocalView{}, &key, 1234};
    PunchSession b{PunchConfig{}, dev_of(1), {srflx(ep4(203, 0, 113, 1, 40000))},
                   LocalView{}, &key, 1234};

    auto r = run_punch(net, a, b, t0());
    CHECK(r.a_ok);
    CHECK(r.b_ok);
    CHECK(net.dropped() > 0);  // the loss actually happened
}

TEST(symmetric_nat_on_both_ends_defeats_punching_as_expected) {
    // This is the case that makes a relay fallback necessary. A symmetric NAT
    // allocates a fresh external port per destination, so the port the
    // rendezvous server observed is NOT the port the peer must hit -- the
    // probes land on a mapping that does not exist.
    Network net{{20ms, 5ms, 0.0, 5}};
    Nat     nat_a{NatType::Symmetric, IpAddr::v4(203, 0, 113, 1)};
    Nat     nat_b{NatType::Symmetric, IpAddr::v4(198, 51, 100, 1)};
    net.add_host("S", ep4(192, 0, 2, 10, 4433), nullptr);  // rendezvous server
    net.add_host("A", ep4(192, 168, 1, 10, 51820), &nat_a);
    net.add_host("B", ep4(10, 0, 0, 5, 51820), &nat_b);

    // Register first, so the srflx each side advertises is the mapping the
    // server actually observed -- which under a symmetric NAT is NOT the
    // mapping a peer-directed packet will use.
    auto a_srflx = register_with_server(net, "A", t0());
    auto b_srflx = register_with_server(net, "B", t0());

    PunchConfig fast;
    fast.total_timeout         = 2s;
    fast.max_attempts_per_pair = 4;

    auto key = a_key();
    PunchSession a{fast, dev_of(2), {srflx(b_srflx)}, LocalView{a_srflx}, &key, 1234};
    PunchSession b{fast, dev_of(1), {srflx(a_srflx)}, LocalView{b_srflx}, &key, 1234};

    auto r = run_punch(net, a, b, t0() + 1s, 6s);
    CHECK(!r.a_ok);
    CHECK(!r.b_ok);
    CHECK(a.state() == PunchState::Failed);
    CHECK(b.state() == PunchState::Failed);
}

TEST(same_nat_peers_connect_via_host_candidates_when_hairpinning_is_unavailable) {
    // Two devices on the same LAN behind a router that will not hairpin. The
    // srflx pair cannot work; the host pair is the only thing that can. This is
    // exactly why host candidates are kept.
    Network net{{5ms, 1ms, 0.0, 13}};
    Nat     nat{NatType::PortRestricted, IpAddr::v4(203, 0, 113, 1), /*hairpin=*/false};
    net.add_host("A", ep4(192, 168, 1, 10, 51820), &nat);
    net.add_host("B", ep4(192, 168, 1, 11, 51820), &nat);

    auto key = a_key();
    // Each peer sees the other's srflx (same public IP -- the same-NAT signal)
    // plus the other's host candidate.
    LocalView la{ep4(203, 0, 113, 1, 40000)};
    LocalView lb{ep4(203, 0, 113, 1, 40001)};

    PunchSession a{PunchConfig{},
                   dev_of(2),
                   {srflx(ep4(203, 0, 113, 1, 40001)), host(ep4(192, 168, 1, 11, 51820))},
                   la,
                   &key, 1234};
    PunchSession b{PunchConfig{},
                   dev_of(1),
                   {srflx(ep4(203, 0, 113, 1, 40000)), host(ep4(192, 168, 1, 10, 51820))},
                   lb,
                   &key, 1234};

    auto r = run_punch(net, a, b, t0());
    REQUIRE(r.a_ok);
    REQUIRE(r.b_ok);
    // Both must have settled on the host path, not the hairpin one.
    CHECK(r.a_path->ip.is_private());
    CHECK(r.b_path->ip.is_private());
    // Note the srflx probe is never even sent here: the host pair is top-ranked
    // and validates within one 5ms RTT, well before the 20ms stagger would have
    // fired the srflx probe. Ranking does not just prefer the working path, it
    // avoids spending a packet on the broken one.
}

TEST(same_nat_peers_with_only_srflx_candidates_cannot_punch_without_hairpinning) {
    // The companion to the test above: strip the host candidates and the same
    // two peers can no longer reach each other at all, because the srflx pair
    // requires the router to loop a packet addressed to its own external IP
    // back inside. This is what makes host candidates load-bearing rather than
    // merely faster.
    Network net{{5ms, 1ms, 0.0, 13}};
    Nat     nat{NatType::PortRestricted, IpAddr::v4(203, 0, 113, 1), /*hairpin=*/false};
    net.add_host("S", ep4(192, 0, 2, 10, 4433), nullptr);
    net.add_host("A", ep4(192, 168, 1, 10, 51820), &nat);
    net.add_host("B", ep4(192, 168, 1, 11, 51820), &nat);

    auto a_srflx = register_with_server(net, "A", t0());
    auto b_srflx = register_with_server(net, "B", t0());
    CHECK(a_srflx.ip == b_srflx.ip);  // the same-NAT signal the ranker uses

    PunchConfig fast;
    fast.total_timeout         = 2s;
    fast.max_attempts_per_pair = 4;

    auto key = a_key();
    PunchSession a{fast, dev_of(2), {srflx(b_srflx)}, LocalView{a_srflx}, &key, 1234};
    PunchSession b{fast, dev_of(1), {srflx(a_srflx)}, LocalView{b_srflx}, &key, 1234};

    auto r = run_punch(net, a, b, t0() + 1s, 6s);
    CHECK(!r.a_ok);
    CHECK(!r.b_ok);
    CHECK(net.nat_blocked() > 0);  // the hairpin attempts really were dropped
}

TEST(a_peer_with_a_public_address_needs_no_nat_traversal) {
    Network net{{10ms, 2ms, 0.0, 17}};
    Nat     nat_a{NatType::PortRestricted, IpAddr::v4(203, 0, 113, 1)};
    net.add_host("A", ep4(192, 168, 1, 10, 51820), &nat_a);
    net.add_host("B", ep4(198, 51, 100, 9, 51820), nullptr);  // public, no NAT

    auto key = a_key();
    PunchSession a{PunchConfig{}, dev_of(2), {srflx(ep4(198, 51, 100, 9, 51820))},
                   LocalView{}, &key, 1234};
    PunchSession b{PunchConfig{}, dev_of(1), {srflx(ep4(203, 0, 113, 1, 40000))},
                   LocalView{}, &key, 1234};

    auto r = run_punch(net, a, b, t0());
    CHECK(r.a_ok);
    CHECK(r.b_ok);
}

// ---------------------------------------------------------------------------
// Nomination policy
// ---------------------------------------------------------------------------
TEST(the_top_ranked_pair_is_nominated_immediately_without_waiting_out_the_grace) {
    Network net{{5ms, 0ms, 0.0, 23}};
    net.add_host("A", ep4(198, 51, 100, 8, 51820), nullptr);
    net.add_host("B", ep4(198, 51, 100, 9, 51820), nullptr);

    auto key = a_key();
    PunchSession a{PunchConfig{}, dev_of(2), {host(ep4(198, 51, 100, 9, 51820))},
                   LocalView{}, &key, 1234};
    PunchSession b{PunchConfig{}, dev_of(1), {host(ep4(198, 51, 100, 8, 51820))},
                   LocalView{}, &key, 1234};

    auto r = run_punch(net, a, b, t0());
    REQUIRE(r.a_ok);
    // One RTT at 5ms each way plus scheduling, well under the 50ms grace: it
    // did not wait.
    CHECK(r.settled_at - t0() < 50ms);
}

TEST(nominated_path_and_txn_are_exposed_for_handshake_binding) {
    // The handshake prologue includes the nominated probe_txn, which is what
    // makes a replayed HandshakeInit useless: it arrives bound to a transaction
    // the responder never issued.
    Network net{{5ms, 0ms, 0.0, 29}};
    net.add_host("A", ep4(198, 51, 100, 8, 51820), nullptr);
    net.add_host("B", ep4(198, 51, 100, 9, 51820), nullptr);

    auto key = a_key();
    PunchSession a{PunchConfig{}, dev_of(2), {host(ep4(198, 51, 100, 9, 51820))},
                   LocalView{}, &key, 1234};
    PunchSession b{PunchConfig{}, dev_of(1), {host(ep4(198, 51, 100, 8, 51820))},
                   LocalView{}, &key, 1234};

    auto r = run_punch(net, a, b, t0());
    REQUIRE(r.a_ok);

    auto path = a.nominated_path();
    auto txn  = a.nominated_txn();
    REQUIRE(path.has_value());
    REQUIRE(txn.has_value());
    CHECK(*path == ep4(198, 51, 100, 9, 51820));

    // The transaction must be non-zero, i.e. actually CSPRNG-generated.
    bool all_zero = true;
    for (auto byte : *txn) {
        if (byte != 0) { all_zero = false; break; }
    }
    CHECK(!all_zero);
}

TEST(a_duplicate_probe_ok_does_not_re_nominate) {
    auto key = a_key();
    PunchSession a{PunchConfig{}, dev_of(2), {host(ep4(198, 51, 100, 9, 51820))},
                   LocalView{}, &key, 1234};
    a.begin(t0());
    auto probe = a.poll_transmit();
    REQUIRE(probe.has_value());

    // Decode the txn we just sent and forge two identical ProbeOks.
    wire::Reader r{probe->data};
    REQUIRE(wire::Header::decode(r).has_value());
    auto p = wire::Probe::decode(r);
    REQUIRE(p.has_value());

    auto build_ok = [&] {
        std::vector<uint8_t> buf(wire::kMaxDatagram);
        wire::Writer         w{buf};
        wire::Header{wire::MsgType::ProbeOk, wire::kVersion, 0, 1}.encode(w);
        wire::ProbeOk{p->txn, ep4(203, 0, 113, 1, 40000),
                      PunchSession::probe_tag(&key, p->txn, true)}
            .encode(w);
        buf.resize(w.size());
        return buf;
    };

    a.on_datagram(ep4(198, 51, 100, 9, 51820), build_ok(), t0() + 10ms);
    a.on_datagram(ep4(198, 51, 100, 9, 51820), build_ok(), t0() + 11ms);

    int nominations = 0;
    while (auto e = a.poll_event()) {
        if (e->kind == PunchEvent::Kind::Nominated) ++nominations;
    }
    CHECK_EQ(nominations, 1);
}

TEST(a_forged_probe_ok_is_ignored_on_a_keyed_topic) {
    auto key = a_key();
    PunchSession a{PunchConfig{}, dev_of(2), {host(ep4(198, 51, 100, 9, 51820))},
                   LocalView{}, &key, 1234};
    a.begin(t0());
    auto probe = a.poll_transmit();
    REQUIRE(probe.has_value());

    wire::Reader r{probe->data};
    REQUIRE(wire::Header::decode(r).has_value());
    auto p = wire::Probe::decode(r);
    REQUIRE(p.has_value());

    // Right transaction id, wrong tag -- an off-path attacker who saw the probe
    // but does not hold K.
    std::vector<uint8_t> buf(wire::kMaxDatagram);
    wire::Writer         w{buf};
    wire::Header{wire::MsgType::ProbeOk, wire::kVersion, 0, 1}.encode(w);
    wire::ProbeTag bad{};
    bad.fill(0xEE);
    wire::ProbeOk{p->txn, ep4(203, 0, 113, 1, 40000), bad}.encode(w);
    buf.resize(w.size());

    a.on_datagram(ep4(198, 51, 100, 9, 51820), buf, t0() + 10ms);
    while (auto e = a.poll_event()) {
        CHECK(e->kind != PunchEvent::Kind::Nominated);
    }
    CHECK(a.state() != PunchState::Nominated);
}

TEST(an_unmatched_transaction_id_is_ignored) {
    auto key = a_key();
    PunchSession a{PunchConfig{}, dev_of(2), {host(ep4(198, 51, 100, 9, 51820))},
                   LocalView{}, &key, 1234};
    a.begin(t0());
    (void)a.poll_transmit();

    wire::ProbeTxn other{};
    other.fill(0x99);
    std::vector<uint8_t> buf(wire::kMaxDatagram);
    wire::Writer         w{buf};
    wire::Header{wire::MsgType::ProbeOk, wire::kVersion, 0, 1}.encode(w);
    wire::ProbeOk{other, ep4(203, 0, 113, 1, 40000),
                  PunchSession::probe_tag(&key, other, true)}
        .encode(w);
    buf.resize(w.size());

    a.on_datagram(ep4(198, 51, 100, 9, 51820), buf, t0() + 10ms);
    CHECK(a.state() != PunchState::Nominated);
}

// ---------------------------------------------------------------------------
// Retransmission behaviour
// ---------------------------------------------------------------------------
TEST(probes_are_staggered_rather_than_sent_as_one_burst) {
    std::vector<Candidate> cands;
    for (uint8_t i = 0; i < 5; ++i) {
        cands.push_back(srflx(ep4(198, 51, 100, i, static_cast<uint16_t>(40000 + i))));
    }
    auto         key = a_key();
    PunchConfig  cfg;
    cfg.stagger = 20ms;
    PunchSession s{cfg, dev_of(1), cands, LocalView{}, &key, 1234};

    s.begin(t0());
    int at_start = 0;
    while (s.poll_transmit()) ++at_start;
    // Only the first candidate is due immediately; the rest are scheduled.
    CHECK_EQ(at_start, 1);

    s.on_timeout(t0() + 20ms);
    int after = 0;
    while (s.poll_transmit()) ++after;
    CHECK(after >= 1);
}

TEST(retransmit_backoff_grows_and_the_attempt_eventually_gives_up) {
    auto        key = a_key();
    PunchConfig cfg;
    cfg.total_timeout         = 3s;
    cfg.max_attempts_per_pair = 4;
    PunchSession s{cfg, dev_of(1), {srflx(ep4(198, 51, 100, 9, 40000))}, LocalView{}, &key, 1234};

    s.begin(t0());
    int     sends = 0;
    Instant now   = t0();
    while (now < t0() + 5s) {
        while (s.poll_transmit()) ++sends;
        auto nt = s.next_timeout();
        if (!nt) break;
        now = *nt > now ? *nt : now + 1ms;
        s.on_timeout(now);
    }
    while (s.poll_transmit()) ++sends;

    CHECK(sends <= cfg.max_attempts_per_pair);
    CHECK(s.state() == PunchState::Failed);

    bool saw_failure = false;
    while (auto e = s.poll_event()) {
        if (e->kind == PunchEvent::Kind::Failed) saw_failure = true;
    }
    CHECK(saw_failure);
}

TEST(an_incoming_probe_accelerates_our_next_probe_to_that_address) {
    // Their probe arriving proves they are live and that the path works in at
    // least one direction. Waiting out a full backoff at that point wastes the
    // window where both NATs are open.
    auto         key = a_key();
    PunchConfig  cfg;
    cfg.first_retransmit = 800ms;
    PunchSession s{cfg, dev_of(1), {srflx(ep4(198, 51, 100, 9, 40000))}, LocalView{}, &key, 1234};

    s.begin(t0());
    while (s.poll_transmit()) {}

    // Nothing due yet -- the backoff is 800ms.
    s.on_timeout(t0() + 50ms);
    CHECK(!s.poll_transmit().has_value());

    // Their probe arrives.
    wire::ProbeTxn txn{};
    txn.fill(0x77);
    std::vector<uint8_t> buf(wire::kMaxDatagram);
    wire::Writer         w{buf};
    wire::Header{wire::MsgType::Probe, wire::kVersion, 0, 1}.encode(w);
    wire::Probe{txn, PunchSession::probe_tag(&key, txn, false)}.encode(w);
    buf.resize(w.size());
    s.on_datagram(ep4(198, 51, 100, 9, 40000), buf, t0() + 60ms);

    // We answer it (opening our NAT toward them)...
    auto reply = s.poll_transmit();
    REQUIRE(reply.has_value());
    CHECK(reply->to == ep4(198, 51, 100, 9, 40000));

    // ...and our own next probe is brought forward instead of waiting 800ms.
    s.on_timeout(t0() + 61ms);
    CHECK(s.poll_transmit().has_value());
}
