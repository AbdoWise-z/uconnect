// Stream layer tests.
//
// The point of this layer is to turn "datagrams, some of which vanish and
// arrive in the wrong order" into "a byte stream". So almost every test here
// runs the two endpoints against a link that loses and reorders on purpose,
// and then asserts the bytes came out intact and in order anyway.
//
// All of it is deterministic: the link's RNG is seeded, and the clock is a
// parameter. A 10-second transfer with 20% loss runs in milliseconds and gives
// the same answer every time.

#include <algorithm>
#include <numeric>
#include <random>
#include <utility>

#include "buffers.hpp"
#include "connection.hpp"
#include "frame.hpp"
#include "recovery.hpp"
#include "testing.hpp"

using namespace uconnect;
using namespace uconnect::stream;
using namespace std::chrono_literals;

namespace {

Instant t0() { return Instant{} + 1000000s; }

std::vector<uint8_t> pattern(size_t n, uint8_t seed = 0) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>((i * 31 + seed) & 0xFF);
    return v;
}

// A link between two StreamConnections that loses, reorders and delays.
// This is the whole test harness: no sockets, no threads, no real time.
class Link {
public:
    struct Config {
        double   loss     = 0.0;
        Duration latency  = 10ms;
        Duration jitter   = 0ms;   // nonzero produces genuine reordering
        uint64_t seed     = 42;
    };

    Link(StreamConnection& a, StreamConnection& b, Config cfg)
        : a_(a), b_(b), cfg_(cfg), rng_(cfg.seed), now_(t0()) {}

    // Advance the simulated clock by `d`, moving datagrams in both directions.
    //
    // The clock is owned by the link and only ever moves forward. An earlier
    // version took (start, until) and every caller passed t0() as the start --
    // so time reset on each call, retransmission timers never fired, and a
    // lossy transfer silently stalled partway through.
    void advance(Duration d, Duration step = 1ms) {
        const Instant until = now_ + d;
        for (; now_ <= until; now_ += step) {
            pump(a_, b_, a_pn_, now_, /*to_b=*/true);
            pump(b_, a_, b_pn_, now_, /*to_b=*/false);
            deliver(now_);
            a_.on_timeout(now_);
            b_.on_timeout(now_);
        }
    }

    Instant now() const { return now_; }

    // Discard everything currently on the wire.
    //
    // Models a session being replaced: those datagrams were sealed under keys
    // the receiver has just destroyed, so they arrive as undecryptable noise
    // and are dropped. Without this a restart test passes for the wrong reason
    // -- the simulator happily delivers old-session packets, so the data
    // arrives whether or not the restart re-queued it.
    size_t drop_in_flight() {
        const size_t n = queue_.size();
        dropped_ += n;
        queue_.clear();
        return n;
    }

    size_t sent() const { return sent_; }
    size_t dropped() const { return dropped_; }

private:
    struct InFlight {
        std::vector<uint8_t> data;
        uint64_t             pn;
        Instant              at;
        bool                 to_b;
    };

    void pump(StreamConnection& from, StreamConnection& to, uint64_t& pn, Instant now,
              bool to_b) {
        (void)to;
        for (int i = 0; i < 8; ++i) {  // several datagrams per tick when the window allows
            std::vector<uint8_t> buf(1200);
            size_t n = from.poll_datagram(pn, buf, now);
            if (n == 0) break;
            buf.resize(n);
            ++sent_;

            const uint64_t this_pn = pn++;

            std::uniform_real_distribution<double> d(0.0, 1.0);
            if (d(rng_) < cfg_.loss) {
                ++dropped_;
                continue;  // the datagram simply never arrives
            }

            Duration delay = cfg_.latency;
            if (cfg_.jitter.count() > 0) {
                std::uniform_int_distribution<int64_t> j(-cfg_.jitter.count(),
                                                          cfg_.jitter.count());
                auto ms = cfg_.latency.count() + j(rng_);
                delay   = Duration{ms < 0 ? 0 : ms};
            }
            queue_.push_back(InFlight{std::move(buf), this_pn, now + delay, to_b});
        }
    }

    void deliver(Instant now) {
        for (auto it = queue_.begin(); it != queue_.end();) {
            if (it->at <= now) {
                auto& dst = it->to_b ? b_ : a_;
                dst.on_datagram(it->pn, it->data, now);
                it = queue_.erase(it);
            } else {
                ++it;
            }
        }
    }

    StreamConnection&     a_;
    StreamConnection&     b_;
    Config                cfg_;
    std::mt19937_64       rng_;
    std::vector<InFlight> queue_;
    uint64_t              a_pn_   = 1;
    uint64_t              b_pn_   = 1;
    Instant               now_;
    size_t                sent_   = 0;
    size_t                dropped_ = 0;
};

// Drain everything readable on a stream into a vector.
void drain(StreamConnection& c, StreamId id, std::vector<uint8_t>& out) {
    std::vector<uint8_t> tmp(4096);
    for (;;) {
        size_t n = c.read(id, tmp);
        if (n == 0) break;
        out.insert(out.end(), tmp.begin(), tmp.begin() + static_cast<ptrdiff_t>(n));
    }
}

StreamConfig fast_cfg() {
    StreamConfig c;
    c.idle_timeout = 60s;
    return c;
}

}  // namespace

// ---------------------------------------------------------------------------
// Varints -- the foundation the frame format sits on
// ---------------------------------------------------------------------------
TEST(varint_roundtrips_across_every_width) {
    const uint64_t values[] = {0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824,
                               4611686018427387903ull};
    for (uint64_t v : values) {
        std::vector<uint8_t> buf(16);
        wire::Writer         w{buf};
        w.varint(v);
        REQUIRE(w.ok());
        CHECK_EQ(w.size(), wire::Writer::varint_size(v));

        wire::Reader r{std::span<const uint8_t>(buf.data(), w.size())};
        CHECK(r.varint() == v);
        CHECK(r.ok());
    }
}

TEST(varint_uses_the_smallest_encoding) {
    // A stream offset early in a transfer must cost one byte, not eight --
    // frame headers are mostly offsets, so this is a real bandwidth concern.
    CHECK_EQ(wire::Writer::varint_size(0), 1u);
    CHECK_EQ(wire::Writer::varint_size(63), 1u);
    CHECK_EQ(wire::Writer::varint_size(64), 2u);
    CHECK_EQ(wire::Writer::varint_size(16384), 4u);
    CHECK_EQ(wire::Writer::varint_size(1ull << 40), 8u);
}

TEST(varint_refuses_values_it_cannot_represent) {
    std::vector<uint8_t> buf(16);
    wire::Writer         w{buf};
    w.varint(1ull << 63);  // beyond the 62-bit ceiling
    CHECK(!w.ok());        // refuses rather than silently truncating
}

// ---------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------
TEST(stream_frame_roundtrips) {
    auto payload = pattern(300);
    std::vector<uint8_t> buf(1200);
    wire::Writer         w{buf};
    size_t wrote = encode_stream(w, 4, 1000, true, payload);
    REQUIRE(wrote == payload.size());

    std::vector<Frame> frames;
    REQUIRE(decode_frames(std::span<const uint8_t>(buf.data(), w.size()), frames));
    REQUIRE(frames.size() == 1);
    CHECK(frames[0].type == FrameType::StreamBase);
    CHECK(frames[0].stream.id == 4u);
    CHECK(frames[0].stream.offset == 1000u);
    CHECK(frames[0].stream.fin);
    CHECK_EQ(frames[0].stream.data.size(), payload.size());
    CHECK(std::equal(payload.begin(), payload.end(), frames[0].stream.data.begin()));
}

TEST(a_stream_frame_that_does_not_fit_is_truncated_not_corrupted) {
    // Short writes are how a large payload gets split across datagrams, so
    // this is the normal path, not an error path.
    auto payload = pattern(1000);
    std::vector<uint8_t> buf(100);
    wire::Writer         w{buf};
    size_t wrote = encode_stream(w, 1, 0, true, payload);
    CHECK(wrote > 0);
    CHECK(wrote < payload.size());

    std::vector<Frame> frames;
    REQUIRE(decode_frames(std::span<const uint8_t>(buf.data(), w.size()), frames));
    REQUIRE(frames.size() == 1);
    // FIN must NOT be set on a truncated frame: this is not the end of the
    // stream, and claiming it was would lose the tail.
    CHECK(!frames[0].stream.fin);
    CHECK_EQ(frames[0].stream.data.size(), wrote);
}

TEST(ack_frame_roundtrips_with_gaps) {
    AckFrame a;
    a.largest     = 100;
    a.first_range = 2;                 // 98,99,100
    a.delay_us    = 1234;
    a.ranges.push_back(AckRange{0, 1}); // gap 0 -> 96,95... see below
    a.ranges.push_back(AckRange{3, 0});

    std::vector<uint8_t> buf(200);
    wire::Writer         w{buf};
    REQUIRE(encode_ack(w, a));

    std::vector<Frame> frames;
    REQUIRE(decode_frames(std::span<const uint8_t>(buf.data(), w.size()), frames));
    REQUIRE(frames.size() == 1);
    CHECK(frames[0].type == FrameType::Ack);
    CHECK(frames[0].ack.largest == 100u);
    CHECK(frames[0].ack.first_range == 2u);
    REQUIRE(frames[0].ack.ranges.size() == 2);
}

TEST(ack_for_each_enumerates_exactly_the_acked_packets) {
    AckFrame a;
    a.largest     = 10;
    a.first_range = 2;                  // 8,9,10
    a.ranges.push_back(AckRange{0, 1}); // gap 0 => skip 7, range 5..6

    std::vector<uint64_t> got;
    a.for_each([&](uint64_t pn) { got.push_back(pn); });

    std::vector<uint64_t> want{10, 9, 8, 6, 5};
    CHECK(got == want);
}

TEST(ack_decoding_survives_hostile_range_values) {
    // These values come off the wire from a peer that is authenticated but not
    // trusted to be sane. Underflow here would be a crash or worse.
    AckFrame a;
    a.largest     = 5;
    a.first_range = 100;  // claims to ack below zero
    std::vector<uint64_t> got;
    a.for_each([&](uint64_t pn) { got.push_back(pn); });
    CHECK(got.empty());

    AckFrame b;
    b.largest     = 10;
    b.first_range = 0;
    b.ranges.push_back(AckRange{1000, 1000});  // gap past the origin
    std::vector<uint64_t> got2;
    b.for_each([&](uint64_t pn) { got2.push_back(pn); });
    CHECK_EQ(got2.size(), 1u);  // only the first range
}

TEST(decoder_rejects_an_unknown_frame_type) {
    // Frames are not length-prefixed, so an unknown type cannot be skipped.
    // Guessing at the remainder is how parsers get exploited.
    std::array<uint8_t, 4> junk{0x7F, 0x00, 0x00, 0x00};
    std::vector<Frame>     frames;
    CHECK(!decode_frames(junk, frames));
}

TEST(decoder_rejects_a_truncated_frame) {
    auto payload = pattern(200);
    std::vector<uint8_t> buf(1200);
    wire::Writer         w{buf};
    encode_stream(w, 1, 0, false, payload);

    for (size_t len = 1; len < w.size(); ++len) {
        std::vector<Frame> frames;
        // Must never claim success on a partial frame.
        if (decode_frames(std::span<const uint8_t>(buf.data(), len), frames)) {
            // Truncating exactly at a frame boundary is legitimate only if no
            // partial frame remains; with one frame that means len == size.
            if (len != w.size()) {
                ::testing::fail(__FILE__, __LINE__,
                                "accepted truncation at " + std::to_string(len));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RecvBuffer -- ordering
// ---------------------------------------------------------------------------
TEST(recv_buffer_reassembles_out_of_order_chunks) {
    RecvBuffer rb{64 * 1024};
    auto data = pattern(300);

    // Deliver in reverse order, which is what the network will do to us.
    REQUIRE(rb.insert(200, std::span(data).subspan(200, 100), true));
    CHECK_EQ(rb.readable(), 0u);  // nothing contiguous yet
    REQUIRE(rb.insert(100, std::span(data).subspan(100, 100), false));
    CHECK_EQ(rb.readable(), 0u);
    REQUIRE(rb.insert(0, std::span(data).subspan(0, 100), false));
    CHECK_EQ(rb.readable(), 300u);  // the gap closed; all of it is now ordered

    std::vector<uint8_t> out(300);
    CHECK_EQ(rb.read(out), 300u);
    CHECK(out == data);
    CHECK(rb.finished());
}

TEST(recv_buffer_ignores_duplicate_and_overlapping_retransmissions) {
    RecvBuffer rb{64 * 1024};
    auto data = pattern(200);

    REQUIRE(rb.insert(0, std::span(data).subspan(0, 100), false));
    REQUIRE(rb.insert(0, std::span(data).subspan(0, 100), false));   // exact duplicate
    REQUIRE(rb.insert(50, std::span(data).subspan(50, 100), false)); // overlaps
    CHECK_EQ(rb.readable(), 150u);

    std::vector<uint8_t> out(150);
    rb.read(out);
    CHECK(std::equal(out.begin(), out.end(), data.begin()));
}

TEST(recv_buffer_enforces_its_advertised_window) {
    // A peer that ignores flow control must be refused, or it chooses how much
    // memory we allocate.
    RecvBuffer rb{1000};
    auto data = pattern(2000);
    CHECK(rb.insert(0, std::span(data).subspan(0, 500), false));
    CHECK(!rb.insert(1500, std::span(data).subspan(0, 600), false));
}

TEST(recv_buffer_window_slides_as_the_application_consumes) {
    RecvBuffer rb{1000};
    CHECK_EQ(rb.max_offset(), 1000u);

    auto data = pattern(600);
    REQUIRE(rb.insert(0, data, false));
    std::vector<uint8_t> out(600);
    rb.read(out);

    // Having consumed 600, the peer may now send 600 further bytes.
    CHECK_EQ(rb.max_offset(), 1600u);
    CHECK(rb.should_update_window());
}

TEST(recv_buffer_rejects_a_moved_fin) {
    RecvBuffer rb{64 * 1024};
    auto data = pattern(100);
    REQUIRE(rb.insert(0, data, true));           // fin at 100
    CHECK(!rb.insert(100, data, true));          // fin claimed at 200 -- contradiction
}

// ---------------------------------------------------------------------------
// SendBuffer -- reliability
// ---------------------------------------------------------------------------
TEST(send_buffer_prioritises_retransmission_over_new_data) {
    // A lost byte blocks the receiver's entire stream, so it is always more
    // urgent than a byte the receiver has never seen.
    SendBuffer sb{1 << 20};
    auto data = pattern(1000);
    sb.write(data, 1 << 20);

    auto c1 = sb.next_chunk(100);
    REQUIRE(c1.has_value());
    sb.on_sent(c1->offset, c1->data.size());
    auto c2 = sb.next_chunk(100);
    REQUIRE(c2.has_value());
    sb.on_sent(c2->offset, c2->data.size());

    sb.on_lost(c1->offset, c1->data.size());

    auto next = sb.next_chunk(100);
    REQUIRE(next.has_value());
    CHECK(next->retransmit);
    CHECK(next->offset == c1->offset);  // the hole, not the frontier
}

TEST(send_buffer_respects_the_peer_window) {
    SendBuffer sb{100};  // peer will accept only 100 bytes
    auto data = pattern(1000);
    sb.write(data, 1 << 20);

    auto c = sb.next_chunk(500);
    REQUIRE(c.has_value());
    CHECK_EQ(c->data.size(), 100u);
    sb.on_sent(c->offset, c->data.size());

    CHECK(!sb.next_chunk(500).has_value());  // blocked
    CHECK(sb.blocked());

    sb.set_peer_max(300);
    auto c2 = sb.next_chunk(500);
    REQUIRE(c2.has_value());
    CHECK_EQ(c2->data.size(), 200u);
}

TEST(send_buffer_releases_acknowledged_bytes) {
    // Without this the buffer grows for the life of the stream, which turns a
    // long-lived transfer into a memory leak.
    SendBuffer sb{1 << 20};
    auto data = pattern(10000);
    sb.write(data, 1 << 20);

    size_t before = sb.buffered();
    auto   c      = sb.next_chunk(5000);
    REQUIRE(c.has_value());
    sb.on_sent(c->offset, c->data.size());
    sb.on_acked(c->offset, c->data.size());

    CHECK(sb.buffered() < before);
    CHECK(sb.acked_prefix() == 5000u);
}

TEST(send_buffer_reports_completion_only_after_fin_is_acked) {
    SendBuffer sb{1 << 20};
    auto data = pattern(100);
    sb.write(data, 1 << 20);
    sb.finish();
    CHECK(!sb.complete());

    auto c = sb.next_chunk(1000);
    REQUIRE(c.has_value());
    CHECK(c->fin);
    sb.on_sent(c->offset, c->data.size());
    CHECK(!sb.complete());  // sent is not delivered

    sb.on_acked(c->offset, c->data.size(), c->fin);
    CHECK(sb.complete());
}

// ---------------------------------------------------------------------------
// RTT and congestion control
// ---------------------------------------------------------------------------
TEST(rtt_estimator_converges_and_tracks_variance) {
    RttEstimator r;
    CHECK(!r.has_sample());

    r.sample(100ms, 0ms);
    CHECK(r.has_sample());
    CHECK(r.smoothed() == 100ms);
    CHECK(r.minimum() == 100ms);

    for (int i = 0; i < 20; ++i) r.sample(50ms, 0ms);
    // Smoothed value should have moved most of the way to the new reality.
    CHECK(r.smoothed() < 60ms);
    CHECK(r.minimum() == 50ms);
}

TEST(rtt_estimator_ignores_an_overstated_ack_delay) {
    // A peer that claims a huge ack delay would otherwise drive our estimate
    // toward zero and make every packet look lost.
    RttEstimator r;
    r.sample(100ms, 0ms);
    for (int i = 0; i < 10; ++i) r.sample(100ms, 500ms);
    CHECK(r.smoothed() >= r.minimum());
    CHECK(r.smoothed() > 0ms);
}

TEST(pto_backs_off_exponentially_but_is_capped) {
    RttEstimator r;
    r.sample(50ms, 0ms);
    auto p0 = r.pto(0);
    auto p1 = r.pto(1);
    auto p3 = r.pto(3);
    CHECK(p1 > p0);
    CHECK(p3 > p1);
    // A long outage must not schedule the next probe years away.
    CHECK(r.pto(50) == r.pto(10));
}

TEST(congestion_window_grows_in_slow_start_then_halves_on_loss) {
    Congestion cc{1200};
    const size_t initial = cc.window();
    CHECK(cc.in_slow_start());

    cc.on_sent(1200);
    cc.on_acked(1200, t0(), t0() + 10ms);
    CHECK(cc.window() == initial + 1200);  // slow start: one-for-one

    const size_t before = cc.window();
    cc.on_sent(1200);
    cc.on_lost(1200, t0() + 20ms, t0() + 30ms);
    CHECK(cc.window() <= before / 2 + 1200);
    CHECK(!cc.in_slow_start());
}

TEST(one_congestion_event_per_round_trip) {
    // A burst of losses within a single flight must halve the window once, not
    // once per lost packet -- otherwise a normal loss episode collapses it.
    Congestion cc{1200};
    for (int i = 0; i < 10; ++i) cc.on_sent(1200);

    const size_t before = cc.window();
    Instant      sent   = t0();
    for (int i = 0; i < 5; ++i) cc.on_lost(1200, sent, t0() + 10ms);

    CHECK(cc.window() >= before / 2);
    CHECK(cc.window() >= 2 * 1200u);  // never below the floor
}

TEST(congestion_window_blocks_sending_when_full) {
    Congestion cc{1200};
    CHECK(cc.can_send(1200));
    while (cc.can_send(1200)) cc.on_sent(1200);
    CHECK(!cc.can_send(1200));
    CHECK_EQ(cc.available(), 0u);
}

// ---------------------------------------------------------------------------
// Loss detection
// ---------------------------------------------------------------------------
TEST(a_packet_is_declared_lost_after_three_later_packets_are_acked) {
    SentPackets sp;
    RttEstimator rtt;
    rtt.sample(20ms, 0ms);

    for (uint64_t n = 1; n <= 5; ++n) {
        SentPacket p;
        p.number        = n;
        p.sent_at       = t0();
        p.size          = 1200;
        p.ack_eliciting = true;
        sp.on_sent(p);
    }

    // Ack 2..5, leaving 1 with four later acks.
    auto out = sp.on_ack(5, 0ms, {5, 4, 3, 2}, rtt, t0() + 25ms);
    CHECK_EQ(out.newly_acked.size(), 4u);
    REQUIRE(out.lost.size() == 1);
    CHECK(out.lost[0].number == 1u);
}

TEST(mild_reordering_is_not_mistaken_for_loss) {
    SentPackets sp;
    RttEstimator rtt;
    rtt.sample(100ms, 0ms);

    for (uint64_t n = 1; n <= 3; ++n) {
        SentPacket p;
        p.number        = n;
        p.sent_at       = t0();
        p.size          = 1200;
        p.ack_eliciting = true;
        sp.on_sent(p);
    }

    // Only packet 2 acked: one later packet is not enough evidence, and the
    // time threshold has not passed either.
    auto out = sp.on_ack(2, 0ms, {2}, rtt, t0() + 5ms);
    CHECK(out.lost.empty());
}

TEST(rtt_is_sampled_only_from_the_largest_acked_packet) {
    // Sampling an older packet in the same ack would measure how long it sat
    // waiting for the ack to be sent, not the path.
    SentPackets sp;
    RttEstimator rtt;

    SentPacket p1;
    p1.number = 1; p1.sent_at = t0(); p1.size = 1200; p1.ack_eliciting = true;
    sp.on_sent(p1);
    SentPacket p2;
    p2.number = 2; p2.sent_at = t0() + 50ms; p2.size = 1200; p2.ack_eliciting = true;
    sp.on_sent(p2);

    auto out = sp.on_ack(2, 0ms, {2, 1}, rtt, t0() + 70ms);
    REQUIRE(out.has_rtt_sample);
    CHECK(out.rtt_sample == 20ms);  // from packet 2, not 70ms from packet 1
}

TEST(ack_tracker_builds_ranges_with_gaps) {
    AckTracker t;
    t.on_received(1, true, t0());
    t.on_received(2, true, t0());
    t.on_received(5, true, t0());  // 3 and 4 missing

    auto b = t.build(t0());
    REQUIRE(b.has_value());
    CHECK(b->largest == 5u);
    CHECK(b->first_range == 0u);   // just packet 5
    REQUIRE(b->extra.size() == 1);
    CHECK(b->extra[0].second == 1u);  // the 1..2 run
}

TEST(ack_tracker_history_is_bounded) {
    // An unbounded range list is a memory leak the peer gets to drive.
    AckTracker t;
    for (uint64_t n = 0; n < 500; n += 2) t.on_received(n, true, t0());
    auto b = t.build(t0());
    REQUIRE(b.has_value());
    CHECK(b->extra.size() <= 32u);
}

// ---------------------------------------------------------------------------
// End to end over a lossy link -- the real test
// ---------------------------------------------------------------------------
TEST(a_stream_delivers_bytes_intact_over_a_clean_link) {
    StreamConnection a{fast_cfg(), Role::A};
    StreamConnection b{fast_cfg(), Role::B};
    Link link{a, b, Link::Config{0.0, 5ms, 0ms, 1}};

    auto     data = pattern(50000);
    StreamId id   = *a.open();
    size_t   off  = 0;
    while (off < data.size()) {
        off += a.write(id, std::span(data).subspan(off));
        link.advance(50ms);
    }
    a.finish(id);
    link.advance(3s);

    std::vector<uint8_t> got;
    drain(b, id, got);
    CHECK_EQ(got.size(), data.size());
    CHECK(got == data);
    CHECK(b.finished(id));
}

TEST(a_stream_delivers_bytes_intact_despite_heavy_loss) {
    // 20% loss both directions. Every byte must still arrive, in order.
    StreamConnection a{fast_cfg(), Role::A};
    StreamConnection b{fast_cfg(), Role::B};
    Link link{a, b, Link::Config{0.20, 10ms, 0ms, 7}};

    auto     data = pattern(20000, 3);
    StreamId id   = *a.open();
    size_t   off  = 0;
    for (int round = 0; round < 40 && off < data.size(); ++round) {
        off += a.write(id, std::span(data).subspan(off));
        link.advance(200ms);
    }
    a.finish(id);
    link.advance(20s);

    std::vector<uint8_t> got;
    drain(b, id, got);
    CHECK_EQ(got.size(), data.size());
    CHECK(got == data);
    CHECK(link.dropped() > 0);  // the loss really happened
}

TEST(a_stream_delivers_bytes_in_order_despite_reordering) {
    // Jitter larger than the base latency guarantees genuine reordering.
    StreamConnection a{fast_cfg(), Role::A};
    StreamConnection b{fast_cfg(), Role::B};
    Link link{a, b, Link::Config{0.05, 20ms, 18ms, 11}};

    auto     data = pattern(20000, 9);
    StreamId id   = *a.open();
    size_t   off  = 0;
    for (int round = 0; round < 40 && off < data.size(); ++round) {
        off += a.write(id, std::span(data).subspan(off));
        link.advance(200ms);
    }
    a.finish(id);
    link.advance(20s);

    std::vector<uint8_t> got;
    drain(b, id, got);
    CHECK_EQ(got.size(), data.size());
    CHECK(got == data);  // byte-for-byte, in order
}

TEST(two_streams_are_independent_so_one_stall_does_not_block_the_other) {
    // The reason to multiplex on datagrams rather than run one ordered pipe:
    // head-of-line blocking is confined to a single stream.
    StreamConnection a{fast_cfg(), Role::A};
    StreamConnection b{fast_cfg(), Role::B};
    Link link{a, b, Link::Config{0.10, 10ms, 0ms, 13}};

    StreamId s1 = *a.open();
    StreamId s2 = *a.open();
    CHECK(s1 != s2);

    auto d1 = pattern(8000, 1);
    auto d2 = pattern(8000, 2);
    size_t o1 = 0, o2 = 0;
    for (int round = 0; round < 40 && (o1 < d1.size() || o2 < d2.size()); ++round) {
        if (o1 < d1.size()) o1 += a.write(s1, std::span(d1).subspan(o1));
        if (o2 < d2.size()) o2 += a.write(s2, std::span(d2).subspan(o2));
        link.advance(200ms);
    }
    a.finish(s1);
    a.finish(s2);
    link.advance(20s);

    std::vector<uint8_t> g1, g2;
    drain(b, s1, g1);
    drain(b, s2, g2);
    CHECK(g1 == d1);
    CHECK(g2 == d2);
}

TEST(streams_opened_concurrently_by_both_peers_never_collide) {
    // There is no central id allocator in a peer-to-peer session, so the id
    // itself has to encode who opened it.
    StreamConnection a{fast_cfg(), Role::A};
    StreamConnection b{fast_cfg(), Role::B};

    for (int i = 0; i < 10; ++i) {
        StreamId ida = *a.open();
        StreamId idb = *b.open();
        CHECK(ida != idb);
        CHECK(opener(ida) == Role::A);
        CHECK(opener(idb) == Role::B);
    }
}

TEST(the_receiver_learns_about_a_stream_it_did_not_open) {
    StreamConnection a{fast_cfg(), Role::A};
    StreamConnection b{fast_cfg(), Role::B};
    Link link{a, b, Link::Config{0.0, 5ms, 0ms, 17}};

    StreamId id = *a.open();
    auto     d  = pattern(100);
    a.write(id, d);
    link.advance(200ms);

    bool opened = false;
    while (auto e = b.poll_event()) {
        if (e->kind == StreamEventKind::Opened && e->id == id) opened = true;
    }
    CHECK(opened);
    CHECK(b.exists(id));
}

TEST(congestion_control_actually_limits_bytes_in_flight) {
    // Without this a sender fills every buffer on the path. Assert the window
    // is genuinely respected rather than merely present.
    StreamConnection a{fast_cfg(), Role::A};
    StreamConnection b{fast_cfg(), Role::B};

    StreamId id   = *a.open();
    auto     data = pattern(200000);
    a.write(id, data);

    // Emit without ever delivering an ack: the window must close.
    uint64_t pn = 1;
    size_t   packets = 0;
    std::vector<uint8_t> buf(1200);
    for (int i = 0; i < 1000; ++i) {
        size_t n = a.poll_datagram(pn, buf, t0());
        if (n == 0) break;
        ++packets;
        ++pn;
    }
    CHECK(packets > 0);
    CHECK(packets < 50u);  // bounded by the initial window, not by the data size
    CHECK(a.bytes_in_flight() > 0);
    (void)b;
}

TEST(flow_control_stops_a_sender_outrunning_a_receiver_that_never_reads) {
    StreamConfig cfg = fast_cfg();
    cfg.stream_recv_window = 8 * 1024;
    cfg.conn_recv_window   = 16 * 1024;

    StreamConnection a{cfg, Role::A};
    StreamConnection b{cfg, Role::B};
    Link link{a, b, Link::Config{0.0, 5ms, 0ms, 19}};

    StreamId id   = *a.open();
    auto     data = pattern(200000);
    size_t   off  = 0;
    for (int round = 0; round < 30; ++round) {
        off += a.write(id, std::span(data).subspan(off));
        link.advance(100ms);
    }

    // b never reads, so its window never slides. The amount buffered must stay
    // bounded by the advertised window rather than growing without limit.
    CHECK(b.readable_bytes(id) <= cfg.stream_recv_window);
}

TEST(a_reset_stream_is_reported_to_the_peer) {
    StreamConnection a{fast_cfg(), Role::A};
    StreamConnection b{fast_cfg(), Role::B};
    Link link{a, b, Link::Config{0.0, 5ms, 0ms, 23}};

    StreamId id = *a.open();
    a.write(id, pattern(100));
    link.advance(100ms);
    a.reset(id, 42);
    link.advance(300ms);

    bool saw = false;
    while (auto e = b.poll_event()) {
        if (e->kind == StreamEventKind::Reset && e->id == id && e->error_code == 42) saw = true;
    }
    CHECK(saw);
}

TEST(a_dead_peer_is_eventually_reported_rather_than_probed_forever) {
    StreamConfig cfg = fast_cfg();
    cfg.idle_timeout  = 2s;
    cfg.max_pto_count = 4;

    StreamConnection a{cfg, Role::A};
    StreamId         id = *a.open();
    a.write(id, pattern(1000));

    // Send into a void: nothing is ever acknowledged.
    uint64_t pn = 1;
    std::vector<uint8_t> buf(1200);
    Instant now = t0();
    a.poll_datagram(pn++, buf, now);

    for (int i = 0; i < 2000 && !a.is_dead(); ++i) {
        now += 50ms;
        a.on_timeout(now);
    }
    CHECK(a.is_dead());

    bool dead_event = false;
    while (auto e = a.poll_event()) {
        if (e->kind == StreamEventKind::ConnDead) dead_event = true;
    }
    CHECK(dead_event);
}

TEST(a_large_transfer_costs_a_sane_number_of_packets) {
    // A rough efficiency guard: if framing overhead or spurious retransmission
    // regressed badly, this is where it shows up.
    StreamConnection a{fast_cfg(), Role::A};
    StreamConnection b{fast_cfg(), Role::B};
    Link link{a, b, Link::Config{0.0, 5ms, 0ms, 29}};

    auto     data = pattern(100000);
    StreamId id   = *a.open();
    size_t   off  = 0;
    for (int round = 0; round < 100 && off < data.size(); ++round) {
        off += a.write(id, std::span(data).subspan(off));
        link.advance(100ms);
    }
    a.finish(id);
    link.advance(10s);

    std::vector<uint8_t> got;
    drain(b, id, got);
    REQUIRE(got.size() == data.size());

    // 100 KB at ~1100 bytes of payload per datagram is ~91 packets minimum.
    // Allow generous headroom for acks and window updates, but catch a blowup.
    CHECK(a.packets_sent() < 400u);
}

TEST(a_transfer_larger_than_the_receive_window_keeps_flowing) {
    // Every other end-to-end test here moves less than one receive window, so
    // none of them exercised the window actually sliding. That gap hid a real
    // bug: the sender seeded its per-stream limit from the CONNECTION window,
    // believed it had four times the room it really had, overran the
    // receiver's buffer and got the stream reset -- a 512 KB transfer stopping
    // dead at exactly 256 KB.
    StreamConfig cfg = fast_cfg();
    cfg.stream_recv_window = 16 * 1024;   // small, so the window must slide often
    cfg.conn_recv_window   = 256 * 1024;  // deliberately much larger

    StreamConnection a{cfg, Role::A};
    StreamConnection b{cfg, Role::B};
    Link link{a, b, Link::Config{0.0, 5ms, 0ms, 31}};

    const size_t total = 128 * 1024;  // eight windows' worth
    auto     data = pattern(total, 5);
    StreamId id   = *a.open();

    std::vector<uint8_t> got;
    size_t               off = 0;
    for (int round = 0; round < 400 && got.size() < total; ++round) {
        if (off < data.size()) off += a.write(id, std::span(data).subspan(off));
        link.advance(50ms);
        drain(b, id, got);   // the reader is what makes the window slide
    }
    a.finish(id);
    link.advance(5s);
    drain(b, id, got);

    CHECK_EQ(got.size(), total);
    CHECK(got == data);
}

TEST(a_stalled_reader_does_not_lose_data_once_it_resumes) {
    // Backpressure must be recoverable, not fatal: a receiver that stops
    // reading for a while should still get every byte when it starts again.
    StreamConfig cfg = fast_cfg();
    cfg.stream_recv_window = 8 * 1024;

    StreamConnection a{cfg, Role::A};
    StreamConnection b{cfg, Role::B};
    Link link{a, b, Link::Config{0.0, 5ms, 0ms, 37}};

    const size_t total = 64 * 1024;
    auto     data = pattern(total, 11);
    StreamId id   = *a.open();

    size_t off = 0;
    for (int i = 0; i < 20; ++i) {
        if (off < data.size()) off += a.write(id, std::span(data).subspan(off));
        link.advance(50ms);   // b reads nothing: the window closes
    }

    std::vector<uint8_t> got;
    for (int round = 0; round < 400 && got.size() < total; ++round) {
        if (off < data.size()) off += a.write(id, std::span(data).subspan(off));
        link.advance(50ms);
        drain(b, id, got);
    }
    a.finish(id);
    link.advance(5s);
    drain(b, id, got);

    CHECK_EQ(got.size(), total);
    CHECK(got == data);
}

// ---------------------------------------------------------------------------
// Stream lifetime: retirement, the concurrency cap, and the events that were
// being generated and dropped.
// ---------------------------------------------------------------------------
namespace {
// Collect every event of one kind seen on a connection so far.
std::vector<StreamEvent> collect(StreamConnection& c, StreamEventKind want) {
    std::vector<StreamEvent> out;
    while (auto e = c.poll_event()) {
        if (e->kind == want) out.push_back(*e);
    }
    return out;
}
}  // namespace

TEST(a_fully_closed_stream_is_retired_and_reports_closed) {
    // Before this, streams_ only ever grew: a connection that opened and
    // finished a million streams held a million buffers until it died.
    //
    // A bidirectional stream needs BOTH ends to finish. One side calling
    // finish() half-closes it; the other direction is still open and the state
    // is still live, which is why the one-way case below uses a uni stream.
    StreamConnection a{fast_cfg(), Role::A};
    StreamConnection b{fast_cfg(), Role::B};
    Link link{a, b, Link::Config{0.0, 5ms, 0ms, 1}};

    auto     data = pattern(4000);
    StreamId id   = *a.open();
    size_t   off  = 0;
    while (off < data.size()) {
        off += a.write(id, std::span(data).subspan(off));
        link.advance(50ms);
    }
    a.finish(id);
    link.advance(2s);

    std::vector<uint8_t> got;
    drain(b, id, got);
    CHECK_EQ(got.size(), data.size());

    // Half closed: a's send side is done but its recv side is not.
    CHECK(a.exists(id));
    CHECK(b.exists(id));

    b.finish(id);
    link.advance(2s);
    drain(b, id, got);
    link.advance(2s);

    CHECK(!a.exists(id));
    CHECK(!b.exists(id));
    CHECK(a.active_streams().empty());
    CHECK(b.active_streams().empty());

    CHECK_EQ(collect(a, StreamEventKind::Closed).size(), 1u);
    CHECK_EQ(collect(b, StreamEventKind::Closed).size(), 1u);
}

TEST(a_unidirectional_stream_retires_when_the_sender_finishes) {
    // The one-way transfer case: there is no reverse direction to wait on, so
    // FIN plus a drained receiver is the whole lifecycle.
    StreamConnection a{fast_cfg(), Role::A};
    StreamConnection b{fast_cfg(), Role::B};
    Link link{a, b, Link::Config{0.0, 5ms, 0ms, 1}};

    StreamId id = *a.open(/*bidirectional=*/false);
    auto data = pattern(4000);
    size_t off = 0;
    while (off < data.size()) {
        off += a.write(id, std::span(data).subspan(off));
        link.advance(50ms);
    }
    a.finish(id);
    link.advance(2s);

    std::vector<uint8_t> got;
    drain(b, id, got);
    link.advance(2s);

    CHECK_EQ(got.size(), data.size());
    CHECK(!a.exists(id));
    CHECK(!b.exists(id));
    CHECK_EQ(collect(a, StreamEventKind::Closed).size(), 1u);
    CHECK_EQ(collect(b, StreamEventKind::Closed).size(), 1u);
}

TEST(a_retired_stream_is_not_recreated_by_a_late_frame) {
    // A retransmitted STREAM frame arriving after retirement must not spring
    // the stream back to life and report a brand new Opened to the peer.
    StreamConnection a{fast_cfg(), Role::A};
    StreamConnection b{fast_cfg(), Role::B};
    Link link{a, b, Link::Config{0.0, 5ms, 0ms, 1}};

    StreamId id = *a.open(/*bidirectional=*/false);
    a.write(id, pattern(100));
    a.finish(id);
    link.advance(2s);

    std::vector<uint8_t> got;
    drain(b, id, got);
    link.advance(2s);
    REQUIRE(!b.exists(id));

    // Replay a data frame for the retired id straight into b.
    (void)collect(b, StreamEventKind::Opened);
    std::vector<uint8_t> frame(200);
    wire::Writer w{frame};
    auto payload = pattern(10);
    size_t n = encode_stream(w, id, 0, false, payload);
    REQUIRE(n > 0);
    b.on_datagram(9999, std::span(frame).first(w.size()), t0() + 10s);

    CHECK(!b.exists(id));
    CHECK(collect(b, StreamEventKind::Opened).empty());
}

TEST(a_peer_cannot_conjure_a_stream_under_our_own_role_bit) {
    // Stream ids carry the opener's role. A frame naming a locally-opened id
    // we never opened would otherwise be reported to us as our own stream.
    StreamConnection b{fast_cfg(), Role::B};

    const StreamId forged = make_stream_id(Role::B, true, 7);  // B is us
    std::vector<uint8_t> frame(200);
    wire::Writer w{frame};
    auto payload = pattern(10);
    REQUIRE(encode_stream(w, forged, 0, false, payload) > 0);
    b.on_datagram(1, std::span(frame).first(w.size()), t0());

    CHECK(!b.exists(forged));
    CHECK(collect(b, StreamEventKind::Opened).empty());
}

TEST(peer_opened_streams_are_capped) {
    // Without a cap an authenticated peer pins unbounded memory by sending one
    // byte to each of arbitrarily many stream ids.
    StreamConfig cfg = fast_cfg();
    cfg.max_concurrent_streams = 4;
    StreamConnection b{cfg, Role::B};

    for (uint64_t i = 0; i < 40; ++i) {
        const StreamId id = make_stream_id(Role::A, true, i);
        std::vector<uint8_t> frame(200);
        wire::Writer w{frame};
        auto payload = pattern(4);
        REQUIRE(encode_stream(w, id, 0, false, payload) > 0);
        b.on_datagram(i + 1, std::span(frame).first(w.size()), t0());
    }

    CHECK_EQ(b.active_streams().size(), 4u);
    CHECK_EQ(collect(b, StreamEventKind::Opened).size(), 4u);
}

TEST(the_local_stream_cap_is_enforced_and_released_by_retirement) {
    StreamConfig cfg = fast_cfg();
    cfg.max_concurrent_streams = 2;
    StreamConnection a{cfg, Role::A};
    StreamConnection b{fast_cfg(), Role::B};
    Link link{a, b, Link::Config{0.0, 5ms, 0ms, 1}};

    StreamId s1 = *a.open(/*bidirectional=*/false);
    StreamId s2 = *a.open(/*bidirectional=*/false);
    CHECK(!a.open().has_value());    // cap reached

    // Finish one and let it retire; the slot must come back.
    a.write(s1, pattern(64));
    a.finish(s1);
    link.advance(2s);
    std::vector<uint8_t> got;
    drain(b, s1, got);
    link.advance(2s);

    REQUIRE(!a.exists(s1));
    CHECK(a.exists(s2));
    auto s3 = a.open();
    CHECK(s3.has_value());
}

TEST(a_peer_reset_is_reported_to_the_application) {
    // The event was being emitted and then dropped by the api layer, so an
    // aborted stream just went quiet.
    StreamConnection a{fast_cfg(), Role::A};
    StreamConnection b{fast_cfg(), Role::B};
    Link link{a, b, Link::Config{0.0, 5ms, 0ms, 1}};

    StreamId id = *a.open();
    a.write(id, pattern(200));
    link.advance(200ms);
    std::vector<uint8_t> seen;
    drain(b, id, seen);          // b now knows the stream
    REQUIRE(!seen.empty());

    a.reset(id, 42);
    link.advance(1s);

    auto resets = collect(b, StreamEventKind::Reset);
    REQUIRE(resets.size() == 1);
    CHECK_EQ(resets[0].id, id);
    CHECK_EQ(resets[0].error_code, 42u);

    // A bare reset ends ONE direction. Neither side may retire on it: b can
    // still send to a, and a has not finished its own receive side. Retiring
    // here is what used to swallow the STOP_SENDING half of a teardown.
    CHECK(b.exists(id));
    CHECK(a.exists(id));

    // b's sending direction genuinely still works.
    CHECK(b.writable(id));
}

TEST(writable_fires_only_for_a_stream_that_was_actually_blocked) {
    // Waking every stream on every window update makes Writable noise the
    // application has to filter itself.
    StreamConfig cfg = fast_cfg();
    cfg.stream_recv_window = 4096;
    cfg.conn_recv_window   = 8192;
    StreamConnection a{cfg, Role::A};
    StreamConnection b{cfg, Role::B};
    Link link{a, b, Link::Config{0.0, 5ms, 0ms, 1}};

    StreamId blocked = *a.open();
    StreamId idle    = *a.open();

    // Fill the first stream until it refuses bytes.
    auto data = pattern(64 * 1024);
    size_t off = 0;
    for (int i = 0; i < 40; ++i) {
        size_t n = a.write(blocked, std::span(data).subspan(off));
        off += n;
        link.advance(50ms);
        if (n == 0) break;
    }
    (void)collect(a, StreamEventKind::Writable);

    // Draining on the receiver reopens the window.
    std::vector<uint8_t> got;
    for (int i = 0; i < 40; ++i) {
        drain(b, blocked, got);
        link.advance(50ms);
    }

    auto w = collect(a, StreamEventKind::Writable);
    REQUIRE(!w.empty());
    for (const auto& e : w) CHECK_EQ(e.id, blocked);   // never the idle stream
    (void)idle;
}

TEST(close_tears_a_bidi_stream_down_from_one_side) {
    // The teardown neither finish() nor reset() can do alone: RESET_STREAM to
    // end our direction, STOP_SENDING to ask the peer to end its own. The
    // peer's answering RESET_STREAM is what releases the initiator, so both
    // ends must come back empty.
    StreamConnection a{fast_cfg(), Role::A};
    StreamConnection b{fast_cfg(), Role::B};
    Link link{a, b, Link::Config{0.0, 5ms, 0ms, 1}};

    StreamId id = *a.open();
    a.write(id, pattern(200));
    link.advance(200ms);
    std::vector<uint8_t> seen;
    drain(b, id, seen);
    REQUIRE(!seen.empty());

    a.close(id, 7);
    link.advance(3s);

    CHECK(!a.exists(id));
    CHECK(!b.exists(id));
    CHECK(a.active_streams().empty());
    CHECK(b.active_streams().empty());

    // The peer is told why, rather than the stream just going quiet.
    auto resets = collect(b, StreamEventKind::Reset);
    REQUIRE(!resets.empty());
    CHECK_EQ(resets[0].error_code, 7u);
}

TEST(close_survives_a_lossy_link) {
    // RESET_STREAM and STOP_SENDING are not carried in SentPacket::chunks, so
    // ordinary loss detection cannot replay them. Without a re-arm on PTO a
    // single dropped datagram strands one side forever.
    StreamConnection a{fast_cfg(), Role::A};
    StreamConnection b{fast_cfg(), Role::B};
    Link link{a, b, Link::Config{0.30, 10ms, 0ms, 5}};

    StreamId id = *a.open();
    a.write(id, pattern(400));
    link.advance(1s);

    a.close(id, 3);
    link.advance(30s);

    CHECK(link.dropped() > 0);   // the loss really happened
    CHECK(!a.exists(id));
    CHECK(!b.exists(id));
}

TEST(close_works_in_both_directions_on_a_unidirectional_stream) {
    // A uni stream has only one direction, so close() must abort whichever end
    // it is called from without naming a direction that does not exist.
    {   // sender closes
        StreamConnection a{fast_cfg(), Role::A};
        StreamConnection b{fast_cfg(), Role::B};
        Link link{a, b, Link::Config{0.0, 5ms, 0ms, 1}};
        StreamId id = *a.open(/*bidirectional=*/false);
        a.write(id, pattern(200));
        link.advance(200ms);
        a.close(id, 1);
        link.advance(3s);
        CHECK(!a.exists(id));
        CHECK(!b.exists(id));
    }
    {   // receiver closes
        StreamConnection a{fast_cfg(), Role::A};
        StreamConnection b{fast_cfg(), Role::B};
        Link link{a, b, Link::Config{0.0, 5ms, 0ms, 1}};
        StreamId id = *a.open(/*bidirectional=*/false);
        a.write(id, pattern(200));
        link.advance(200ms);
        REQUIRE(b.exists(id));
        b.close(id, 2);
        link.advance(3s);
        CHECK(!a.exists(id));
        CHECK(!b.exists(id));
    }
}

TEST(closing_a_stream_leaves_the_others_untouched) {
    // Closing a stream is not closing the connection. The session below is not
    // this layer's business, and neither is any other stream on it.
    StreamConnection a{fast_cfg(), Role::A};
    StreamConnection b{fast_cfg(), Role::B};
    Link link{a, b, Link::Config{0.0, 5ms, 0ms, 1}};

    StreamId doomed   = *a.open();
    StreamId survivor = *a.open();

    a.write(doomed, pattern(100));
    a.write(survivor, pattern(100, 9));
    link.advance(500ms);

    a.close(doomed, 1);
    link.advance(2s);

    REQUIRE(!a.exists(doomed));
    REQUIRE(!b.exists(doomed));

    // The other stream is still live and still carries bytes afterwards.
    CHECK(a.exists(survivor));
    CHECK(b.exists(survivor));
    CHECK(!a.is_dead());
    CHECK(!b.is_dead());

    auto more = pattern(2000, 4);
    size_t off = 0;
    for (int i = 0; i < 40 && off < more.size(); ++i) {
        off += a.write(survivor, std::span(more).subspan(off));
        link.advance(100ms);
    }
    a.finish(survivor);
    link.advance(3s);

    std::vector<uint8_t> got;
    drain(b, survivor, got);
    CHECK_EQ(got.size(), 100u + more.size());
}

TEST(a_bare_reset_does_not_stop_the_peer_from_finishing) {
    // The peer's sending direction is independent. Refusing to send on a
    // peer-reset stream meant it could not push data OR a FIN, so its send side
    // never completed and the stream could never be released.
    StreamConnection a{fast_cfg(), Role::A};
    StreamConnection b{fast_cfg(), Role::B};
    Link link{a, b, Link::Config{0.0, 5ms, 0ms, 1}};

    StreamId id = *a.open();
    a.write(id, pattern(100));
    link.advance(300ms);
    std::vector<uint8_t> seen;
    drain(b, id, seen);

    a.reset(id, 5);
    link.advance(500ms);

    // b can still write and finish, even though a aborted its own direction.
    CHECK(b.write(id, pattern(300, 2)) > 0);
    b.finish(id);
    link.advance(3s);

    std::vector<uint8_t> back;
    drain(a, id, back);
    CHECK_EQ(back.size(), 300u);

    link.advance(2s);
    CHECK(!a.exists(id));
    CHECK(!b.exists(id));
}

TEST(stop_sending_ends_the_peers_direction_without_ending_ours) {
    // The third teardown primitive, and the one a reader wants: "I have what I
    // need, stop" -- without giving up our own direction the way close() does.
    StreamConnection a{fast_cfg(), Role::A};
    StreamConnection b{fast_cfg(), Role::B};
    Link link{a, b, Link::Config{0.0, 5ms, 0ms, 1}};

    StreamId id = *a.open();
    auto data = pattern(40000);
    size_t off = a.write(id, data);
    link.advance(500ms);

    std::vector<uint8_t> got;
    drain(b, id, got);
    REQUIRE(!got.empty());

    b.stop_sending(id, 9);
    link.advance(2s);

    // a has aborted its sending direction, so nothing more is accepted or sent.
    CHECK(!a.writable(id));
    CHECK_EQ(a.write(id, std::span(data).subspan(off)), 0u);

    const size_t delivered = got.size();
    link.advance(2s);
    drain(b, id, got);
    CHECK_EQ(got.size(), delivered);   // the flow really stopped

    // b's own sending direction survives: this is not a full teardown.
    CHECK(b.writable(id));
}

TEST(writable_fires_when_acks_drain_the_local_send_buffer) {
    // Three things can make write() short: the connection window, the peer's
    // per-stream window, and our OWN stream_send_cap. The first two are
    // relieved by a peer window update, which emits Writable. The third is
    // relieved by our data being ACKED -- and nothing used to emit anything
    // for it, so an application that waited for Writable instead of polling
    // (which is exactly what the docs tell it to do) waited forever.
    StreamConfig cfg = fast_cfg();
    cfg.stream_send_cap = 4096;        // well below the peer's receive window,
    StreamConnection a{cfg, Role::A};  // so only the local cap can block us
    StreamConnection b{fast_cfg(), Role::B};
    Link link{a, b, Link::Config{0.0, 5ms, 0ms, 1}};

    StreamId id = *a.open();
    auto data = pattern(8192);

    size_t off = a.write(id, data);
    REQUIRE(off > 0);
    CHECK_EQ(a.write(id, std::span(data).subspan(off)), 0u);   // local cap hit
    (void)collect(a, StreamEventKind::Writable);

    // Let it flush and be acknowledged. The receiver consumes far too little
    // to trigger a MAX_STREAM_DATA, so an ack is the only thing that can
    // unblock us -- which is precisely the case under test.
    std::vector<uint8_t> got;
    for (int i = 0; i < 20; ++i) {
        link.advance(100ms);
        drain(b, id, got);
    }

    CHECK(a.writable(id));   // there really is room now
    auto w = collect(a, StreamEventKind::Writable);
    CHECK(!w.empty());       // and the application was told
    CHECK(a.write(id, std::span(data).subspan(off)) > 0);
}

// ---------------------------------------------------------------------------
// Surviving a session re-handshake
// ---------------------------------------------------------------------------
TEST(a_stream_survives_a_session_restart_with_data_in_flight) {
    // A session reaches its 15-minute lifetime and is replaced. The peer has
    // not gone anywhere and the path is unchanged, so an in-progress transfer
    // must continue rather than be abandoned -- which is what destroying the
    // StreamConnection used to do, silently.
    StreamConnection a{fast_cfg(), Role::A};
    StreamConnection b{fast_cfg(), Role::B};
    // 40ms each way, so the pipe holds packets: the early ones are delivered
    // and acknowledged while later ones are still out. A 5ms link acks
    // everything between ticks and the restart would have nothing in flight to
    // rescue, which is the whole point of the test.
    Link link{a, b, Link::Config{0.0, 40ms, 0ms, 1}};

    auto     data = pattern(60000);
    StreamId id   = *a.open();
    size_t   off  = 0;

    // Get a transfer genuinely under way, with packets outstanding.
    for (int i = 0; i < 3; ++i) {
        off += a.write(id, std::span(data).subspan(off));
        link.advance(45ms);
    }
    std::vector<uint8_t> got;
    drain(b, id, got);
    REQUIRE(!got.empty());
    REQUIRE(got.size() < data.size());      // still going
    REQUIRE(a.bytes_in_flight() > 0);       // and something is outstanding

    // The session is replaced. Anything already on the wire was sealed under
    // the old keys and is now undecryptable, so it never arrives.
    REQUIRE(link.drop_in_flight() > 0);
    a.on_session_restart(link.now());
    b.on_session_restart(link.now());

    // Finish the transfer across the boundary.
    for (int i = 0; i < 200 && off < data.size(); ++i) {
        off += a.write(id, std::span(data).subspan(off));
        link.advance(50ms);
        drain(b, id, got);
    }
    a.finish(id);
    link.advance(5s);
    drain(b, id, got);

    CHECK_EQ(got.size(), data.size());
    CHECK(got == data);          // byte for byte, across the restart
    CHECK(!a.is_dead());
    CHECK(!b.is_dead());
}

TEST(a_session_restart_does_not_lose_unacknowledged_bytes) {
    // The specific hazard: bytes handed to the send buffer and put into a
    // packet, but not yet acknowledged when the session went away. They are in
    // neither the retransmit queue nor the unsent range, so unless the restart
    // declares those packets lost they are skipped by next_chunk() and never
    // arrive.
    StreamConnection a{fast_cfg(), Role::A};
    StreamConnection b{fast_cfg(), Role::B};
    Link link{a, b, Link::Config{0.0, 200ms, 0ms, 1}};   // slow: acks lag behind

    StreamId id = *a.open();
    auto data = pattern(20000);
    size_t off = a.write(id, data);
    REQUIRE(off > 0);

    // Let packets go out but deliberately not come back acknowledged.
    link.advance(80ms);
    REQUIRE(a.bytes_in_flight() > 0);

    // Those packets die with the old session, so the only way their bytes ever
    // reach the peer is if the restart puts them back in the retransmit queue.
    REQUIRE(link.drop_in_flight() > 0);
    a.on_session_restart(link.now());
    b.on_session_restart(link.now());

    a.finish(id);
    link.advance(20s);
    std::vector<uint8_t> got;
    drain(b, id, got);

    CHECK_EQ(got.size(), off);
    CHECK(std::equal(got.begin(), got.end(), data.begin()));
}

TEST(a_session_restart_clears_the_old_packet_number_space) {
    // Acks and loss detection are keyed on session packet numbers, which
    // restart at zero. Carrying either across would mean acknowledging packets
    // the peer has not sent yet -- so it would drop them from its sent table
    // and never retransmit.
    StreamConnection a{fast_cfg(), Role::A};
    StreamConnection b{fast_cfg(), Role::B};
    Link link{a, b, Link::Config{0.0, 5ms, 0ms, 1}};

    StreamId id = *a.open();
    a.write(id, pattern(30000));
    link.advance(300ms);
    std::vector<uint8_t> got;
    drain(b, id, got);
    REQUIRE(a.packets_sent() > 1);

    b.on_session_restart(link.now());

    // b has received plenty under the old session. If its ack tracker carried
    // over, the next ACK it builds would describe those old numbers.
    std::vector<uint8_t> out(1200);
    size_t n = b.poll_datagram(1, out, link.now());
    if (n > 0) {
        std::vector<Frame> frames;
        REQUIRE(decode_frames(std::span<const uint8_t>(out.data(), n), frames));
        for (const auto& f : frames) {
            if (f.type == FrameType::Ack) {
                // Nothing has arrived in the new space yet, so any ack must be
                // about packet 1 -- the one just polled -- not the old run.
                CHECK(f.ack.largest <= 1u);
            }
        }
    }
    CHECK(!b.is_dead());
}

// ---------------------------------------------------------------------------
// Hostile peers. An authenticated peer is still not a trusted one -- on an open
// topic it is anyone at all -- so the work and memory a frame costs must be
// bounded by what WE sent and advertised, never by numbers the peer chose.
// ---------------------------------------------------------------------------
namespace {

// Have `a` put `count` data-bearing packets in flight, numbered from `first_pn`.
void send_packets(StreamConnection& a, uint64_t first_pn, uint64_t count, Instant now) {
    StreamId id = *a.open();
    a.write(id, pattern(static_cast<size_t>(count) * 1100));
    std::vector<uint8_t> buf(1200);
    for (uint64_t i = 0; i < count; ++i) {
        REQUIRE(a.poll_datagram(first_pn + i, buf, now) > 0);
    }
}

// Feed `c` a datagram, numbered `pn`, that carries nothing but this ACK.
void deliver_ack(StreamConnection& c, const AckFrame& ack, uint64_t pn, Instant now) {
    std::vector<uint8_t> buf(64);
    wire::Writer         w{buf};
    REQUIRE(encode_ack(w, ack));
    c.on_datagram(pn, std::span(buf).first(w.size()), now);
}

std::vector<uint8_t> encoded(const AckFrame& a) {
    std::vector<uint8_t> buf(64);
    wire::Writer         w{buf};
    encode_ack(w, a);
    buf.resize(w.size());
    return buf;
}

}  // namespace

TEST(ack_decoder_rejects_ranges_that_do_not_fit_below_largest) {
    // for_each tolerates these by stopping early, so they used to decode as
    // valid. Our own encoder can never produce one, which makes it malformed,
    // and the decoder's rule for malformed is to refuse the whole datagram.
    std::vector<Frame> frames;

    AckFrame below_zero;
    below_zero.largest     = 5;
    below_zero.first_range = 100;
    CHECK(!decode_frames(encoded(below_zero), frames));

    AckFrame gap_past_origin;
    gap_past_origin.largest = 10;
    gap_past_origin.ranges.push_back(AckRange{1000, 0});
    CHECK(!decode_frames(encoded(gap_past_origin), frames));

    AckFrame len_past_origin;
    len_past_origin.largest = 10;                          // first range is just 10
    len_past_origin.ranges.push_back(AckRange{0, 9});      // 9 is skipped, so 8 down to -1
    CHECK(!decode_frames(encoded(len_past_origin), frames));

    // The boundary itself is fine: a range that ends exactly at zero.
    AckFrame to_zero;
    to_zero.largest = 10;
    to_zero.ranges.push_back(AckRange{0, 8});              // 8 down to 0
    CHECK(decode_frames(encoded(to_zero), frames));
}

TEST(an_ack_for_packets_never_sent_is_ignored) {
    // A peer acking numbers we never used is lying, and believing any of it --
    // even the part naming packets that do exist -- lets it inflate our
    // congestion window by acknowledging data it never received.
    StreamConnection a{fast_cfg(), Role::A};
    send_packets(a, 1, 3, t0());
    const size_t in_flight = a.bytes_in_flight();
    REQUIRE(in_flight > 0);

    AckFrame lie;
    lie.largest     = 100;
    lie.first_range = 99;  // 1..100: the three real packets and 97 that never existed
    deliver_ack(a, lie, 1, t0() + 20ms);
    CHECK_EQ(a.bytes_in_flight(), in_flight);

    // An honest ack for the same three packets still lands.
    AckFrame honest;
    honest.largest     = 3;
    honest.first_range = 2;
    deliver_ack(a, honest, 2, t0() + 25ms);
    CHECK_EQ(a.bytes_in_flight(), 0u);
}

TEST(ack_cost_is_bounded_by_packets_sent_not_by_the_ranges_claimed) {
    // Packet numbers are the session's AEAD counter, so a long-lived connection
    // legitimately reaches large ones, and an ACK can legitimately describe one
    // range reaching all the way back to zero. Walking that range a number at a
    // time costs whatever the peer wrote, which is a remote hang.
    constexpr uint64_t kBase = uint64_t{1} << 40;

    StreamConnection a{fast_cfg(), Role::A};
    send_packets(a, kBase, 3, t0());
    REQUIRE(a.bytes_in_flight() > 0);

    AckFrame wide;
    wide.largest     = kBase + 2;
    wide.first_range = kBase + 2;  // every number from zero up
    const auto start = std::chrono::steady_clock::now();
    deliver_ack(a, wide, 1, t0() + 20ms);
    const auto took = std::chrono::steady_clock::now() - start;

    CHECK_EQ(a.bytes_in_flight(), 0u);  // the three real packets are acked
    CHECK(took < 100ms);
}

TEST(recv_buffer_holds_each_byte_once_however_the_peer_overlaps_chunks) {
    // Chunks one byte apart overlap their neighbours almost completely. Kept
    // per start offset, every one of them was stored in full: a 64 KB window
    // pinned ~70 MB, and a 256 KB one ~280 MB, per stream.
    constexpr uint64_t kWindow = 64 * 1024;
    constexpr size_t   kChunk  = 1100;
    RecvBuffer rb{kWindow};
    auto data = pattern(kWindow);

    // Offset 0 is withheld, so nothing becomes contiguous yet.
    for (uint64_t off = 1; off + kChunk <= kWindow; ++off) {
        REQUIRE(rb.insert(off, std::span(data).subspan(off, kChunk), false));
    }
    CHECK(rb.pending_bytes() <= kWindow);
    CHECK_EQ(rb.fragment_count(), 1u);  // every chunk touched the last: one run

    REQUIRE(rb.insert(0, std::span(data).first(1), false));
    CHECK_EQ(rb.readable(), kWindow);
    CHECK_EQ(rb.fragment_count(), 0u);

    std::vector<uint8_t> out(kWindow);
    rb.read(out);
    CHECK(out == data);
}

TEST(recv_buffer_merges_fragments_that_touch) {
    RecvBuffer rb{64 * 1024};
    auto data = pattern(400);

    REQUIRE(rb.insert(100, std::span(data).subspan(100, 100), false));
    REQUIRE(rb.insert(300, std::span(data).subspan(300, 100), false));
    CHECK_EQ(rb.fragment_count(), 2u);

    REQUIRE(rb.insert(200, std::span(data).subspan(200, 100), false));  // bridges both
    CHECK_EQ(rb.fragment_count(), 1u);
    CHECK_EQ(rb.pending_bytes(), 300u);

    REQUIRE(rb.insert(0, std::span(data).first(100), false));
    CHECK_EQ(rb.readable(), 400u);
    std::vector<uint8_t> out(400);
    rb.read(out);
    CHECK(out == data);
}

TEST(recv_buffer_refuses_a_peer_that_fragments_without_limit) {
    // One-byte chunks with a one-byte hole between each can never merge, so
    // every one is a new fragment. Bytes stay within the window; bookkeeping
    // would not, and it is the count the cap exists to bound.
    RecvBuffer rb{64 * 1024};
    auto one = pattern(1);

    bool refused = false;
    for (uint64_t i = 1; i <= RecvBuffer::kMaxFragments + 16; ++i) {
        if (!rb.insert(2 * i, one, false)) {
            refused = true;
            break;
        }
    }
    CHECK(refused);
    CHECK(rb.fragment_count() <= RecvBuffer::kMaxFragments);
}

TEST(recv_buffer_reassembles_randomly_overlapping_fragments) {
    // The merging above must not cost correctness: whatever the overlap, the
    // application reads back exactly the bytes that were sent.
    std::mt19937_64 rng(7);
    for (int round = 0; round < 20; ++round) {
        constexpr size_t n = 20000;
        auto data = pattern(n, static_cast<uint8_t>(round));
        RecvBuffer rb{64 * 1024};

        // Random overlapping chunks, plus a clean tiling so every byte is
        // covered at least once, all delivered in one shuffled order.
        std::vector<std::pair<size_t, size_t>> chunks;
        std::uniform_int_distribution<size_t> pick_off(0, n - 1), pick_len(1, 1500);
        for (int i = 0; i < 200; ++i) {
            size_t o = pick_off(rng);
            chunks.emplace_back(o, std::min(pick_len(rng), n - o));
        }
        for (size_t o = 0; o < n; o += 1000) chunks.emplace_back(o, std::min<size_t>(1000, n - o));
        std::shuffle(chunks.begin(), chunks.end(), rng);

        for (auto [o, l] : chunks) {
            REQUIRE(rb.insert(o, std::span(data).subspan(o, l), o + l == n));
        }
        REQUIRE(rb.readable() == n);
        CHECK_EQ(rb.fragment_count(), 0u);

        std::vector<uint8_t> out(n);
        rb.read(out);
        CHECK(out == data);
        CHECK(rb.finished());
    }
}

TEST(a_peer_that_fragments_a_stream_without_limit_gets_it_reset) {
    // The cap is only worth something if the connection acts on it. Dropping
    // the excess is not an option: the packet carrying it is already acked, so
    // the sender would never retransmit and the stream would silently stall.
    StreamConnection b{fast_cfg(), Role::B};
    const StreamId id = make_stream_id(Role::A, true, 0);
    auto one = pattern(1);

    uint64_t offset = 2;
    for (uint64_t pn = 1; pn <= 40; ++pn) {
        std::vector<uint8_t> frame(1100);
        wire::Writer w{frame};
        while (w.remaining() > 16) {
            if (encode_stream(w, id, offset, false, one) == 0) break;
            offset += 2;
        }
        b.on_datagram(pn, std::span(frame).first(w.size()), t0());
    }

    CHECK(!collect(b, StreamEventKind::Reset).empty());
}

// ---------------------------------------------------------------------------
// Reported issues. Each test names the GitHub issue it reproduces.
// ---------------------------------------------------------------------------
TEST(a_peer_that_only_receives_is_not_declared_dead) {
    // #3. The receiving end of a one-way stream sends nothing but ACKs, and an
    // ACK is never itself acknowledged. Held in the sent table, those made the
    // receiver look like a sender whose peer had gone silent, and it declared
    // the connection dead one idle timeout in -- while data was still arriving.
    StreamConfig cfg;  // the real 30s idle timeout; fast_cfg()'s 60s hid this
    StreamConnection a{cfg, Role::A};
    StreamConnection b{cfg, Role::B};
    Link link{a, b, Link::Config{0.0, 5ms, 0ms, 1}};

    // A small message every 2s for 90s: three idle timeouts' worth. B reads it
    // all, and never enough to owe A a window update, so B has nothing to send
    // but ACKs.
    StreamId id = *a.open();
    std::vector<uint8_t> got;
    for (int i = 0; i < 45; ++i) {
        a.write(id, pattern(100, static_cast<uint8_t>(i)));
        link.advance(2s);
        drain(b, id, got);
    }

    CHECK(!a.is_dead());
    CHECK(!b.is_dead());
    CHECK(collect(b, StreamEventKind::ConnDead).empty());
    CHECK_EQ(got.size(), 4500u);
}

TEST(packets_that_elicit_no_ack_are_not_held_awaiting_one) {
    // #3. Nothing ever acknowledges an ACK-only packet, so holding it waiting
    // for an ack means holding it forever -- and letting whatever reads the
    // table believe work is outstanding.
    SentPackets sp;
    SentPacket  p;
    p.number        = 7;
    p.sent_at       = t0();
    p.size          = 40;
    p.ack_eliciting = false;
    sp.on_sent(p);

    CHECK(sp.empty());
    // The number was still used, so a peer acking it is telling the truth.
    REQUIRE(sp.largest_sent().has_value());
    CHECK_EQ(*sp.largest_sent(), 7u);
}

namespace {

// Hand `c` a datagram of pure padding. It carries nothing, but like any
// arriving datagram it gives the connection a chance to retire streams.
void poke(StreamConnection& c, uint64_t pn, Instant now) {
    const std::array<uint8_t, 1> padding{0x00};
    c.on_datagram(pn, padding, now);
}

bool saw_finished(StreamConnection& c, StreamId id) {
    for (const auto& e : collect(c, StreamEventKind::Finished)) {
        if (e.id == id) return true;
    }
    return false;
}

// A bidi stream where A has written 100 bytes and had them all acked, and B
// has written and FINished its own direction, which A has read to the end.
// What remains is A's FIN.
StreamId everything_done_but_a_fin(StreamConnection& a, StreamConnection& b, Link& link) {
    StreamId id = *a.open();
    a.write(id, pattern(100));
    link.advance(200ms);

    std::vector<uint8_t> at_b;
    drain(b, id, at_b);
    b.write(id, pattern(100, 1));
    b.finish(id);
    link.advance(200ms);

    std::vector<uint8_t> at_a;
    drain(a, id, at_a);
    (void)collect(b, StreamEventKind::Finished);  // start from a clean slate
    return id;
}

}  // namespace

TEST(send_buffer_is_not_complete_until_the_fin_itself_is_acked) {
    // #10. The last data chunk can be sent before finish() and acked after
    // it. That ack reaches the end of the stream, but it did not carry the
    // FIN, and the FIN has not even been sent yet.
    SendBuffer sb{1 << 20};
    sb.write(pattern(100), 1 << 20);
    auto data = sb.next_chunk(1000);
    REQUIRE(data.has_value());
    REQUIRE(!data->fin);
    sb.on_sent(data->offset, data->data.size());

    sb.finish();
    sb.on_acked(data->offset, data->data.size(), /*fin=*/false);
    CHECK(!sb.complete());

    auto fin = sb.next_chunk(1000);
    REQUIRE(fin.has_value());
    CHECK(fin->fin);
    CHECK(fin->data.empty());
    sb.on_sent(fin->offset, 0);
    CHECK(!sb.complete());  // sent is not delivered

    sb.on_acked(fin->offset, 0, /*fin=*/true);
    CHECK(sb.complete());
}

TEST(finishing_after_everything_is_acked_still_delivers_the_fin) {
    // #10. With every byte already acked, finish() made the send side look
    // complete at once, so the first datagram to arrive retired the stream --
    // before the FIN was ever sent. The peer never saw the stream end.
    StreamConnection a{fast_cfg(), Role::A};
    StreamConnection b{fast_cfg(), Role::B};
    Link link{a, b, Link::Config{0.0, 5ms, 0ms, 1}};
    StreamId id = everything_done_but_a_fin(a, b, link);
    REQUIRE(a.finished(id));

    a.finish(id);
    poke(a, 0, link.now());  // something arrives before A gets to send

    link.advance(2s);
    CHECK(saw_finished(b, id));
    CHECK(!a.exists(id));  // and once the FIN is acked, the stream does retire
}

TEST(a_lost_fin_is_resent_even_when_other_traffic_arrives_first) {
    // #10. A lost FIN-only frame is re-armed on loss, but the stream had
    // already retired by then, so nothing was left to resend it.
    StreamConnection a{fast_cfg(), Role::A};
    StreamConnection b{fast_cfg(), Role::B};
    Link link{a, b, Link::Config{0.0, 5ms, 0ms, 1}};
    StreamId id = everything_done_but_a_fin(a, b, link);
    REQUIRE(a.finished(id));

    a.finish(id);
    link.advance(1ms);                    // A sends the FIN...
    REQUIRE(link.drop_in_flight() > 0);   // ...and it is lost
    poke(a, 0, link.now());

    link.advance(3s);
    CHECK(saw_finished(b, id));
}

namespace {

// Push `total` bytes from A to B, with B reading as it goes, but lose the one
// datagram B sends right after it first drains a full window -- the one that
// carries the window update. Returns how many bytes B ends up with.
size_t transfer_losing_the_first_window_update(StreamConfig cfg, size_t total) {
    StreamConnection a{cfg, Role::A};
    StreamConnection b{cfg, Role::B};
    Link link{a, b, Link::Config{0.0, 5ms, 0ms, 1}};

    auto     data = pattern(total);
    StreamId id   = *a.open();
    size_t   off  = a.write(id, data);

    // Run until A is out of credit, then let B read everything it holds.
    link.advance(300ms);
    std::vector<uint8_t> got;
    drain(b, id, got);
    if (got.empty() || got.size() >= total) return got.size();

    // B's next datagram announces the room it just made. Lose it.
    link.advance(1ms);
    if (link.drop_in_flight() == 0) return got.size();

    for (int i = 0; i < 100 && got.size() < total; ++i) {
        off += a.write(id, std::span(data).subspan(off));
        link.advance(100ms);
        drain(b, id, got);
    }
    return got.size();
}

}  // namespace

TEST(a_lost_stream_window_update_is_resent) {
    // #4. Window updates were fire-and-forget: the new limit was recorded as
    // announced when written, not when acked, so losing that one datagram
    // left the sender at the old limit for good -- and since the receiver's
    // "moved far enough to announce" test was measured against the lost
    // value, it never tried again. The transfer stopped dead.
    StreamConfig cfg = fast_cfg();
    cfg.stream_recv_window = 4096;
    CHECK_EQ(transfer_losing_the_first_window_update(cfg, 20000), 20000u);
}

TEST(a_flow_control_violation_is_reported_once_and_stops_the_peer) {
    // #25. Overrunning the window reset our sending direction and reported
    // it, but left the peer's direction open: the peer kept sending, every
    // further frame was a fresh violation and a fresh Reset event, and the
    // receive side never ended, so the stream never retired.
    StreamConfig cfg       = fast_cfg();
    cfg.stream_recv_window = 1000;
    StreamConnection b{cfg, Role::B};
    const StreamId   id    = make_stream_id(Role::A, true, 0);
    auto             chunk = pattern(600);

    // Offsets 0, 600, 1200, ...: the second frame already runs past 1000.
    for (uint64_t pn = 1; pn <= 5; ++pn) {
        std::vector<uint8_t> frame(1200);
        wire::Writer         w{frame};
        REQUIRE(encode_stream(w, id, (pn - 1) * 600, false, chunk) > 0);
        b.on_datagram(pn, std::span(frame).first(w.size()), t0());
    }
    CHECK_EQ(collect(b, StreamEventKind::Reset).size(), 1u);

    // B must tell A to stop, not just abort its own direction.
    std::vector<uint8_t> out(1200);
    size_t n = b.poll_datagram(1, out, t0());
    REQUIRE(n > 0);
    std::vector<Frame> frames;
    REQUIRE(decode_frames(std::span<const uint8_t>(out.data(), n), frames));
    bool stop = false;
    for (const auto& f : frames) {
        if (f.type == FrameType::StopSending && f.stop.id == id) stop = true;
    }
    CHECK(stop);

    // With both directions over, the stream retires rather than holding a slot.
    poke(b, 6, t0() + 10ms);
    CHECK(!b.exists(id));
}

namespace {

// Abandon `rounds` one-way streams of `each` bytes, in the way `abandon`
// chooses, then try to push `last` bytes on a fresh stream. Returns how many
// of those the receiver gets.
template <typename Abandon>
size_t transfer_after_abandoning_streams(int rounds, size_t each, size_t last,
                                         Abandon&& abandon) {
    StreamConfig cfg       = fast_cfg();
    cfg.conn_recv_window   = 8192;
    cfg.stream_recv_window = 64 * 1024;
    StreamConnection a{cfg, Role::A};
    StreamConnection b{cfg, Role::B};
    Link link{a, b, Link::Config{0.0, 5ms, 0ms, 1}};

    for (int i = 0; i < rounds; ++i) {
        StreamId s = *a.open(/*bidirectional=*/false);
        auto     d = pattern(each);
        size_t   off = 0;
        for (int t = 0; t < 50 && off < each; ++t) {
            off += a.write(s, std::span(d).subspan(off));
            link.advance(20ms);
        }
        abandon(a, b, s);
        link.advance(300ms);
    }

    StreamId s    = *a.open(/*bidirectional=*/false);
    auto     data = pattern(last);
    size_t   off  = 0;
    std::vector<uint8_t> got;
    for (int t = 0; t < 100 && got.size() < last; ++t) {
        off += a.write(s, std::span(data).subspan(off));
        link.advance(50ms);
        drain(b, s, got);
    }
    return got.size();
}

}  // namespace

TEST(resetting_streams_does_not_leak_connection_credit) {
    // #14. The sender counts connection credit when it writes; the receiver
    // gave it back only as the application read. Bytes a reset threw away
    // were counted on one side and never on the other, so each abandoned
    // stream shrank the connection window for good -- here, after ~8 KB of
    // them, nothing more could be sent on any stream.
    size_t got = transfer_after_abandoning_streams(
        10, 3000, 5000, [](StreamConnection& a, StreamConnection&, StreamId s) {
            a.reset(s, 7);
        });
    CHECK_EQ(got, 5000u);
}

TEST(closing_unread_streams_does_not_leak_connection_credit) {
    // #14, from the other end: the receiver closes streams without reading
    // them. Those bytes arrived and were counted, but will never be consumed.
    size_t got = transfer_after_abandoning_streams(
        10, 3000, 5000, [](StreamConnection&, StreamConnection& b, StreamId s) {
            b.close(s, 7);
        });
    CHECK_EQ(got, 5000u);
}

TEST(the_connection_receive_window_is_enforced_across_streams) {
    // #15. Only the per-stream windows were checked on receive, so a peer
    // could fill every stream to its own limit at once: 64 x 256 KB = 16 MB
    // buffered per connection, against a documented 1 MB.
    StreamConfig cfg       = fast_cfg();
    cfg.conn_recv_window   = 4096;
    cfg.stream_recv_window = 64 * 1024;
    StreamConnection b{cfg, Role::B};
    auto chunk = pattern(1000);

    for (uint64_t i = 0; i < 10; ++i) {
        std::vector<uint8_t> frame(1200);
        wire::Writer         w{frame};
        REQUIRE(encode_stream(w, make_stream_id(Role::A, true, i), 0, false, chunk) > 0);
        b.on_datagram(i + 1, std::span(frame).first(w.size()), t0());
    }

    size_t buffered = 0;
    for (StreamId id : b.active_streams()) buffered += b.readable_bytes(id);
    CHECK(buffered <= 4096u);
    CHECK(!collect(b, StreamEventKind::Reset).empty());
}

TEST(a_lost_connection_window_update_is_resent) {
    // #4, at the connection level: the same loss of MAX_DATA.
    StreamConfig cfg = fast_cfg();
    cfg.conn_recv_window   = 4096;
    cfg.stream_recv_window = 64 * 1024;
    CHECK_EQ(transfer_losing_the_first_window_update(cfg, 20000), 20000u);
}
