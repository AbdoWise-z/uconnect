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

    sb.on_acked(c->offset, c->data.size());
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
