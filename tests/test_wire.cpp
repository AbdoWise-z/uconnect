#include <random>
#include <utility>

#include "messages.hpp"
#include "testing.hpp"

using namespace uconnect;
using namespace uconnect::wire;

namespace {

DevId dev_of(uint8_t fill) {
    DevId d{};
    d.fill(fill);
    return d;
}

Candidate host_v4(uint8_t last, uint16_t port) {
    return Candidate{Candidate::Kind::Host, Endpoint{IpAddr::v4(192, 168, 1, last), port}};
}

Candidate srflx_v6(uint16_t port) {
    IpAddr ip;
    ip.family = IpAddr::Family::V6;
    for (uint8_t i = 0; i < 16; ++i) ip.bytes[i] = static_cast<uint8_t>(i + 1);
    return Candidate{Candidate::Kind::Srflx, Endpoint{ip, port}};
}

// Encode a message with its header, return the datagram.
template <typename T>
std::vector<uint8_t> pack(MsgType type, const T& msg, uint8_t hflags = 0) {
    std::vector<uint8_t> buf(kMaxDatagram);
    Writer w{buf};
    Header{type, kVersion, hflags, 0x1234}.encode(w);
    msg.encode(w);
    buf.resize(w.size());
    return buf;
}

}  // namespace

// ---------------------------------------------------------------------------
// Buffer primitives
// ---------------------------------------------------------------------------
TEST(buffer_roundtrips_integers_big_endian) {
    std::vector<uint8_t> buf(32);
    Writer w{buf};
    w.u8(0xAB);
    w.u16(0x1234);
    w.u32(0xDEADBEEF);
    w.u64(0x0102030405060708ULL);
    REQUIRE(w.ok());

    // Big-endian on the wire, most significant byte first.
    CHECK_EQ(buf[0], 0xAB);
    CHECK_EQ(buf[1], 0x12);
    CHECK_EQ(buf[2], 0x34);
    CHECK_EQ(buf[3], 0xDE);
    CHECK_EQ(buf[7], 0x01);

    Reader r{std::span<const uint8_t>(buf.data(), w.size())};
    CHECK_EQ(r.u8(), 0xAB);
    CHECK_EQ(r.u16(), 0x1234);
    CHECK_EQ(r.u32(), 0xDEADBEEF);
    CHECK(r.u64() == 0x0102030405060708ULL);
    CHECK(r.ok());
    CHECK(r.empty());
}

TEST(writer_latches_error_on_overflow_and_does_not_write) {
    std::vector<uint8_t> buf(4);
    Writer w{buf};
    w.u32(0x11223344);
    CHECK(w.ok());
    w.u8(0xFF);  // one byte too many
    CHECK(!w.ok());
    CHECK_EQ(w.size(), 4u);  // the failed write did not advance the cursor
    // Error is sticky: a subsequent write that would fit still fails.
    Writer w2{buf};
    w2.u64(0);
    CHECK(!w2.ok());
    w2.u8(1);
    CHECK(!w2.ok());
}

TEST(reader_returns_zero_past_end_and_latches) {
    std::array<uint8_t, 2> buf{0xAA, 0xBB};
    Reader r{buf};
    CHECK_EQ(r.u8(), 0xAA);
    CHECK_EQ(r.u32(), 0u);  // short read yields zero, not garbage
    CHECK(!r.ok());
    CHECK_EQ(r.remaining(), 0u);
}

TEST(endpoint_roundtrips_v4_and_v6) {
    std::vector<uint8_t> buf(64);
    Writer w{buf};
    Endpoint a{IpAddr::v4(203, 0, 113, 7), 39412};
    IpAddr v6;
    v6.family = IpAddr::Family::V6;
    v6.bytes.fill(0x42);
    Endpoint b{v6, 4433};
    w.endpoint(a);
    w.endpoint(b);
    REQUIRE(w.ok());
    CHECK_EQ(w.size(), 7u + 19u);  // family+4+port, family+16+port

    Reader r{std::span<const uint8_t>(buf.data(), w.size())};
    CHECK(r.endpoint() == a);
    CHECK(r.endpoint() == b);
    CHECK(r.ok());
}

TEST(reader_rejects_bogus_address_family) {
    std::array<uint8_t, 8> buf{};
    buf[0] = 9;  // neither 4 nor 6
    Reader r{buf};
    r.endpoint();
    CHECK(!r.ok());
}

// ---------------------------------------------------------------------------
// Header and demultiplexing
// ---------------------------------------------------------------------------
TEST(header_roundtrips) {
    std::vector<uint8_t> buf(16);
    Writer w{buf};
    Header h{MsgType::Lookup, kVersion, flags::kWantMeta, 0xCAFEBABE};
    h.encode(w);
    REQUIRE(w.ok());
    CHECK_EQ(w.size(), Header::kSize);

    Reader r{std::span<const uint8_t>(buf.data(), w.size())};
    auto got = Header::decode(r);
    REQUIRE(got.has_value());
    CHECK(got->type == MsgType::Lookup);
    CHECK_EQ(got->flags, flags::kWantMeta);
    CHECK_EQ(got->txn_id, 0xCAFEBABEu);
}

TEST(header_rejects_wrong_version_and_unknown_class) {
    std::array<uint8_t, 8> buf{static_cast<uint8_t>(MsgType::Lookup), 0x99, 0, 0, 0, 0, 0, 0};
    Reader r{buf};
    CHECK(!Header::decode(r).has_value());  // version mismatch

    std::array<uint8_t, 8> buf2{0x7F, kVersion, 0, 0, 0, 0, 0, 0};
    Reader r2{buf2};
    CHECK(!Header::decode(r2).has_value());  // 0x7F is in no defined class

    // The retired UDP handshake range is not accepted either.
    std::array<uint8_t, 8> buf3{0x30, kVersion, 0, 0, 0, 0, 0, 0};
    Reader r3{buf3};
    CHECK(!Header::decode(r3).has_value());
}

TEST(classify_partitions_the_type_space) {
    CHECK(classify(0x01) == MsgClass::Signaling);
    CHECK(classify(0x1F) == MsgClass::Signaling);
    CHECK(classify(0x20) == MsgClass::Probe);
    CHECK(classify(0x30) == MsgClass::Unknown);
    CHECK(classify(0x40) == MsgClass::Transport);
    CHECK(classify(0x00) == MsgClass::Unknown);
    CHECK(classify(0x50) == MsgClass::Unknown);
    // The ranges must not overlap -- demultiplexing depends on it.
    for (int i = 0; i <= 0xFF; ++i) {
        auto c = classify(static_cast<uint8_t>(i));
        int matches = (i >= 0x01 && i <= 0x1F) + (i >= 0x20 && i <= 0x2F) +
                      (i >= 0x40 && i <= 0x4F);
        CHECK((c == MsgClass::Unknown) == (matches == 0));
    }
}

TEST(peek_type_demuxes_without_consuming) {
    Probe p;
    p.txn.fill(0x11);
    auto dgram = pack(MsgType::Probe, p);
    auto t = peek_type(dgram);
    REQUIRE(t.has_value());
    CHECK(*t == MsgType::Probe);

    std::array<uint8_t, 3> tiny{};
    CHECK(!peek_type(tiny).has_value());  // shorter than a header
}

// ---------------------------------------------------------------------------
// Message round-trips
// ---------------------------------------------------------------------------
TEST(peer_entry_roundtrips_with_candidates_and_meta) {
    PeerEntry in;
    in.dev_id   = dev_of(0xa3);
    in.age_secs = 17;
    in.stale    = true;
    in.cands    = {host_v4(40, 51820), srflx_v6(51820)};
    in.meta     = {'n', 'a', 'm', 'e'};

    std::vector<uint8_t> buf(kMaxDatagram);
    Writer w{buf};
    in.encode(w);
    REQUIRE(w.ok());
    Reader r{std::span<const uint8_t>(buf.data(), w.size())};
    auto out = PeerEntry::decode(r);
    REQUIRE(out.has_value());
    CHECK(out->dev_id == in.dev_id);
    CHECK_EQ(out->age_secs, 17);
    CHECK(out->stale);
    CHECK(out->cands == in.cands);
    CHECK(out->meta == in.meta);
    CHECK(r.empty());
}

TEST(peer_entry_encoded_size_matches_actual_encoding) {
    // The server sizes replies against this before committing an entry. If it
    // under-reports, a reply silently overflows its budget.
    for (uint8_t n = 0; n < 4; ++n) {
        PeerEntry e;
        e.dev_id = dev_of(n);
        for (uint8_t i = 0; i < n; ++i) e.cands.push_back(host_v4(i, 1000));
        if (n % 2) e.cands.push_back(srflx_v6(2000));
        e.meta.assign(n * 20u, 0xAB);

        std::vector<uint8_t> buf(kMaxDatagram);
        Writer w{buf};
        e.encode(w);
        REQUIRE(w.ok());
        CHECK_EQ(w.size(), e.encoded_size());
    }
}

TEST(probe_and_probe_ok_roundtrip) {
    Probe p;
    p.txn.fill(0x33);
    p.tag.fill(0x44);
    auto d = pack(MsgType::Probe, p);
    Reader r{d};
    REQUIRE(Header::decode(r).has_value());
    auto out = Probe::decode(r);
    REQUIRE(out.has_value());
    CHECK(out->txn == p.txn);
    CHECK(out->tag == p.tag);

    ProbeOk ok;
    ok.txn.fill(0x33);
    ok.mapped = Endpoint{IpAddr::v4(198, 51, 100, 9), 1234};
    ok.tag.fill(0x55);
    auto d2 = pack(MsgType::ProbeOk, ok);
    Reader r2{d2};
    REQUIRE(Header::decode(r2).has_value());
    auto out2 = ProbeOk::decode(r2);
    REQUIRE(out2.has_value());
    CHECK(out2->txn == ok.txn);
    CHECK(out2->mapped == ok.mapped);
}

TEST(transport_roundtrips_and_its_overhead_is_what_is_documented) {
    std::vector<uint8_t> ct(64, 0x11);
    Transport t;
    t.conn_id    = 7;
    t.counter    = 0x0102030405060708ULL;
    t.ciphertext = ct;
    auto d = pack(MsgType::Transport, t);
    // 64 bytes of ciphertext are 48 of payload and a 16-byte tag.
    CHECK_EQ(d.size(), 48u + kTransportOverhead);
    Reader r{d};
    REQUIRE(Header::decode(r).has_value());
    auto out = Transport::decode(r);
    REQUIRE(out.has_value());
    CHECK_EQ(out->conn_id, 7u);
    CHECK(out->counter == 0x0102030405060708ULL);
    CHECK_EQ(out->ciphertext.size(), 64u);
}

TEST(relay_data_and_error_roundtrip) {
    RelayData rd;
    rd.relay_id = 0xABCDEF0102030405ULL;
    rd.payload.assign(300, 0x42);
    auto d = pack(MsgType::RelayData, rd);
    Reader r{d};
    REQUIRE(Header::decode(r).has_value());
    auto out = RelayData::decode(r);
    REQUIRE(out.has_value());
    CHECK(out->relay_id == rd.relay_id);
    CHECK(out->payload == rd.payload);

    Error e{ErrorCode::QuotaExceeded, "too many records for this address"};
    auto d2 = pack(MsgType::Error, e);
    Reader r2{d2};
    REQUIRE(Header::decode(r2).has_value());
    auto out2 = Error::decode(r2);
    REQUIRE(out2.has_value());
    CHECK(out2->code == ErrorCode::QuotaExceeded);
    CHECK(out2->reason == e.reason);
}

// ---------------------------------------------------------------------------
// Caps and hostile input
// ---------------------------------------------------------------------------
TEST(decoder_rejects_counts_above_the_protocol_cap) {
    // A candidate count of 200 must be refused outright rather than reserved:
    // a one-byte field should never be a remote allocation primitive.
    std::vector<uint8_t> buf(kMaxDatagram);
    Writer w{buf};
    w.array(dev_of(1));
    w.u16(0);
    w.u8(0);
    w.u8(200);  // claimed candidate count, far above kMaxCandidates
    buf.resize(w.size());

    Reader r{buf};
    CHECK(!PeerEntry::decode(r).has_value());
}

TEST(decoder_rejects_oversize_meta) {
    std::vector<uint8_t> buf(kMaxDatagram);
    Writer w{buf};
    w.array(dev_of(1));
    w.u16(0);
    w.u8(0);
    w.u8(0);      // no candidates
    w.u16(9000);  // meta length beyond kMaxMeta
    buf.resize(w.size());

    Reader r{buf};
    CHECK(!PeerEntry::decode(r).has_value());
}

TEST(truncation_at_every_offset_never_yields_a_value) {
    // Chop a valid encoding at each length and confirm decode fails cleanly
    // rather than returning a half-populated struct.
    PeerEntry in;
    in.dev_id = dev_of(0x9f);
    in.cands  = {host_v4(40, 51820), srflx_v6(51820)};
    in.meta.assign(64, 0xAB);
    std::vector<uint8_t> full(kMaxDatagram);
    Writer w{full};
    in.encode(w);
    full.resize(w.size());

    for (size_t len = 0; len < full.size(); ++len) {
        Reader r{std::span<const uint8_t>(full.data(), len)};
        if (PeerEntry::decode(r).has_value()) {
            ::testing::fail(__FILE__, __LINE__,
                            "truncated PeerEntry at len " + std::to_string(len) + " decoded");
        }
    }
}

TEST(random_bytes_never_crash_the_decoders) {
    // Not a substitute for a real fuzzer, but it catches the obvious class of
    // bug where a decoder trusts a length it just read.
    std::mt19937 rng{12345};
    std::vector<uint8_t> buf;
    for (int iter = 0; iter < 20000; ++iter) {
        size_t len = rng() % 300;
        buf.resize(len);
        for (auto& b : buf) b = static_cast<uint8_t>(rng());

        Reader r{buf};
        auto h = Header::decode(r);
        if (!h) continue;
        switch (h->type) {
            case MsgType::ResolveOk:   (void)ResolveOk::decode(r); break;
            case MsgType::Relayed:     (void)Relayed::decode(r); break;
            case MsgType::RelayData:   (void)RelayData::decode(r); break;
            case MsgType::Error:       (void)Error::decode(r); break;
            case MsgType::Probe:       (void)Probe::decode(r); break;
            case MsgType::ProbeOk:     (void)ProbeOk::decode(r); break;
            case MsgType::Transport:   (void)Transport::decode(r); break;
            default:                   (void)PeerEntry::decode(r); break;
        }
    }
    CHECK(true);  // reaching here without a crash or hang is the assertion
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------
TEST(hex_roundtrips_and_rejects_bad_input) {
    std::array<uint8_t, 4> in{0x00, 0x9f, 0xab, 0xFF};
    auto hex = to_hex(in);
    CHECK(hex == "009fabff");

    auto back = from_hex<4>(hex);
    REQUIRE(back.has_value());
    CHECK(*back == in);

    CHECK(!from_hex<4>("009fabf").has_value());   // odd length
    CHECK(!from_hex<4>("009fabfg").has_value());  // non-hex digit
    CHECK(!from_hex<4>("009fabffaa").has_value());// too long
    CHECK(from_hex<4>("009FABFF").has_value());   // uppercase accepted
}
