#include <random>
#include <utility>

#include "messages.hpp"
#include "testing.hpp"

using namespace uconnect;
using namespace uconnect::wire;

namespace {

TopicId topic_of(uint8_t fill) {
    TopicId t{};
    t.fill(fill);
    return t;
}

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
}

TEST(classify_partitions_the_type_space) {
    CHECK(classify(0x01) == MsgClass::Signaling);
    CHECK(classify(0x1F) == MsgClass::Signaling);
    CHECK(classify(0x20) == MsgClass::Probe);
    CHECK(classify(0x30) == MsgClass::Handshake);
    CHECK(classify(0x40) == MsgClass::Transport);
    CHECK(classify(0x00) == MsgClass::Unknown);
    CHECK(classify(0x50) == MsgClass::Unknown);
    // The ranges must not overlap -- demultiplexing depends on it.
    for (int i = 0; i <= 0xFF; ++i) {
        auto c = classify(static_cast<uint8_t>(i));
        int matches = (i >= 0x01 && i <= 0x1F) + (i >= 0x20 && i <= 0x2F) +
                      (i >= 0x30 && i <= 0x3F) + (i >= 0x40 && i <= 0x4F);
        CHECK((c == MsgClass::Unknown) == (matches == 0));
    }
}

TEST(peek_type_demuxes_without_consuming) {
    Register reg;
    reg.id = topic_of(0x11);
    auto dgram = pack(MsgType::Register, reg);
    auto t = peek_type(dgram);
    REQUIRE(t.has_value());
    CHECK(*t == MsgType::Register);

    std::array<uint8_t, 3> tiny{};
    CHECK(!peek_type(tiny).has_value());  // shorter than a header
}

// ---------------------------------------------------------------------------
// Message round-trips
// ---------------------------------------------------------------------------
TEST(register_roundtrips_with_candidates_and_meta) {
    Register in;
    in.id         = topic_of(0x9f);
    in.mode       = TopicMode::Keyed;
    in.key_epoch  = 3;
    in.unlisted   = true;
    in.host_cands = {host_v4(40, 51820), srflx_v6(51820)};
    in.meta       = {'n', 'a', 'm', 'e'};
    in.cookie     = {1, 2, 3, 4};

    auto dgram = pack(MsgType::Register, in, flags::kUnlisted);
    Reader r{dgram};
    auto h = Header::decode(r);
    REQUIRE(h.has_value());
    auto out = Register::decode(r, *h);
    REQUIRE(out.has_value());

    CHECK(out->id == in.id);
    CHECK(out->mode == TopicMode::Keyed);
    CHECK_EQ(out->key_epoch, 3);
    CHECK(out->unlisted);  // carried in the header flags, not the body
    REQUIRE(out->host_cands.size() == 2);
    CHECK(out->host_cands[0] == in.host_cands[0]);
    CHECK(out->host_cands[1] == in.host_cands[1]);
    CHECK(out->meta == in.meta);
    CHECK(out->cookie == in.cookie);
    CHECK(r.empty());
}

TEST(register_ok_roundtrips) {
    RegisterOk in;
    in.dev_id = dev_of(0xa3);
    in.lease_token.fill(0x5c);
    in.srflx          = Endpoint{IpAddr::v4(203, 0, 113, 7), 39412};
    in.ttl_secs       = 90;
    in.peers_in_topic = 17;

    auto dgram = pack(MsgType::RegisterOk, in);
    Reader r{dgram};
    REQUIRE(Header::decode(r).has_value());
    auto out = RegisterOk::decode(r);
    REQUIRE(out.has_value());
    CHECK(out->dev_id == in.dev_id);
    CHECK(out->lease_token == in.lease_token);
    CHECK(out->srflx == in.srflx);
    CHECK_EQ(out->ttl_secs, 90);
    CHECK_EQ(out->peers_in_topic, 17);
}

TEST(keepalive_exposes_exactly_the_bytes_the_mac_covers) {
    // The MAC covers header + body + seq, and stops before the MAC field. Get
    // this boundary wrong and verification silently succeeds on tampered input.
    Keepalive in;
    in.dev_id   = dev_of(0x7c);
    in.auth.seq = 42;
    in.auth.mac.fill(0xEE);

    std::vector<uint8_t> buf(kMaxDatagram);
    Writer w{buf};
    Header{MsgType::Keepalive, kVersion, 0, 7}.encode(w);
    in.encode_prefix(w);
    size_t prefix_len = w.size();
    w.array(in.auth.mac);
    buf.resize(w.size());

    CHECK_EQ(prefix_len, Header::kSize + kDevIdLen + 8u);
    CHECK_EQ(buf.size(), prefix_len + kMacLen);

    Reader r{buf};
    REQUIRE(Header::decode(r).has_value());
    auto out = Keepalive::decode(r);
    REQUIRE(out.has_value());
    CHECK(out->dev_id == in.dev_id);
    CHECK(out->auth.seq == 42u);
    CHECK(out->auth.mac == in.auth.mac);
    CHECK_EQ(out->auth.authed.size(), prefix_len);
    CHECK(out->auth.authed.data() == buf.data());  // spans the real datagram bytes
}

TEST(lookup_clamps_max_to_the_ceiling) {
    Lookup in;
    in.id  = topic_of(0x01);
    in.max = 250;  // over the 100 ceiling
    auto dgram = pack(MsgType::Lookup, in, flags::kWantMeta);
    Reader r{dgram};
    auto h = Header::decode(r);
    REQUIRE(h.has_value());
    auto out = Lookup::decode(r, *h);
    REQUIRE(out.has_value());
    CHECK_EQ(out->max, kLookupMax);
    CHECK(out->want_meta);

    // Zero means "use the default", not "send me nothing".
    Lookup zero;
    zero.id  = topic_of(0x01);
    zero.max = 0;
    auto d2 = pack(MsgType::Lookup, zero);
    Reader r2{d2};
    auto h2 = Header::decode(r2);
    REQUIRE(h2.has_value());
    auto out2 = Lookup::decode(r2, *h2);
    REQUIRE(out2.has_value());
    CHECK_EQ(out2->max, kLookupDefault);
}

TEST(lookup_ok_roundtrips_paged_entries) {
    LookupOk in;
    in.id    = topic_of(0x9f);
    in.mode  = TopicMode::Keyed;
    in.total = 5000;
    in.part  = 1;
    in.parts = 4;
    for (uint8_t i = 0; i < 10; ++i) {
        PeerEntry e;
        e.dev_id   = dev_of(i);
        e.age_secs = static_cast<uint16_t>(i * 7);
        e.stale    = (i % 3 == 0);
        e.cands    = {host_v4(i, static_cast<uint16_t>(40000 + i))};
        in.entries.push_back(std::move(e));
    }

    auto dgram = pack(MsgType::LookupOk, in);
    CHECK(dgram.size() <= kMaxDatagram);
    Reader r{dgram};
    REQUIRE(Header::decode(r).has_value());
    auto out = LookupOk::decode(r);
    REQUIRE(out.has_value());
    CHECK(out->id == in.id);
    CHECK_EQ(out->total, 5000);
    CHECK_EQ(out->part, 1);
    CHECK_EQ(out->parts, 4);
    REQUIRE(out->entries.size() == 10);
    for (size_t i = 0; i < 10; ++i) {
        CHECK(out->entries[i].dev_id == in.entries[i].dev_id);
        CHECK(out->entries[i].stale == in.entries[i].stale);
        CHECK(out->entries[i].cands == in.entries[i].cands);
    }
}

TEST(lookup_ok_rejects_incoherent_paging) {
    LookupOk in;
    in.id    = topic_of(1);
    in.part  = 3;
    in.parts = 2;  // part >= parts is nonsense
    auto dgram = pack(MsgType::LookupOk, in);
    Reader r{dgram};
    REQUIRE(Header::decode(r).has_value());
    CHECK(!LookupOk::decode(r).has_value());
}

TEST(peer_entry_encoded_size_matches_actual_encoding) {
    // The server sizes pages against this before committing an entry to a
    // datagram. If it under-reports, pages silently overflow the MTU.
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

TEST(handshake_and_transport_roundtrip) {
    HandshakeInit hi;
    hi.conn_id = 0xAABBCCDD;
    hi.probe_txn.fill(0x77);
    hi.noise_msg.assign(80, 0x5A);  // [e, psk] + 32B padding + tag
    auto d = pack(MsgType::HandshakeInit, hi);
    Reader r{d};
    REQUIRE(Header::decode(r).has_value());
    auto out = HandshakeInit::decode(r);
    REQUIRE(out.has_value());
    CHECK_EQ(out->conn_id, 0xAABBCCDDu);
    CHECK(out->probe_txn == hi.probe_txn);
    CHECK(out->noise_msg == hi.noise_msg);

    std::vector<uint8_t> ct(64, 0x11);
    Transport t;
    t.conn_id    = 7;
    t.counter    = 0x0102030405060708ULL;
    t.ciphertext = ct;
    auto d2 = pack(MsgType::Transport, t);
    Reader r2{d2};
    REQUIRE(Header::decode(r2).has_value());
    auto out2 = Transport::decode(r2);
    REQUIRE(out2.has_value());
    CHECK_EQ(out2->conn_id, 7u);
    CHECK(out2->counter == 0x0102030405060708ULL);
    CHECK_EQ(out2->ciphertext.size(), 64u);
}

TEST(error_and_retry_roundtrip) {
    Error e{ErrorCode::QuotaExceeded, "too many records for this address"};
    auto d = pack(MsgType::Error, e);
    Reader r{d};
    REQUIRE(Header::decode(r).has_value());
    auto out = Error::decode(r);
    REQUIRE(out.has_value());
    CHECK(out->code == ErrorCode::QuotaExceeded);
    CHECK(out->reason == e.reason);

    Retry rt{{9, 8, 7, 6, 5}};
    auto d2 = pack(MsgType::Retry, rt);
    // A Retry must be smaller than the request that provoked it, or it is
    // itself an amplifier.
    CHECK(d2.size() < 64u);
}

// ---------------------------------------------------------------------------
// Caps and hostile input
// ---------------------------------------------------------------------------
TEST(decoder_rejects_counts_above_the_protocol_cap) {
    // A candidate count of 200 must be refused outright rather than reserved:
    // a one-byte field should never be a remote allocation primitive.
    std::vector<uint8_t> buf(kMaxDatagram);
    Writer w{buf};
    Header{MsgType::Register, kVersion, 0, 0}.encode(w);
    w.array(topic_of(1));
    w.u8(static_cast<uint8_t>(TopicMode::Open));
    w.u8(0);
    w.u8(200);  // claimed candidate count, far above kMaxCandidates
    buf.resize(w.size());

    Reader r{buf};
    auto h = Header::decode(r);
    REQUIRE(h.has_value());
    CHECK(!Register::decode(r, *h).has_value());
}

TEST(decoder_rejects_oversize_meta) {
    std::vector<uint8_t> buf(kMaxDatagram);
    Writer w{buf};
    Header{MsgType::Register, kVersion, 0, 0}.encode(w);
    w.array(topic_of(1));
    w.u8(static_cast<uint8_t>(TopicMode::Open));
    w.u8(0);
    w.u8(0);      // no candidates
    w.u16(9000);  // meta length beyond kMaxMeta
    buf.resize(w.size());

    Reader r{buf};
    auto h = Header::decode(r);
    REQUIRE(h.has_value());
    CHECK(!Register::decode(r, *h).has_value());
}

TEST(truncation_at_every_offset_never_yields_a_value) {
    // Chop a valid datagram at each length and confirm decode fails cleanly
    // rather than returning a half-populated struct.
    Register in;
    in.id         = topic_of(0x9f);
    in.mode       = TopicMode::Keyed;
    in.host_cands = {host_v4(40, 51820), srflx_v6(51820)};
    in.meta.assign(64, 0xAB);
    in.cookie.assign(16, 0xCD);
    auto full = pack(MsgType::Register, in);

    for (size_t len = 0; len < full.size(); ++len) {
        Reader r{std::span<const uint8_t>(full.data(), len)};
        auto h = Header::decode(r);
        if (!h) continue;
        auto out = Register::decode(r, *h);
        if (out.has_value()) {
            ::testing::fail(__FILE__, __LINE__,
                            "truncated Register at len " + std::to_string(len) + " decoded");
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
            case MsgType::Register:    (void)Register::decode(r, *h); break;
            case MsgType::RegisterOk:  (void)RegisterOk::decode(r); break;
            case MsgType::Keepalive:
            case MsgType::Unregister:  (void)DevAuth::decode(r); break;
            case MsgType::Update:      (void)Update::decode(r); break;
            case MsgType::Lookup:      (void)Lookup::decode(r, *h); break;
            case MsgType::LookupOk:    (void)LookupOk::decode(r); break;
            case MsgType::Resolve:     (void)Resolve::decode(r); break;
            case MsgType::ResolveOk:   (void)ResolveOk::decode(r); break;
            case MsgType::Topics:      (void)Topics::decode(r); break;
            case MsgType::TopicsOk:    (void)TopicsOk::decode(r); break;
            case MsgType::Connect:     (void)Connect::decode(r); break;
            case MsgType::Relayed:     (void)Relayed::decode(r); break;
            case MsgType::Retry:       (void)Retry::decode(r); break;
            case MsgType::Error:       (void)Error::decode(r); break;
            case MsgType::Probe:       (void)Probe::decode(r); break;
            case MsgType::ProbeOk:     (void)ProbeOk::decode(r); break;
            case MsgType::HandshakeInit:  (void)HandshakeInit::decode(r); break;
            case MsgType::HandshakeResp:  (void)HandshakeResp::decode(r); break;
            case MsgType::Transport:   (void)Transport::decode(r); break;
            default: break;
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
