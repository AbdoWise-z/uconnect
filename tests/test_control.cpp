// Control protocol v2: TCP framing and message codecs.

#include <random>

#include "control.hpp"
#include "testing.hpp"

using namespace uconnect;
using namespace uconnect::wire::ctl;
using wire::Header;
using wire::kMaxCandidates;
using wire::MsgType;
using wire::PeerEntry;
using wire::Reader;
using wire::Writer;
namespace flags = wire::flags;
namespace ctl   = wire::ctl;

namespace {

TopicId topic_of(uint8_t f) { TopicId t{}; t.fill(f); return t; }
DevId   dev_of(uint8_t f)   { DevId d{};   d.fill(f); return d; }

Candidate host(uint8_t last, uint16_t port) {
    return Candidate{Candidate::Kind::Host, Endpoint{IpAddr::v4(192, 168, 1, last), port}};
}

// Encode `m` as a full message, decode it back through the header.
template <typename T, typename Decode>
std::optional<T> roundtrip(MsgType type, const T& m, Decode decode, uint8_t flags = 0) {
    auto   bytes = message(type, 7, m, flags);
    Reader r{bytes};
    auto   h = Header::decode(r, ctl::kVersion);
    if (!h || h->type != type || h->txn_id != 7) return std::nullopt;
    return decode(r, *h);
}

}  // namespace

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------
TEST(control_frames_survive_arbitrary_tcp_chunking) {
    // TCP delivers bytes, not messages: a frame may arrive split anywhere, or
    // several in one read. Feed a run of frames one random-sized chunk at a
    // time and get exactly the messages back.
    std::vector<std::vector<uint8_t>> msgs;
    std::vector<uint8_t>              stream;
    for (uint8_t i = 0; i < 20; ++i) {
        std::vector<uint8_t> m(static_cast<size_t>(i) * 37 + 1, i);
        auto f = frame(m);
        stream.insert(stream.end(), f.begin(), f.end());
        msgs.push_back(std::move(m));
    }

    std::mt19937 rng(3);
    FrameReader  fr;
    std::vector<std::vector<uint8_t>> got;
    for (size_t off = 0; off < stream.size();) {
        size_t n = std::min<size_t>(stream.size() - off, 1 + rng() % 50);
        REQUIRE(fr.feed(std::span(stream).subspan(off, n)));
        off += n;
        while (auto m = fr.next()) got.push_back(std::move(*m));
    }
    CHECK(got == msgs);
}

TEST(control_an_oversized_frame_breaks_the_stream_before_it_is_buffered) {
    // The length prefix is checked on arrival: a peer announcing a huge frame
    // must not get to make us buffer it first.
    FrameReader fr{1000};
    const std::array<uint8_t, 2> prefix{0x10, 0x00};  // 4096 > 1000
    CHECK(!fr.feed(prefix));
    CHECK(fr.broken());
    CHECK(!fr.next().has_value());
}

TEST(control_bytes_after_a_frame_are_handed_back_raw) {
    // A relay connection sends one framed RelayJoin, then raw bytes. Anything
    // that arrived in the same read as the frame belongs to the raw stream.
    FrameReader fr;
    std::vector<uint8_t> msg{1, 2, 3};
    auto bytes = frame(msg);
    bytes.push_back(0xAA);
    bytes.push_back(0xBB);
    REQUIRE(fr.feed(bytes));
    auto m = fr.next();
    REQUIRE(m.has_value());
    CHECK(*m == msg);
    CHECK(fr.take_rest() == std::vector<uint8_t>({0xAA, 0xBB}));
}

TEST(control_messages_carry_version_two) {
    // v1 decoding refuses a v2 header and vice versa: the two protocols can
    // share a port without one being mistaken for the other.
    auto   bytes = empty_message(MsgType::Stats, 1);
    Reader r1{bytes};
    CHECK(!Header::decode(r1).has_value());
    Reader r2{bytes};
    CHECK(Header::decode(r2, ctl::kVersion).has_value());
}

// ---------------------------------------------------------------------------
// Codecs
// ---------------------------------------------------------------------------
TEST(control_register_roundtrips_with_flags_candidates_and_meta) {
    Register m;
    m.id         = topic_of(1);
    m.mode       = TopicMode::Keyed;
    m.key_epoch  = 3;
    m.unlisted   = true;
    m.host_cands = {host(10, 5000), host(11, 5000)};
    m.meta       = {9, 8, 7};
    auto got = roundtrip(MsgType::Register, m,
                         [](Reader& r, const Header& h) { return Register::decode(r, h); },
                         flags::kUnlisted);
    REQUIRE(got.has_value());
    CHECK(got->id == m.id);
    CHECK(got->mode == TopicMode::Keyed);
    CHECK_EQ(got->key_epoch, 3);
    CHECK(got->unlisted);
    CHECK(got->host_cands == m.host_cands);
    CHECK(got->meta == m.meta);
}

TEST(control_lookup_ok_carries_every_entry_in_one_frame) {
    // No paging on TCP: a full 100-entry sample with IPv6 and metadata fits
    // one frame.
    LookupOk m;
    m.id    = topic_of(2);
    m.mode  = TopicMode::Open;
    m.total = 500;
    for (uint8_t i = 0; i < 100; ++i) {
        PeerEntry e;
        e.dev_id = dev_of(i);
        e.cands.push_back(Candidate{Candidate::Kind::Srflx,
                                    Endpoint{IpAddr{IpAddr::Family::V6, {}}, 4433}});
        e.meta.assign(64, i);
        m.entries.push_back(e);
    }
    auto got = roundtrip(MsgType::LookupOk, m,
                         [](Reader& r, const Header&) { return LookupOk::decode(r); });
    REQUIRE(got.has_value());
    CHECK_EQ(got->entries.size(), 100u);
    CHECK_EQ(got->total, 500);
    CHECK(got->entries[42].meta == m.entries[42].meta);
}

TEST(control_relay_messages_roundtrip) {
    RelayToken tok{};
    tok.fill(0x5C);

    RelayAlloc ra{dev_of(1), dev_of(2), RelayKind::Udp};
    auto a = roundtrip(MsgType::RelayAlloc, ra,
                       [](Reader& r, const Header&) { return RelayAlloc::decode(r); });
    REQUIRE(a.has_value());
    CHECK(a->kind == RelayKind::Udp);
    CHECK(a->peer_dev == dev_of(2));

    RelayOffer ro{77, tok, RelayKind::Tcp, dev_of(3), topic_of(4)};
    auto o = roundtrip(MsgType::RelayOffer, ro,
                       [](Reader& r, const Header&) { return RelayOffer::decode(r); });
    REQUIRE(o.has_value());
    CHECK_EQ(o->relay_id, 77u);
    CHECK(o->token == tok);
    CHECK(o->from_dev == dev_of(3));
    CHECK(o->topic == topic_of(4));

    RelayJoin rj{77, tok};
    auto j = roundtrip(MsgType::RelayJoin, rj,
                       [](Reader& r, const Header&) { return RelayJoin::decode(r); });
    REQUIRE(j.has_value());
    CHECK(j->token == tok);
}

TEST(control_decoders_reject_hostile_counts_and_kinds) {
    // A candidate count past the cap.
    std::vector<uint8_t> buf(64);
    Writer w{buf};
    w.array(dev_of(1));
    w.u8(static_cast<uint8_t>(kMaxCandidates + 1));
    Reader r{std::span<const uint8_t>(buf.data(), w.size())};
    CHECK(!Update::decode(r).has_value());

    // An unknown relay kind.
    std::vector<uint8_t> buf2(64);
    Writer w2{buf2};
    w2.array(dev_of(1));
    w2.array(dev_of(2));
    w2.u8(9);
    Reader r2{std::span<const uint8_t>(buf2.data(), w2.size())};
    CHECK(!RelayAlloc::decode(r2).has_value());
}

TEST(control_who_am_i_is_never_answered_with_more_than_it_carries) {
    // WhoAmI travels over UDP to a server that has validated nothing, so its
    // answer -- even reporting an IPv6 address -- must not outgrow it.
    auto req = [] {
        std::vector<uint8_t> b(kMaxFrame);
        Writer w{b};
        Header{MsgType::WhoAmI, ctl::kVersion, 0, 1}.encode(w);
        WhoAmI{123}.encode(w);
        b.resize(w.size());
        return b;
    }();
    CHECK_EQ(req.size(), kWhoAmISize);

    WhoAmIOk ok{123, Endpoint{IpAddr{IpAddr::Family::V6, {}}, 65535}};
    auto rep = message(MsgType::WhoAmIOk, 1, ok);
    CHECK(rep.size() <= req.size());

    // UdpRelayBind likewise.
    auto bind = message(MsgType::UdpRelayBind, 1, UdpRelayBind{5, RelayToken{}});
    auto bok  = message(MsgType::UdpRelayBindOk, 1, UdpRelayBindOk{5});
    CHECK(bok.size() <= bind.size());
}
