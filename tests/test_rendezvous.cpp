// The v2 rendezvous server end to end over loopback: control connections,
// introductions, TCP and UDP relays. Clients here speak the control protocol
// by hand, so every byte on the wire is the test's own.

#include <atomic>
#include <mutex>
#include <thread>

#include "control.hpp"
#include "rendezvous.hpp"
#include "testing.hpp"

using namespace uconnect;
using namespace uconnect::server;
using namespace std::chrono_literals;
namespace ctl = wire::ctl;
using wire::MsgType;

namespace {

// A Rendezvous on its own thread. Queries take the same lock as the loop.
class Server {
public:
    explicit Server(RendezvousConfig cfg = {}) : r_(adjust(std::move(cfg))) {
        if (!r_.open()) throw std::runtime_error(r_.error());
        thread_ = std::thread([this] {
            while (!stop_) {
                std::lock_guard<std::mutex> lk(mu_);
                r_.poll_once(5ms);
            }
        });
    }
    ~Server() {
        stop_ = true;
        thread_.join();
    }
    uint16_t port() const { return r_.port(); }
    Endpoint addr() const { return Endpoint{IpAddr::v4(127, 0, 0, 1), r_.port()}; }
    size_t   records() {
        std::lock_guard<std::mutex> lk(mu_);
        return r_.service().registry().size();
    }

private:
    static RendezvousConfig adjust(RendezvousConfig c) {
        c.port = 0;
        return c;
    }
    Rendezvous        r_;
    std::mutex        mu_;
    std::atomic<bool> stop_{false};
    std::thread       thread_;
};

// One TCP connection speaking framed control messages.
class Client {
public:
    explicit Client(const Server& s) {
        REQUIRE_OK(sock_.open(0));
        REQUIRE_OK(sock_.connect(s.addr()));
        const auto deadline = std::chrono::steady_clock::now() + 2s;
        while (sock_.state() == io::TcpSocket::State::Connecting &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(2ms);
        }
    }

    uint16_t local_port() const { return sock_.local_port(); }

    void send(std::span<const uint8_t> msg) { send_raw(ctl::frame(msg)); }

    void send_raw(std::span<const uint8_t> bytes) {
        while (!bytes.empty()) {
            auto n = sock_.send(bytes);
            if (!n) return;
            bytes = bytes.subspan(*n);
            if (*n == 0) std::this_thread::sleep_for(1ms);
        }
    }

    // The next message of type `want`, skipping others, or nullopt.
    std::optional<std::vector<uint8_t>> expect(MsgType want, std::chrono::milliseconds t = 2s) {
        const auto deadline = std::chrono::steady_clock::now() + t;
        while (std::chrono::steady_clock::now() < deadline) {
            while (auto m = reader_.next()) {
                if (wire::peek_type(*m) == want) return m;
            }
            if (!pump()) return std::nullopt;
        }
        return std::nullopt;
    }

    // Raw bytes after a relay's handshake.
    std::string read_raw(size_t n, std::chrono::milliseconds t = 2s) {
        std::string out;
        auto rest = reader_.take_rest();
        out.append(rest.begin(), rest.end());
        const auto deadline = std::chrono::steady_clock::now() + t;
        std::vector<uint8_t> buf(4096);
        while (out.size() < n && std::chrono::steady_clock::now() < deadline) {
            auto got = sock_.recv(buf);
            if (!got) break;
            if (*got == 0) {
                std::this_thread::sleep_for(2ms);
                continue;
            }
            out.append(reinterpret_cast<const char*>(buf.data()), *got);
        }
        return out;
    }

    // True once the server has closed the connection.
    bool closed_within(std::chrono::milliseconds t) {
        const auto deadline = std::chrono::steady_clock::now() + t;
        std::vector<uint8_t> buf(4096);
        while (std::chrono::steady_clock::now() < deadline) {
            auto got = sock_.recv(buf);
            if (!got) return true;
            if (*got == 0) std::this_thread::sleep_for(5ms);
        }
        return false;
    }

    void close() { sock_.close(); }

private:
    static void REQUIRE_OK(bool ok) {
        if (!ok) throw std::runtime_error("client setup failed");
    }
    bool pump() {
        std::vector<uint8_t> buf(4096);
        auto                 got = sock_.recv(buf);
        if (!got) return false;
        if (*got == 0) {
            std::this_thread::sleep_for(2ms);
            return true;
        }
        reader_.feed(std::span(buf).first(*got));
        return true;
    }

    io::TcpSocket          sock_;
    ctl::FrameReader       reader_;
};

TopicId topic_of(uint8_t f) { TopicId t{}; t.fill(f); return t; }

template <typename T, typename Decode>
std::optional<T> decode(const std::optional<std::vector<uint8_t>>& m, Decode d) {
    if (!m) return std::nullopt;
    wire::Reader r{*m};
    auto         h = wire::Header::decode(r, ctl::kVersion);
    if (!h) return std::nullopt;
    return d(r);
}

ctl::RegisterOk register_in(Client& c, TopicId topic) {
    ctl::Register m;
    m.id   = topic;
    m.mode = TopicMode::Keyed;
    c.send(ctl::message(MsgType::Register, 1, m));
    auto ok = decode<ctl::RegisterOk>(c.expect(MsgType::RegisterOk),
                                      [](wire::Reader& r) { return ctl::RegisterOk::decode(r); });
    if (!ok) throw std::runtime_error("no RegisterOk");
    return *ok;
}

size_t lookup_count(Client& c, TopicId topic) {
    ctl::Lookup l;
    l.id = topic;
    c.send(ctl::message(MsgType::Lookup, 2, l));
    auto ok = decode<ctl::LookupOk>(c.expect(MsgType::LookupOk),
                                    [](wire::Reader& r) { return ctl::LookupOk::decode(r); });
    return ok ? ok->entries.size() : 999;
}

}  // namespace

TEST(rendezvous_registers_over_tcp_and_reports_the_observed_address) {
    Server s;
    Client a{s};
    auto   ok = register_in(a, topic_of(1));
    // The server reports the TCP address it sees -- on loopback, the client's
    // own port. That is the address peers will be told to dial.
    CHECK_EQ(ok.srflx.port, a.local_port());
    CHECK_EQ(s.records(), 1u);
}

TEST(rendezvous_an_empty_keepalive_holds_a_connection_with_nothing_registered) {
    // A node that has published nothing still keeps its control connection:
    // it is how the server reaches it. An empty Keepalive refreshes the
    // connection alone and reports the address it came from.
    Server s;
    Client a{s};
    a.send(ctl::empty_message(MsgType::Keepalive, 3));
    auto ok = decode<ctl::KeepaliveOk>(a.expect(MsgType::KeepaliveOk),
                                       [](wire::Reader& r) { return ctl::KeepaliveOk::decode(r); });
    REQUIRE(ok.has_value());
    CHECK_EQ(ok->srflx.port, a.local_port());
    CHECK(!a.closed_within(300ms));
    CHECK_EQ(s.records(), 0u);
}

TEST(rendezvous_a_record_disappears_when_its_connection_closes) {
    Server s;
    Client a{s}, b{s};
    register_in(a, topic_of(1));
    CHECK_EQ(lookup_count(b, topic_of(1)), 1u);

    a.close();
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (s.records() != 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(10ms);
    }
    CHECK_EQ(s.records(), 0u);
    CHECK_EQ(lookup_count(b, topic_of(1)), 0u);
}

TEST(rendezvous_a_silent_connection_is_closed_after_the_idle_timeout) {
    RendezvousConfig cfg;
    cfg.idle_timeout = 1s;
    Server s{cfg};
    Client a{s};
    register_in(a, topic_of(1));
    CHECK(a.closed_within(3s));
    CHECK_EQ(s.records(), 0u);
}

TEST(rendezvous_connect_is_delivered_on_the_targets_own_connection) {
    Server s;
    Client a{s}, b{s};
    auto   ra = register_in(a, topic_of(1));
    auto   rb = register_in(b, topic_of(1));

    ctl::Connect c;
    c.from_dev = ra.dev_id;
    c.to_dev   = rb.dev_id;
    c.payload  = {1, 2, 3};
    a.send(ctl::message(MsgType::Connect, 3, c));

    auto rel = decode<wire::Relayed>(b.expect(MsgType::Relayed),
                                     [](wire::Reader& r) { return wire::Relayed::decode(r); });
    REQUIRE(rel.has_value());
    CHECK(rel->from_dev == ra.dev_id);
    CHECK(rel->payload == std::vector<uint8_t>({1, 2, 3}));
}

TEST(rendezvous_a_tcp_relay_splices_two_joined_connections) {
    Server s;
    Client a{s}, b{s};
    auto   ra = register_in(a, topic_of(1));
    auto   rb = register_in(b, topic_of(1));

    a.send(ctl::message(MsgType::RelayAlloc, 4,
                        ctl::RelayAlloc{ra.dev_id, rb.dev_id, ctl::RelayKind::Tcp}));
    auto grant = decode<ctl::RelayAllocOk>(a.expect(MsgType::RelayAllocOk), [](wire::Reader& r) {
        return ctl::RelayAllocOk::decode(r);
    });
    auto offer = decode<ctl::RelayOffer>(b.expect(MsgType::RelayOffer), [](wire::Reader& r) {
        return ctl::RelayOffer::decode(r);
    });
    REQUIRE(grant.has_value());
    REQUIRE(offer.has_value());
    CHECK_EQ(offer->relay_id, grant->relay_id);
    CHECK(offer->from_dev == ra.dev_id);

    // Each side opens its own relay connection with its own token.
    Client la{s}, lb{s};
    la.send(ctl::message(MsgType::RelayJoin, 0, ctl::RelayJoin{grant->relay_id, grant->token}));
    lb.send(ctl::message(MsgType::RelayJoin, 0, ctl::RelayJoin{offer->relay_id, offer->token}));
    REQUIRE(la.expect(MsgType::RelayJoinOk).has_value());
    REQUIRE(lb.expect(MsgType::RelayJoinOk).has_value());

    // Raw bytes both ways.
    const std::string hello = "hello over the relay";
    la.send_raw(std::span(reinterpret_cast<const uint8_t*>(hello.data()), hello.size()));
    CHECK(lb.read_raw(hello.size()) == hello);
    const std::string back = "and back";
    lb.send_raw(std::span(reinterpret_cast<const uint8_t*>(back.data()), back.size()));
    CHECK(la.read_raw(back.size()) == back);

    // One leg closing ends the other.
    la.close();
    CHECK(lb.closed_within(2s));
}

TEST(rendezvous_a_spliced_pair_silent_both_ways_is_closed) {
    // #71. Nothing else ends a splice whose two nodes vanished without closing
    // -- it held its legs and their connection slots forever. A pair that
    // carries anything, either way, stays; on the loop and on a worker alike.
    for (size_t threads : {size_t{1}, size_t{2}}) {
        RendezvousConfig cfg;
        cfg.relay_idle_timeout = 1s;
        cfg.threads            = threads;
        Server s{cfg};
        Client a{s}, b{s};
        auto   ra = register_in(a, topic_of(1));
        auto   rb = register_in(b, topic_of(1));
        a.send(ctl::message(MsgType::RelayAlloc, 4,
                            ctl::RelayAlloc{ra.dev_id, rb.dev_id, ctl::RelayKind::Tcp}));
        auto grant = decode<ctl::RelayAllocOk>(a.expect(MsgType::RelayAllocOk),
            [](wire::Reader& r) { return ctl::RelayAllocOk::decode(r); });
        auto offer = decode<ctl::RelayOffer>(b.expect(MsgType::RelayOffer),
            [](wire::Reader& r) { return ctl::RelayOffer::decode(r); });
        REQUIRE(grant.has_value());
        REQUIRE(offer.has_value());
        Client la{s}, lb{s};
        la.send(ctl::message(MsgType::RelayJoin, 0, ctl::RelayJoin{grant->relay_id, grant->token}));
        lb.send(ctl::message(MsgType::RelayJoin, 0, ctl::RelayJoin{offer->relay_id, offer->token}));
        REQUIRE(la.expect(MsgType::RelayJoinOk).has_value());
        REQUIRE(lb.expect(MsgType::RelayJoinOk).has_value());

        // Traffic one way only, for well past the timeout: the pair stays.
        const std::string tick = "tick";
        for (int i = 0; i < 8; ++i) {
            la.send_raw(std::span(reinterpret_cast<const uint8_t*>(tick.data()), tick.size()));
            CHECK(lb.read_raw(tick.size(), 1s) == tick);
            std::this_thread::sleep_for(300ms);
        }

        // Then nothing either way: both legs go.
        CHECK(la.closed_within(4s));
        CHECK(lb.closed_within(4s));
    }
}

TEST(rendezvous_a_relay_join_with_the_wrong_token_is_refused) {
    Server s;
    Client a{s}, b{s};
    auto   ra = register_in(a, topic_of(1));
    auto   rb = register_in(b, topic_of(1));
    a.send(ctl::message(MsgType::RelayAlloc, 4,
                        ctl::RelayAlloc{ra.dev_id, rb.dev_id, ctl::RelayKind::Tcp}));
    auto grant = decode<ctl::RelayAllocOk>(a.expect(MsgType::RelayAllocOk), [](wire::Reader& r) {
        return ctl::RelayAllocOk::decode(r);
    });
    REQUIRE(grant.has_value());

    Client intruder{s};
    intruder.send(ctl::message(MsgType::RelayJoin, 0,
                               ctl::RelayJoin{grant->relay_id, ctl::RelayToken{}}));
    CHECK(intruder.closed_within(2s));
}

TEST(rendezvous_waiting_relay_bounds_early_input) {
    // #39: exercise both data coalesced with RelayJoin and later socket reads.
    for (bool coalesced : {false, true}) {
        RendezvousConfig cfg;
        cfg.splice_buffer = 4096;
        Server s{cfg};
        Client a{s}, b{s};
        auto ra = register_in(a, topic_of(1));
        auto rb = register_in(b, topic_of(1));
        a.send(ctl::message(MsgType::RelayAlloc, 4,
                            ctl::RelayAlloc{ra.dev_id, rb.dev_id, ctl::RelayKind::Tcp}));
        auto grant = decode<ctl::RelayAllocOk>(a.expect(MsgType::RelayAllocOk),
            [](wire::Reader& r) { return ctl::RelayAllocOk::decode(r); });
        REQUIRE(grant.has_value());
        Client leg{s};
        auto join = ctl::frame(ctl::message(MsgType::RelayJoin, 0,
                                           ctl::RelayJoin{grant->relay_id, grant->token}));
        std::vector<uint8_t> early(cfg.splice_buffer + 1, 0);
        if (coalesced) {
            join.insert(join.end(), early.begin(), early.end());
            leg.send_raw(join);
        } else {
            leg.send_raw(join);
            CHECK(!leg.closed_within(50ms));
            leg.send_raw(early);
        }
        CHECK(leg.closed_within(500ms));
        // Rejecting a relay leg must not destroy its owner's control record.
        CHECK_EQ(lookup_count(a, topic_of(1)), 2u);
    }
}

TEST(rendezvous_waiting_relay_preserves_bounded_raw_input) {
    RendezvousConfig cfg;
    cfg.splice_buffer = 4096;
    Server s{cfg};
    Client a{s}, b{s};
    auto ra = register_in(a, topic_of(1));
    auto rb = register_in(b, topic_of(1));
    a.send(ctl::message(MsgType::RelayAlloc, 4,
                        ctl::RelayAlloc{ra.dev_id, rb.dev_id, ctl::RelayKind::Tcp}));
    auto grant = decode<ctl::RelayAllocOk>(a.expect(MsgType::RelayAllocOk),
        [](wire::Reader& r) { return ctl::RelayAllocOk::decode(r); });
    auto offer = decode<ctl::RelayOffer>(b.expect(MsgType::RelayOffer),
        [](wire::Reader& r) { return ctl::RelayOffer::decode(r); });
    REQUIRE(grant.has_value()); REQUIRE(offer.has_value());
    Client la{s}, lb{s};
    auto join = ctl::frame(ctl::message(MsgType::RelayJoin, 0,
                                       ctl::RelayJoin{grant->relay_id, grant->token}));
    // Raw relay data is not another control frame, even when it starts ff ff.
    std::string early(cfg.splice_buffer, static_cast<char>(0xff));
    join.insert(join.end(), early.begin(), early.end());
    la.send_raw(join);
    CHECK(!la.closed_within(50ms));
    lb.send(ctl::message(MsgType::RelayJoin, 0, ctl::RelayJoin{offer->relay_id, offer->token}));
    REQUIRE(la.expect(MsgType::RelayJoinOk).has_value());
    REQUIRE(lb.expect(MsgType::RelayJoinOk).has_value());
    CHECK(lb.read_raw(early.size()) == early);
}

TEST(rendezvous_a_tcp_relay_stops_when_its_budget_is_spent) {
    RendezvousConfig cfg;
    cfg.registry.relay_max_bytes = 4096;
    Server s{cfg};
    Client a{s}, b{s};
    auto   ra = register_in(a, topic_of(1));
    auto   rb = register_in(b, topic_of(1));
    a.send(ctl::message(MsgType::RelayAlloc, 4,
                        ctl::RelayAlloc{ra.dev_id, rb.dev_id, ctl::RelayKind::Tcp}));
    auto grant = decode<ctl::RelayAllocOk>(a.expect(MsgType::RelayAllocOk), [](wire::Reader& r) {
        return ctl::RelayAllocOk::decode(r);
    });
    auto offer = decode<ctl::RelayOffer>(b.expect(MsgType::RelayOffer), [](wire::Reader& r) {
        return ctl::RelayOffer::decode(r);
    });
    REQUIRE(grant.has_value());
    REQUIRE(offer.has_value());
    Client la{s}, lb{s};
    la.send(ctl::message(MsgType::RelayJoin, 0, ctl::RelayJoin{grant->relay_id, grant->token}));
    lb.send(ctl::message(MsgType::RelayJoin, 0, ctl::RelayJoin{offer->relay_id, offer->token}));
    REQUIRE(la.expect(MsgType::RelayJoinOk).has_value());
    REQUIRE(lb.expect(MsgType::RelayJoinOk).has_value());

    std::vector<uint8_t> big(10000, 0x42);
    la.send_raw(big);
    CHECK(lb.closed_within(3s));
}

TEST(rendezvous_who_am_i_reports_the_udp_mapping_and_never_amplifies) {
    Server        s;
    io::UdpSocket u;
    REQUIRE(u.open(0));

    auto send_who = [&](size_t size) {
        std::vector<uint8_t> d(128);
        wire::Writer         w{d};
        wire::Header{MsgType::WhoAmI, ctl::kVersion, 0, 9}.encode(w);
        ctl::WhoAmI{77}.encode(w);
        d.resize(std::min(size, w.size()));
        u.send_to(s.addr(), d);
    };
    auto recv_one = [&](std::chrono::milliseconds t) -> std::optional<std::vector<uint8_t>> {
        std::vector<uint8_t> buf(2048);
        if (!u.wait_readable(t)) return std::nullopt;
        auto got = u.recv_from(buf);
        if (!got) return std::nullopt;
        buf.resize(got->len);
        return buf;
    };

    send_who(ctl::kWhoAmISize);
    auto rep = recv_one(2s);
    REQUIRE(rep.has_value());
    wire::Reader r{*rep};
    REQUIRE(wire::Header::decode(r, ctl::kVersion).has_value());
    auto ok = ctl::WhoAmIOk::decode(r);
    REQUIRE(ok.has_value());
    CHECK_EQ(ok->nonce, 77u);
    CHECK_EQ(ok->mapped.port, u.local_port());
    CHECK(rep->size() <= ctl::kWhoAmISize);

    // Unpadded, it is not answered at all.
    send_who(wire::Header::kSize + 8);
    CHECK(!recv_one(300ms).has_value());
}

TEST(rendezvous_a_udp_relay_forwards_between_bound_sockets) {
    Server s;
    Client a{s}, b{s};
    auto   ra = register_in(a, topic_of(1));
    auto   rb = register_in(b, topic_of(1));
    a.send(ctl::message(MsgType::RelayAlloc, 4,
                        ctl::RelayAlloc{ra.dev_id, rb.dev_id, ctl::RelayKind::Udp}));
    auto grant = decode<ctl::RelayAllocOk>(a.expect(MsgType::RelayAllocOk), [](wire::Reader& r) {
        return ctl::RelayAllocOk::decode(r);
    });
    auto offer = decode<ctl::RelayOffer>(b.expect(MsgType::RelayOffer), [](wire::Reader& r) {
        return ctl::RelayOffer::decode(r);
    });
    REQUIRE(grant.has_value());
    REQUIRE(offer.has_value());

    io::UdpSocket ua, ub;
    REQUIRE(ua.open(0));
    REQUIRE(ub.open(0));
    auto bind = [&](io::UdpSocket& u, const ctl::RelayToken& tok) {
        u.send_to(s.addr(), ctl::message(MsgType::UdpRelayBind, 1,
                                         ctl::UdpRelayBind{grant->relay_id, tok}));
        std::vector<uint8_t> buf(256);
        return u.wait_readable(2s) && u.recv_from(buf).has_value();
    };
    REQUIRE(bind(ua, grant->token));
    REQUIRE(bind(ub, offer->token));

    wire::RelayData rd;
    rd.relay_id = grant->relay_id;
    rd.payload  = {9, 9, 9};
    ua.send_to(s.addr(), ctl::message(MsgType::RelayData, 0, rd));
    std::vector<uint8_t> buf(2048);
    REQUIRE(ub.wait_readable(2s));
    auto got = ub.recv_from(buf);
    REQUIRE(got.has_value());
    wire::Reader r{std::span<const uint8_t>(buf.data(), got->len)};
    REQUIRE(wire::Header::decode(r, ctl::kVersion).has_value());
    auto fwd = wire::RelayData::decode(r);
    REQUIRE(fwd.has_value());
    CHECK(fwd->payload == rd.payload);
}
