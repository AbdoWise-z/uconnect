// TCP sockets and polling, over loopback.
//
// The property the whole transport rests on is that one local port can be
// shared: a node listens on it, keeps its rendezvous connection from it, and
// punches from it, because the NAT mapping of that one port is the address
// peers are told. These tests hold the OS to that.

#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include "socket.hpp"
#include "testing.hpp"

using namespace uconnect;
using namespace uconnect::io;
using namespace std::chrono_literals;

namespace {

Endpoint loopback(uint16_t port) { return Endpoint{IpAddr::v4(127, 0, 0, 1), port}; }

// Poll `sock` until it finishes connecting, or give up.
bool wait_connected(TcpSocket& sock, std::chrono::milliseconds timeout = 2s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        auto st = sock.state();
        if (st == TcpSocket::State::Connected) return true;
        if (st == TcpSocket::State::Failed) return false;
        PollItem it;
        it.fd         = sock.native();
        it.want_write = true;
        poll(std::span(&it, 1), 20ms);
    }
    return false;
}

std::optional<TcpSocket> wait_accept(TcpSocket& listener, std::chrono::milliseconds timeout = 2s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (auto s = listener.accept()) return s;
        PollItem it;
        it.fd        = listener.native();
        it.want_read = true;
        poll(std::span(&it, 1), 20ms);
    }
    return std::nullopt;
}

// Read exactly `n` bytes, polling as needed.
std::string read_n(TcpSocket& s, size_t n, std::chrono::milliseconds timeout = 2s) {
    std::string          out;
    std::vector<uint8_t> buf(4096);
    const auto           deadline = std::chrono::steady_clock::now() + timeout;
    while (out.size() < n && std::chrono::steady_clock::now() < deadline) {
        auto got = s.recv(buf);
        if (!got) break;
        if (*got == 0) {
            PollItem it;
            it.fd        = s.native();
            it.want_read = true;
            poll(std::span(&it, 1), 20ms);
            continue;
        }
        out.append(reinterpret_cast<const char*>(buf.data()), *got);
    }
    return out;
}

bool write_all(TcpSocket& s, std::string_view text) {
    auto bytes = std::span(reinterpret_cast<const uint8_t*>(text.data()), text.size());
    while (!bytes.empty()) {
        auto n = s.send(bytes);
        if (!n) return false;
        bytes = bytes.subspan(*n);
    }
    return true;
}

}  // namespace

TEST(tcp_connects_over_loopback_and_carries_bytes_both_ways) {
    TcpSocket listener;
    REQUIRE(listener.open(0));
    REQUIRE(listener.listen());

    TcpSocket client;
    REQUIRE(client.open(0));
    REQUIRE(client.connect(loopback(listener.local_port())));

    auto server_side = wait_accept(listener);
    REQUIRE(server_side.has_value());
    REQUIRE(wait_connected(client));

    REQUIRE(write_all(client, "ping"));
    CHECK(read_n(*server_side, 4) == "ping");
    REQUIRE(write_all(*server_side, "pong!"));
    CHECK(read_n(client, 5) == "pong!");

    // The accepted side knows who it is talking to.
    auto peer = server_side->remote();
    REQUIRE(peer.has_value());
    CHECK(peer->port == client.local_port());
}

TEST(tcp_a_closed_peer_is_reported_as_the_end_of_the_connection) {
    TcpSocket listener;
    REQUIRE(listener.open(0));
    REQUIRE(listener.listen());
    TcpSocket client;
    REQUIRE(client.open(0));
    REQUIRE(client.connect(loopback(listener.local_port())));
    auto server_side = wait_accept(listener);
    REQUIRE(server_side.has_value());
    REQUIRE(wait_connected(client));

    client.close();
    std::vector<uint8_t> buf(16);
    std::optional<size_t> got = 0;
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (got && *got == 0 && std::chrono::steady_clock::now() < deadline) {
        PollItem it;
        it.fd        = server_side->native();
        it.want_read = true;
        poll(std::span(&it, 1), 20ms);
        got = server_side->recv(buf);
    }
    CHECK(!got.has_value());
}

TEST(tcp_a_listener_and_an_outgoing_connection_share_one_port) {
    // The node's listener and its rendezvous connection live on the same
    // port. If the OS refused the second bind, the address the server sees
    // would not be the one peers can reach.
    TcpSocket remote_listener;
    REQUIRE(remote_listener.open(0));
    REQUIRE(remote_listener.listen());

    TcpSocket own_listener;
    REQUIRE(own_listener.open(0));
    REQUIRE(own_listener.listen());
    const uint16_t shared = own_listener.local_port();

    TcpSocket outgoing;
    REQUIRE(outgoing.open(shared));
    CHECK_EQ(outgoing.local_port(), shared);
    REQUIRE(outgoing.connect(loopback(remote_listener.local_port())));

    auto accepted = wait_accept(remote_listener);
    REQUIRE(accepted.has_value());
    REQUIRE(wait_connected(outgoing));
    auto seen_as = accepted->remote();
    REQUIRE(seen_as.has_value());
    CHECK_EQ(seen_as->port, shared);  // the far side sees the shared port

    // And the listener on that port still takes connections.
    TcpSocket inbound;
    REQUIRE(inbound.open(0));
    REQUIRE(inbound.connect(loopback(shared)));
    CHECK(wait_accept(own_listener).has_value());
}

TEST(tcp_two_sides_dialling_each_other_at_once_get_connected) {
    // A punch: both nodes listen on their shared port and dial the other's
    // from it at the same moment. Whether the OS resolves that as a
    // simultaneous open or one SYN finds the other's listener, the two must
    // end up with one working connection between the two shared ports.
    TcpSocket la, lb;
    REQUIRE(la.open(0));
    REQUIRE(la.listen());
    REQUIRE(lb.open(0));
    REQUIRE(lb.listen());
    const uint16_t pa = la.local_port(), pb = lb.local_port();

    TcpSocket da, db;
    REQUIRE(da.open(pa));
    REQUIRE(db.open(pb));
    da.connect(loopback(pb));
    db.connect(loopback(pa));

    // Gather every connection each side ends up holding.
    std::vector<TcpSocket> side_a, side_b;
    bool da_done = false, db_done = false;
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (std::chrono::steady_clock::now() < deadline && (side_a.empty() || side_b.empty())) {
        if (auto s = la.accept()) side_a.push_back(std::move(*s));
        if (auto s = lb.accept()) side_b.push_back(std::move(*s));
        if (!da_done && da.state() != TcpSocket::State::Connecting) {
            da_done = true;
            if (da.state() == TcpSocket::State::Connected) side_a.push_back(std::move(da));
        }
        if (!db_done && db.state() != TcpSocket::State::Connecting) {
            db_done = true;
            if (db.state() == TcpSocket::State::Connected) side_b.push_back(std::move(db));
        }
        std::this_thread::sleep_for(5ms);
    }
    REQUIRE(!side_a.empty());
    REQUIRE(!side_b.empty());

    // Some connection on A's side reaches some connection on B's side.
    bool linked = false;
    for (auto& a : side_a) {
        if (!write_all(a, "hi")) continue;
        for (auto& b : side_b) {
            if (read_n(b, 2, 300ms) == "hi") linked = true;
        }
    }
    CHECK(linked);
}

TEST(link_local_addresses_are_recognised_in_both_families) {
    IpAddr v6{};
    v6.family = IpAddr::Family::V6;
    v6.bytes  = {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0xED, 0x6A, 0x74, 0xC7, 0x1D, 0xA3, 0x85, 0x1F};
    CHECK(v6.is_link_local());
    CHECK(v6.is_private());
    v6.bytes[1] = 0xBF;  // still inside fe80::/10
    CHECK(v6.is_link_local());
    v6.bytes[1] = 0xC0;  // fec0:: is not
    CHECK(!v6.is_link_local());
    v6.bytes = {0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};  // ULA
    CHECK(!v6.is_link_local());
    CHECK(v6.is_private());

    CHECK(IpAddr::v4(169, 254, 3, 4).is_link_local());
    CHECK(!IpAddr::v4(10, 0, 12, 204).is_link_local());
    CHECK(IpAddr::v4(169, 254, 3, 4).is_private());
}

TEST(host_candidates_never_include_loopback_or_link_local) {
    // A link-local address cannot be dialed without a scope id a candidate
    // does not carry. Advertising one also got every registration reset on a
    // real network whose middlebox resets any flow whose first segment
    // carries an fe80:: address.
    for (const auto& ip : local_addresses()) {
        CHECK(!ip.is_loopback());
        CHECK(!ip.is_link_local());
    }
}

TEST(poll_reports_readiness_for_many_sockets) {
    // More sockets than select() manages on Windows (64).
    //
    // The backlog must hold the whole burst. With 32, Linux accepted 66 of the
    // 80 within the deadline: the overflow's handshakes are completed by
    // retransmission, seconds later -- which on one kernel happened to beat
    // the deadline and on another did not.
    TcpSocket listener;
    REQUIRE(listener.open(0));
    REQUIRE(listener.listen(128));

    std::vector<TcpSocket> clients(80);
    for (auto& c : clients) {
        REQUIRE(c.open(0));
        c.connect(loopback(listener.local_port()));
    }
    std::vector<TcpSocket> accepted;
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (accepted.size() < clients.size() && std::chrono::steady_clock::now() < deadline) {
        if (auto s = listener.accept()) accepted.push_back(std::move(*s));
        else std::this_thread::sleep_for(1ms);
    }
    REQUIRE(accepted.size() == clients.size());

    // One byte to the last client only; poll must find exactly that one.
    REQUIRE(write_all(accepted.back(), "x"));
    std::vector<PollItem> items(clients.size());
    for (size_t i = 0; i < clients.size(); ++i) {
        items[i].fd        = clients[i].native();
        items[i].want_read = true;
    }
    bool seen = false;
    for (int round = 0; round < 50 && !seen; ++round) {
        REQUIRE(poll(items, 50ms));
        for (size_t i = 0; i < items.size(); ++i) {
            if (items[i].readable) {
                // Accept order is not connect order, so check by content.
                std::vector<uint8_t> b(4);
                auto got = clients[i].recv(b);
                if (got && *got == 1) seen = true;
            }
        }
    }
    CHECK(seen);
}
