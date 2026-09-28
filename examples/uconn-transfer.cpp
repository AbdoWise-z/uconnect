// uconn-transfer -- move a large payload between two peers as messages, and
// optionally a burst of datagrams.
//
//   uconn-transfer --server <host:port> --topic <uri> --send 1048576 [--dgrams 500]
//   uconn-transfer --server <host:port> --topic <uri> --recv
//
// The sender splits N bytes of a known pattern into messages and follows them
// with an empty one to mark the end; the receiver verifies every byte, in
// order, and acknowledges. With --dgrams the sender then opens a datagram
// channel, sends that many datagrams, and asks how many arrived -- they are
// unreliable, so the answer may be short. Finally it says "bye" and both exit.
//
// --relay on both sides forces every path through the rendezvous server; with
// it, --dgram-fallback relay|tcp|none decides where the datagrams go.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "uconnect/uconnect.hpp"

using namespace uconnect;
using namespace std::chrono_literals;

namespace {
uint8_t pat(size_t i) { return static_cast<uint8_t>((i * 31 + 7) & 0xFF); }
constexpr size_t kChunk = 64 * 1024;

std::span<const uint8_t> as_bytes(const std::string& s) {
    return std::span(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

bool parse_fallback(const std::string& s, DatagramFallback& out) {
    if (s == "tcp") out = DatagramFallback::Tcp;
    else if (s == "relay") out = DatagramFallback::Relay;
    else if (s == "none") out = DatagramFallback::None;
    else return false;
    return true;
}
}  // namespace

int main(int argc, char** argv) {
    std::string      server, topic_uri;
    size_t           to_send     = 0;
    size_t           dgrams      = 0;
    bool             recv        = false;
    bool             force_relay = false;
    bool             verbose     = false;
    int              seconds     = 40;
    DatagramFallback fallback    = DatagramFallback::Tcp;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](int& idx) -> const char* { return idx + 1 < argc ? argv[++idx] : nullptr; };
        if (a == "--server") { if (auto* v = next(i)) server = v; }
        else if (a == "--topic") { if (auto* v = next(i)) topic_uri = v; }
        else if (a == "--send") { if (auto* v = next(i)) to_send = static_cast<size_t>(std::atoll(v)); }
        else if (a == "--dgrams") { if (auto* v = next(i)) dgrams = static_cast<size_t>(std::atoll(v)); }
        else if (a == "--dgram-fallback") {
            auto* v = next(i);
            if (!v || !parse_fallback(v, fallback)) {
                std::fprintf(stderr, "--dgram-fallback takes tcp, relay or none\n");
                return 2;
            }
        }
        else if (a == "--recv") recv = true;
        else if (a == "--relay") force_relay = true;
        else if (a == "--verbose") verbose = true;
        else if (a == "--seconds") { if (auto* v = next(i)) seconds = std::atoi(v); }
        else { std::fprintf(stderr, "unknown option: %s\n", a.c_str()); return 2; }
    }
    if (server.empty() || topic_uri.empty() || (!recv && to_send == 0 && dgrams == 0)) {
        std::fprintf(stderr, "need --server, --topic and one of --send/--dgrams or --recv\n");
        return 2;
    }

    auto creds = TopicCreds::parse(topic_uri);
    if (!creds) { std::fprintf(stderr, "bad topic\n"); return 2; }

    Node::Config cfg;
    cfg.server            = server;
    cfg.force_relay       = force_relay;
    cfg.verbose           = verbose;
    cfg.datagram_fallback = fallback;
    Node node{cfg};
    node.run_in_background();
    auto& topic = node.join(*creds);

    // Receiver state.
    std::atomic<size_t> got{0};
    std::atomic<size_t> messages{0};
    std::atomic<bool>   bad{false};
    std::atomic<bool>   end_seen{false};
    std::atomic<bool>   bye{false};
    std::mutex          seen_mu;
    std::set<uint32_t>  seen;  // datagram sequence numbers, duplicates ignored

    // Sender state.
    std::atomic<bool>    acked{false};
    std::atomic<int64_t> reported{-1};

    topic.on_data([&](DevId dev, std::span<const uint8_t> data) {
        const std::string text(data.begin(), data.end());
        if (!recv) {
            if (text == "ok") acked = true;
            else if (text.rfind("dgrams ", 0) == 0) reported = std::atoll(text.c_str() + 7);
            return;
        }
        if (data.empty()) {
            end_seen = true;
            topic.send(dev, as_bytes("ok"));
        } else if (text == "dgrams-done") {
            std::lock_guard<std::mutex> lk(seen_mu);
            topic.send(dev, as_bytes("dgrams " + std::to_string(seen.size())));
        } else if (text == "bye") {
            bye = true;
        } else {
            for (size_t i = 0; i < data.size(); ++i) {
                if (data[i] != pat(got + i)) bad = true;
            }
            got += data.size();
            ++messages;
        }
    });
    topic.on_datagram([&](DevId, std::span<const uint8_t> d) {
        if (d.size() < 4) return;
        const uint32_t n = static_cast<uint32_t>(d[0]) << 24 | static_cast<uint32_t>(d[1]) << 16 |
                           static_cast<uint32_t>(d[2]) << 8 | d[3];
        std::lock_guard<std::mutex> lk(seen_mu);
        seen.insert(n);
    });

    // The library discovers and connects to peers on its own interval.
    topic.set_auto_connect(true);

    if (!topic.publish()) { std::fprintf(stderr, "publish failed\n"); return 1; }
    std::printf("[%s] published\n", recv ? "recv" : "send");
    std::fflush(stdout);

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    auto       before   = [&] { return std::chrono::steady_clock::now() < deadline; };
    size_t     sent     = 0;
    size_t     dgrams_sent = 0;
    DatagramPath dpath  = DatagramPath::None;
    std::optional<DevId> to;

    if (recv) {
        while (before() && !bye) std::this_thread::sleep_for(20ms);
    } else {
        while (before() && !to) {
            auto conn = topic.connected();
            if (!conn.empty()) to = conn.front();
            else std::this_thread::sleep_for(20ms);
        }
        if (to && to_send > 0) {
            std::vector<uint8_t> chunk(kChunk);
            while (sent < to_send) {
                const size_t want = std::min(chunk.size(), to_send - sent);
                for (size_t i = 0; i < want; ++i) chunk[i] = pat(sent + i);
                if (!topic.send(*to, std::span(chunk).first(want))) break;
                sent += want;
            }
            topic.send(*to, {});  // the end marker
            std::printf("[send] queued %zu bytes\n", sent);
            std::fflush(stdout);
            while (before() && !acked) std::this_thread::sleep_for(20ms);
        }
        if (to && dgrams > 0) {
            topic.open_datagrams(*to, fallback);
            while (before() && topic.datagram_path(*to) == DatagramPath::Opening) {
                std::this_thread::sleep_for(20ms);
            }
            dpath = topic.datagram_path(*to);
            std::vector<uint8_t> d(1000);
            for (uint32_t n = 0; n < dgrams; ++n) {
                d[0] = static_cast<uint8_t>(n >> 24);
                d[1] = static_cast<uint8_t>(n >> 16);
                d[2] = static_cast<uint8_t>(n >> 8);
                d[3] = static_cast<uint8_t>(n);
                if (topic.send_datagram(*to, d)) ++dgrams_sent;
                // Paced: a burst faster than the path can carry is lost
                // wholesale, which tests the network rather than the library.
                if (n % 10 == 9) std::this_thread::sleep_for(2ms);
            }
            std::this_thread::sleep_for(300ms);  // the tail, in flight
            topic.send(*to, as_bytes("dgrams-done"));
            while (before() && reported < 0) std::this_thread::sleep_for(20ms);
        }
        if (to) topic.send(*to, as_bytes("bye"));
    }

    // What the path looked like. The transfer is end-to-end encrypted either
    // way, but a relayed one went through the rendezvous server.
    for (const auto& dev : topic.connected()) {
        if (auto li = topic.link(dev)) {
            std::printf("[link] %s msgs=%llu/%llu bytes=%llu/%llu dgrams=%llu/%llu\n",
                        li->relayed ? "relayed" : "direct",
                        (unsigned long long)li->messages_sent,
                        (unsigned long long)li->messages_received,
                        (unsigned long long)li->bytes_sent,
                        (unsigned long long)li->bytes_received,
                        (unsigned long long)li->datagrams_sent,
                        (unsigned long long)li->datagrams_received);
        }
    }

    int rc = 0;
    if (recv) {
        size_t n_seen = 0;
        {
            std::lock_guard<std::mutex> lk(seen_mu);
            n_seen = seen.size();
        }
        std::printf("[recv] %zu bytes in %zu messages, verified=%s, end=%s, datagrams=%zu\n",
                    got.load(), messages.load(), bad ? "NO" : "yes", end_seen ? "yes" : "no",
                    n_seen);
        rc = (bye && !bad) ? 0 : 1;
        // Leave the last replies time to reach the wire before the close does.
        std::this_thread::sleep_for(500ms);
    } else {
        if (to_send > 0) {
            std::printf("[send] %zu bytes, acked=%s\n", sent, acked ? "yes" : "no");
            if (sent != to_send || !acked) rc = 1;
        }
        if (dgrams > 0) {
            std::printf("[send] datagrams path=%s sent=%zu received=%lld\n", to_string(dpath),
                        dgrams_sent, static_cast<long long>(reported.load()));
            if (reported < 0) rc = 1;
        }
        if (!to) rc = 1;
    }
    std::fflush(stdout);
    node.shutdown();
    return rc;
}
