// uconn-transfer -- move a large payload between two peers as messages.
//
//   uconn-transfer --server <host:port> --topic <uri> --send 1048576
//   uconn-transfer --server <host:port> --topic <uri> --recv
//
// The sender splits N bytes of a known pattern into messages and follows them
// with an empty one to mark the end. The receiver verifies every byte, in
// order, and answers the end marker with an acknowledgement, so the sender
// knows everything arrived before it shuts down. Run with --relay on both
// sides to force the path through the rendezvous server.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#include "uconnect/uconnect.hpp"

using namespace uconnect;
using namespace std::chrono_literals;

namespace {
uint8_t pat(size_t i) { return static_cast<uint8_t>((i * 31 + 7) & 0xFF); }
constexpr size_t kChunk = 64 * 1024;
}  // namespace

int main(int argc, char** argv) {
    std::string server, topic_uri;
    size_t      to_send     = 0;
    bool        recv        = false;
    bool        force_relay = false;
    bool        verbose     = false;
    int         seconds     = 40;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](int& idx) -> const char* { return idx + 1 < argc ? argv[++idx] : nullptr; };
        if (a == "--server") { if (auto* v = next(i)) server = v; }
        else if (a == "--topic") { if (auto* v = next(i)) topic_uri = v; }
        else if (a == "--send") { if (auto* v = next(i)) to_send = static_cast<size_t>(std::atoll(v)); }
        else if (a == "--recv") recv = true;
        else if (a == "--relay") force_relay = true;
        else if (a == "--verbose") verbose = true;
        else if (a == "--seconds") { if (auto* v = next(i)) seconds = std::atoi(v); }
        else { std::fprintf(stderr, "unknown option: %s\n", a.c_str()); return 2; }
    }
    if (server.empty() || topic_uri.empty() || (!recv && to_send == 0)) {
        std::fprintf(stderr, "need --server, --topic and one of --send <bytes> / --recv\n");
        return 2;
    }

    auto creds = TopicCreds::parse(topic_uri);
    if (!creds) { std::fprintf(stderr, "bad topic\n"); return 2; }

    Node::Config cfg;
    cfg.server      = server;
    cfg.force_relay = force_relay;
    cfg.verbose     = verbose;
    Node node{cfg};
    node.run_in_background();
    auto& topic = node.join(*creds);

    std::atomic<size_t> got{0};
    std::atomic<size_t> messages{0};
    std::atomic<bool>   bad{false};
    std::atomic<bool>   done{false};   // receiver: end marker seen
    std::atomic<bool>   acked{false};  // sender: receiver confirmed

    topic.on_data([&](DevId dev, std::span<const uint8_t> data) {
        if (!recv) {
            if (std::string(data.begin(), data.end()) == "ok") acked = true;
            return;
        }
        if (data.empty()) {
            done = true;
            static const std::string ok = "ok";
            topic.send(dev, std::span(reinterpret_cast<const uint8_t*>(ok.data()), ok.size()));
            return;
        }
        for (size_t i = 0; i < data.size(); ++i) {
            if (data[i] != pat(got + i)) bad = true;
        }
        got += data.size();
        ++messages;
    });

    // The library discovers and connects to peers on its own interval.
    topic.set_auto_connect(true);

    if (!topic.publish()) { std::fprintf(stderr, "publish failed\n"); return 1; }
    std::printf("[%s] published\n", recv ? "recv" : "send");
    std::fflush(stdout);

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    size_t     sent     = 0;
    std::optional<DevId> to;
    std::vector<uint8_t> chunk(kChunk);

    while (std::chrono::steady_clock::now() < deadline) {
        if (recv ? done.load() : acked.load()) break;
        if (!recv && !to) {
            auto conn = topic.connected();
            if (!conn.empty()) {
                to = conn.front();
                while (sent < to_send) {
                    const size_t want = std::min(chunk.size(), to_send - sent);
                    for (size_t i = 0; i < want; ++i) chunk[i] = pat(sent + i);
                    if (!topic.send(*to, std::span(chunk).first(want))) break;
                    sent += want;
                }
                topic.send(*to, {});  // the end marker
                std::printf("[send] queued %zu bytes\n", sent);
                std::fflush(stdout);
            }
        }
        std::this_thread::sleep_for(20ms);
    }

    // What the path looked like. The transfer is end-to-end encrypted either
    // way, but a relayed one went through the rendezvous server.
    for (const auto& dev : topic.connected()) {
        if (auto li = topic.link(dev)) {
            std::printf("[link] %s msgs=%llu/%llu bytes=%llu/%llu\n",
                        li->relayed ? "relayed" : "direct",
                        (unsigned long long)li->messages_sent,
                        (unsigned long long)li->messages_received,
                        (unsigned long long)li->bytes_sent,
                        (unsigned long long)li->bytes_received);
        }
    }

    if (recv) {
        std::printf("[recv] %zu bytes in %zu messages, verified=%s, end=%s\n", got.load(),
                    messages.load(), bad ? "NO" : "yes", done ? "yes" : "no");
    } else {
        std::printf("[send] %zu bytes, acked=%s\n", sent, acked ? "yes" : "no");
    }
    std::fflush(stdout);
    // Leave the receiver's ack time to reach the wire before the close does.
    if (recv) std::this_thread::sleep_for(500ms);
    node.shutdown();
    if (recv) return (done && got > 0 && !bad) ? 0 : 1;
    return (sent == to_send && acked) ? 0 : 1;
}
