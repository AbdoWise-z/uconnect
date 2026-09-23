// uconn-stream -- exercise the reliable stream layer over a real network.
//
//   uconn-stream --server <host:port> --topic <uri> --send 1048576
//   uconn-stream --server <host:port> --topic <uri> --recv
//
// The sender opens a stream, writes N bytes of a known pattern and finishes.
// The receiver reads until FIN and verifies every byte, in order. That is the
// whole point of the layer: the session underneath loses and reorders, and the
// application must not be able to tell.

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
}

int main(int argc, char** argv) {
    std::string server, topic_uri;
    size_t      to_send = 0;
    bool        recv        = false;
    bool        force_relay = false;
    bool        verbose     = false;
    int         seconds = 40;

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
    }
    if (server.empty() || topic_uri.empty()) {
        std::fprintf(stderr, "need --server and --topic\n");
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
    std::atomic<bool>   bad{false};
    std::atomic<bool>   done{false};

    // Read on the loop thread as bytes become available, verifying as we go.
    topic.on_stream_readable([&](Stream s) {
        std::vector<uint8_t> buf(64 * 1024);
        for (;;) {
            size_t n = s.read(buf);
            if (n == 0) break;
            for (size_t i = 0; i < n; ++i) {
                if (buf[i] != pat(got + i)) bad = true;
            }
            got += n;
        }
        if (s.finished()) done = true;
    });
    topic.on_stream_finished([&](Stream) { done = true; });

    // Let the library discover and connect to peers on its own interval,
    // instead of polling peers() from the loop below.
    topic.set_auto_connect(true);

    if (!topic.publish()) { std::fprintf(stderr, "publish failed\n"); return 1; }
    std::printf("[%s] published\n", recv ? "recv" : "send");
    std::fflush(stdout);

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    Stream out;
    size_t sent = 0;
    std::vector<uint8_t> chunk(32 * 1024);

    while (std::chrono::steady_clock::now() < deadline && !done) {
        // No discovery loop here: set_auto_connect(true) below makes the
        // library do it, on its own interval. Polling peers() by hand is what
        // this example used to do, and at a 20ms tick it produced well over a
        // thousand lookups in ten seconds.

        if (to_send > 0) {
            auto conn = topic.connected();
            if (!out && !conn.empty()) {
                out = topic.open_stream(conn.front());
                if (out) std::printf("[send] stream %llu opened\n",
                                     (unsigned long long)out.id());
            }
            if (out) {
                while (sent < to_send) {
                    size_t want = std::min(chunk.size(), to_send - sent);
                    for (size_t i = 0; i < want; ++i) chunk[i] = pat(sent + i);
                    size_t n = out.write(std::span(chunk).first(want));
                    if (n == 0) break;   // backpressure; try again next tick
                    sent += n;
                }
                if (sent >= to_send) {
                    out.finish();
                    std::printf("[send] wrote %zu bytes, finished\n", sent);
                    std::fflush(stdout);
                    break;
                }
            }
        }
        std::this_thread::sleep_for(20ms);
    }

    // Let the tail drain / acks settle.
    // Drain the tail.
    //
    // The receiver waits until the stream finishes, bounded by the deadline: a
    // relayed transfer moves more slowly than a direct one, so a short fixed
    // window would report a still-arriving transfer as a failure.
    //
    // The sender only needs long enough to flush and see the acks. Letting it
    // wait on the same condition meant it sat out the entire deadline, since
    // `done` is only ever set on the receiving side.
    const auto until = recv ? deadline : std::chrono::steady_clock::now() + 20s;
    while (std::chrono::steady_clock::now() < until) {
        if (recv && done) break;
        std::this_thread::sleep_for(50ms);
    }

    // What the path actually looked like. `relayed` is the one worth reading
    // closely: the transfer is still end-to-end encrypted either way, but a
    // relayed one went through the rendezvous server.
    for (const auto& dev : topic.connected()) {
        if (auto li = topic.link(dev)) {
            std::printf("[link] %s rtt=%lldms cwnd=%zu inflight=%zu %s "
                        "pkts=%llu lost=%llu dgrams=%llu/%llu streams=%zu\n",
                        li->relayed ? "relayed" : "direct",
                        (long long)li->rtt.count(), li->congestion_window,
                        li->bytes_in_flight, li->slow_start ? "slow-start" : "avoid",
                        (unsigned long long)li->packets_sent,
                        (unsigned long long)li->packets_lost,
                        (unsigned long long)li->datagrams_sent,
                        (unsigned long long)li->datagrams_received,
                        li->open_streams);
        }
    }

    if (recv) {
        std::printf("[recv] %zu bytes, verified=%s, fin=%s\n", got.load(),
                    bad ? "NO" : "yes", done ? "yes" : "no");
    } else {
        std::printf("[send] done (%zu bytes)\n", sent);
    }
    node.shutdown();
    if (recv) return (got > 0 && !bad) ? 0 : 1;
    return sent == to_send ? 0 : 1;
}
