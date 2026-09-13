// uconnect-rendezvous: the rendezvous server.
//
// Its entire job is to let two peers learn each other's addresses and fire at
// the same moment. It holds no K, cannot read a keyed topic's traffic, and
// cannot impersonate a member. What it knows about a device is a dev_id it
// derived itself, an IP:port, a topic_id, and an opaque blob -- all of which
// expire 90 seconds after the last keepalive.
//
// Entirely in memory. With that expiry there is no database and no persistence:
// a restart just means every live device re-registers within one keepalive.

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <string>

#include "socket.hpp"
#include "udp_service.hpp"

using namespace uconnect;
using namespace std::chrono_literals;

namespace {

std::atomic<bool> g_stop{false};
void on_signal(int) { g_stop = true; }

void usage() {
    std::printf(
        "uconnect-rendezvous -- rendezvous server for uConnect\n"
        "\n"
        "  --port <n>            UDP port to bind (default 4433)\n"
        "  --stale <secs>        freshness window (default 45)\n"
        "  --expiry <secs>       hard record expiry (default 90)\n"
        "  --max-per-ip <n>      records per source IP per topic (default 16)\n"
        "  --quiet               suppress the periodic stats line\n"
        "  --help\n");
}

}  // namespace

int main(int argc, char** argv) {
    uint16_t port  = 4433;
    bool     quiet = false;
    server::StoreConfig scfg;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](int& idx) -> const char* {
            return idx + 1 < argc ? argv[++idx] : nullptr;
        };
        if (a == "--help" || a == "-h") { usage(); return 0; }
        else if (a == "--quiet") quiet = true;
        else if (a == "--port") { if (auto* v = next(i)) port = static_cast<uint16_t>(std::atoi(v)); }
        else if (a == "--stale") { if (auto* v = next(i)) scfg.stale_after = std::chrono::seconds(std::atoi(v)); }
        else if (a == "--expiry") { if (auto* v = next(i)) scfg.hard_expiry = std::chrono::seconds(std::atoi(v)); }
        else if (a == "--max-per-ip") { if (auto* v = next(i)) scfg.max_per_ip_per_topic = static_cast<size_t>(std::atoi(v)); }
        else { std::fprintf(stderr, "unknown option: %s\n", a.c_str()); usage(); return 2; }
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    io::UdpSocket sock;
    if (!sock.open(port)) {
        std::fprintf(stderr, "failed to bind UDP port %u: %s\n", port,
                     sock.last_error().c_str());
        return 1;
    }

    server::Store      store{scfg};
    server::UdpService service{store};

    std::printf("uconnect-rendezvous listening on UDP %u\n", sock.local_port());
    std::printf("  keepalive %llds  stale %llds  expiry %llds  quota %zu/ip/topic\n",
                static_cast<long long>(scfg.keepalive_interval.count()),
                static_cast<long long>(scfg.stale_after.count()),
                static_cast<long long>(scfg.hard_expiry.count()),
                scfg.max_per_ip_per_topic);
    std::fflush(stdout);

    std::vector<uint8_t> buf(2048);
    auto                 last_tick   = std::chrono::steady_clock::now();
    auto                 last_report = last_tick;

    while (!g_stop) {
        sock.wait_readable(200ms);

        // Drain everything readable before touching the clock again: one
        // syscall's worth of work per loop keeps latency low under load.
        for (int i = 0; i < 256; ++i) {
            auto got = sock.recv_from(buf);
            if (!got) break;
            auto now = std::chrono::steady_clock::now();
            for (auto& reply : service.handle(got->from, std::span(buf).first(got->len), now)) {
                if (!reply.data.empty()) sock.send_to(reply.to, reply.data);
            }
        }

        auto now = std::chrono::steady_clock::now();
        if (now - last_tick >= 5s) {
            service.tick(now);
            last_tick = now;
        }
        if (!quiet && now - last_report >= 30s) {
            auto st = store.stats(now);
            std::printf(
                "[stats] topics=%llu(listed %llu) records=%llu(fresh %llu) "
                "reg=%llu ka=%llu lookup=%llu relay=%llu rebind=%llu expired=%llu "
                "rej{auth=%llu quota=%llu}\n",
                static_cast<unsigned long long>(st.topics_total),
                static_cast<unsigned long long>(st.topics_listed),
                static_cast<unsigned long long>(st.entries_total),
                static_cast<unsigned long long>(st.entries_fresh),
                static_cast<unsigned long long>(st.registers),
                static_cast<unsigned long long>(st.keepalives),
                static_cast<unsigned long long>(st.lookups),
                static_cast<unsigned long long>(st.connects),
                static_cast<unsigned long long>(st.rebinds),
                static_cast<unsigned long long>(st.expired),
                static_cast<unsigned long long>(st.rej_bad_auth),
                static_cast<unsigned long long>(st.rej_quota));
            std::fflush(stdout);
            last_report = now;
        }
    }

    std::printf("\nshutting down\n");
    return 0;
}
