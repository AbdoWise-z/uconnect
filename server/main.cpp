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
#include <cstdlib>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <string>

#include "socket.hpp"
#include "stun.hpp"
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
        "  --bind <addr>         bind a specific address (default: all interfaces)\n"
        "  --stale <secs>        freshness window (default 45)\n"
        "  --expiry <secs>       hard record expiry (default 90)\n"
        "  --max-per-ip <n>      records per source IP per topic (default 16)\n"
        "  --quiet               suppress the periodic stats line\n"
        "  --nat-check           report this host's NAT behaviour and exit\n"
        "  --help\n");
}

}  // namespace

int main(int argc, char** argv) {
    uint16_t port  = 4433;
    bool     quiet = false;
    bool     nat_check = false;
    std::string bind_host;
    server::StoreConfig scfg;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](int& idx) -> const char* {
            return idx + 1 < argc ? argv[++idx] : nullptr;
        };
        if (a == "--help" || a == "-h") { usage(); return 0; }
        else if (a == "--quiet") quiet = true;
        else if (a == "--nat-check") nat_check = true;
        else if (a == "--bind") { if (auto* v = next(i)) bind_host = v; }
        else if (a == "--port") { if (auto* v = next(i)) port = static_cast<uint16_t>(std::atoi(v)); }
        else if (a == "--stale") { if (auto* v = next(i)) scfg.stale_after = std::chrono::seconds(std::atoi(v)); }
        else if (a == "--expiry") { if (auto* v = next(i)) scfg.hard_expiry = std::chrono::seconds(std::atoi(v)); }
        else if (a == "--max-per-ip") { if (auto* v = next(i)) scfg.max_per_ip_per_topic = static_cast<size_t>(std::atoi(v)); }
        else { std::fprintf(stderr, "unknown option: %s\n", a.c_str()); usage(); return 2; }
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    io::UdpSocket sock;
    if (!sock.open(port, bind_host)) {
        std::fprintf(stderr, "failed to bind UDP port %u: %s\n", port,
                     sock.last_error().c_str());
        return 1;
    }

    if (nat_check) {
        std::printf("probing NAT behaviour from local UDP port %u ...\n\n",
                    sock.local_port());

        auto r = stun::probe_nat(sock);
        for (const auto& e : r.observed) {
            std::printf("  a STUN server sees us at %s\n", io::to_string(e).c_str());
        }
        if (r.observed.empty()) {
            std::printf("  no STUN server replied -- UDP may be blocked outbound\n");
        }

        std::printf("\n  mapping        : %s\n", stun::to_string(r.mapping));
        std::printf("  port preserved : %s\n\n", r.port_preserved ? "yes" : "no");

        switch (r.mapping) {
            case stun::Mapping::EndpointIndependent:
                std::printf(
                    "  Peers CAN hole punch to this host, once a rendezvous server\n"
                    "  coordinates both sides to fire at the same moment.\n");
                break;
            case stun::Mapping::EndpointDependent:
                std::printf(
                    "  Symmetric NAT: a fresh external port is allocated per\n"
                    "  destination, so the address any third party observed is NOT the\n"
                    "  address a peer must hit. Hole punching cannot work from here;\n"
                    "  such a pair needs a relay.\n");
                break;
            default:
                std::printf("  Inconclusive -- fewer than two STUN servers answered.\n");
                break;
        }

        std::printf(
            "\n  This measures MAPPING behaviour (is the external address stable\n"
            "  across destinations), not FILTERING behaviour (will the NAT admit a\n"
            "  packet from a host we have not sent to). Punching only needs stable\n"
            "  mapping, because both peers send and each one opens its own filter.\n"
            "\n  A RENDEZVOUS SERVER needs more than that: a client arrives cold,\n"
            "  with nobody to coordinate a simultaneous punch toward it, so the\n"
            "  first packet is unsolicited and a filtering NAT drops it. Running\n"
            "  the server here requires a public IP or an explicit UDP port\n"
            "  forward -- no amount of STUN changes that.\n");
        return 0;
    }

    server::Store      store{scfg};
    server::UdpService service{store};

    std::printf("uconnect-rendezvous listening on UDP %u\n", sock.local_port());

    // Resolve by name. The previous hardcoded 74.125.250.129 is one of Google's
    // anycast STUN addresses; those rotate, and a stale literal turns every
    // probe into a silent timeout.
    if (auto stun_server = io::resolve("stun.l.google.com:19302")) {
        if (auto result = stun::binding(sock, *stun_server)) {
            std::printf("  public addr %s\n",
                        io::to_string(result->mapped_endpoint).c_str());

            // Knowing the address is not the same as being reachable at it.
            // A rendezvous server must be reachable by a client that has never
            // been contacted first, which requires a real inbound path -- a
            // public IP, or an explicit port forward. See --nat-check.
            if (result->mapped_endpoint.port != sock.local_port()) {
                std::printf(
                    "  NOTE: mapped port %u differs from local port %u -- this host\n"
                    "        is behind a port-translating NAT and CANNOT serve as a\n"
                    "        rendezvous server. Run with --nat-check for detail.\n",
                    result->mapped_endpoint.port, sock.local_port());
            }
        } else {
            std::fprintf(stderr, "  (STUN probe got no reply; continuing)\n");
        }
    } else {
        std::fprintf(stderr, "  (could not resolve STUN server; continuing)\n");
    }

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
