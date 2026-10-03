// uconnect-rendezvous: the rendezvous server.
//
// Its entire job is to let two peers learn each other's addresses and dial at
// the same moment, and to relay the pairs whose NATs will not let them. It
// holds no K, cannot read a keyed topic's traffic, and cannot impersonate a
// member. What it knows about a device is a dev_id it derived itself, an
// IP:port, a topic_id, and an opaque blob -- all held only for as long as the
// device's control connection stays open.
//
// Entirely in memory. There is no database and no persistence: a restart just
// means every live node reconnects and registers again.

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "config.hpp"
#include "rendezvous.hpp"
#include "socket.hpp"
#include "stun.hpp"

using namespace uconnect;
using namespace std::chrono_literals;

namespace {

std::atomic<bool> g_stop{false};
void on_signal(int) { g_stop = true; }

void usage() {
    std::printf(
        "uconnect-rendezvous -- rendezvous server for uConnect\n"
        "\n"
        "  --config <file>       read settings and limits from a YAML file; see\n"
        "                        server/rendezvous.example.yaml for every key.\n"
        "                        The flags below override it, wherever they appear\n"
        "  --print-config        print the configuration in force and exit\n"
        "  --port <n>            TCP and UDP port to bind (default 4433)\n"
        "  --bind <addr>         bind UDP to a specific address (default: all\n"
        "                        interfaces); TCP always listens on all of them\n"
        "  --stale <secs>        freshness window (default 45)\n"
        "  --max-per-ip <n>      records per source IP per topic (default 16)\n"
        "  --no-relay            refuse relay allocations\n"
        "  --quiet               suppress the periodic stats line\n"
        "  --nat-check           report this host's NAT behaviour and exit\n"
        "  --help\n");
}

int nat_check(io::UdpSocket& sock) {
    std::printf("probing NAT behaviour from local UDP port %u ...\n\n", sock.local_port());

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
                "  coordinates both sides to dial at the same moment.\n");
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
        "\n  This measures UDP MAPPING behaviour (is the external address stable\n"
        "  across destinations), not FILTERING behaviour (will the NAT admit a\n"
        "  packet from a host we have not sent to). Most NATs map TCP the same\n"
        "  way they map UDP, but that is a tendency, not a guarantee.\n"
        "\n  A RENDEZVOUS SERVER needs more than that: a client arrives cold,\n"
        "  with nobody to coordinate a simultaneous open toward it, so its\n"
        "  connection is unsolicited and a filtering NAT drops it. Running the\n"
        "  server here requires a public IP or an explicit port forward (TCP\n"
        "  and UDP) -- no amount of STUN changes that.\n");
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    server::ServerOptions opts;
    std::string           error;
    if (!server::parse_server_args(std::vector<std::string>(argv + 1, argv + argc), opts, error)) {
        std::fprintf(stderr, "%s\n(--help lists the options)\n", error.c_str());
        return 2;
    }
    if (opts.help) {
        usage();
        return 0;
    }
    // Before any socket: checking a configuration must not need the port.
    if (opts.print_config) {
        std::fputs(server::to_yaml(opts.cfg).c_str(), stdout);
        return 0;
    }
    const bool                      quiet     = opts.quiet;
    const bool                      check_nat = opts.nat_check;
    const server::RendezvousConfig& cfg       = opts.cfg;

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    io::init_networking();

    // STUN runs over UDP from the server's own port, before the server takes
    // that port: the mapping of that exact port is what matters.
    {
        io::UdpSocket probe;
        if (!probe.open(cfg.port, cfg.bind_host)) {
            std::fprintf(stderr, "failed to bind UDP port %u: %s\n", cfg.port,
                         probe.last_error().c_str());
            return 1;
        }
        if (check_nat) return nat_check(probe);

        // Resolve by name: Google's anycast STUN addresses rotate, and a stale
        // literal turns every probe into a silent timeout.
        if (auto stun_server = io::resolve("stun.l.google.com:19302")) {
            if (auto result = stun::binding(probe, *stun_server)) {
                std::printf("  public addr %s\n", io::to_string(result->mapped_endpoint).c_str());

                // Knowing the address is not the same as being reachable at it.
                // A rendezvous server must be reachable by a client that has
                // never been contacted first, which requires a real inbound
                // path -- a public IP, or an explicit port forward.
                if (result->mapped_endpoint.port != probe.local_port()) {
                    std::printf(
                        "  NOTE: mapped port %u differs from local port %u -- this host\n"
                        "        is behind a port-translating NAT and CANNOT serve as a\n"
                        "        rendezvous server. Run with --nat-check for detail.\n",
                        result->mapped_endpoint.port, probe.local_port());
                }
            } else {
                std::fprintf(stderr, "  (STUN probe got no reply; continuing)\n");
            }
        } else {
            std::fprintf(stderr, "  (could not resolve STUN server; continuing)\n");
        }
    }

    server::Rendezvous rv{cfg};
    if (!rv.open()) {
        std::fprintf(stderr, "failed to open port %u: %s\n", cfg.port, rv.error().c_str());
        return 1;
    }

    std::printf("uconnect-rendezvous listening on TCP+UDP %u\n", rv.port());
    std::printf("  stale %llds  quota %zu/ip/topic  relay %s\n",
                static_cast<long long>(cfg.registry.stale_after.count()),
                cfg.registry.max_per_ip_per_topic, cfg.registry.relay_enabled ? "on" : "off");
    std::fflush(stdout);

    auto last_report = std::chrono::steady_clock::now();
    while (!g_stop) {
        rv.poll_once(200ms);

        auto now = std::chrono::steady_clock::now();
        if (!quiet && now - last_report >= 30s) {
            auto st = rv.service().registry().stats(now);
            std::printf(
                "[stats] conns=%zu topics=%llu(listed %llu) records=%llu(fresh %llu) "
                "reg=%llu lookup=%llu connect=%llu relays=%llu(open %llu, %llu bytes) "
                "rej{quota=%llu}\n",
                rv.service().connections(),
                static_cast<unsigned long long>(st.topics_total),
                static_cast<unsigned long long>(st.topics_listed),
                static_cast<unsigned long long>(st.entries_total),
                static_cast<unsigned long long>(st.entries_fresh),
                static_cast<unsigned long long>(st.registers),
                static_cast<unsigned long long>(st.lookups),
                static_cast<unsigned long long>(st.connects),
                static_cast<unsigned long long>(st.relays_allocated),
                static_cast<unsigned long long>(st.relays_open),
                static_cast<unsigned long long>(st.relay_bytes),
                static_cast<unsigned long long>(st.rej_quota));
            std::fflush(stdout);
            last_report = now;
        }
    }

    std::printf("\nshutting down\n");
    return 0;
}
