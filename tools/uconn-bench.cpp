// uconn-bench -- how fast nodes share data, by node count and path.
//
//   uconn-bench --server-config tools/uconn-bench.server.yaml
//   uconn-bench --nodes 2,4 --modes tcp,udp-relay --seconds 3
//
// Each run starts a rendezvous server in-process, under the limits in
// --server-config, and N nodes on loopback in one topic. Every node connects
// to every other -- a full mesh -- and once every link is verified to take the
// path under test, every node sends to every peer at once, as fast as the
// library accepts. After a warm-up, bytes received are counted over a fixed
// window.
//
// Modes:
//   tcp        messages over directly punched TCP
//   tcp-relay  messages through the server's TCP relay
//   udp        datagrams over directly punched UDP (no fallback)
//   udp-relay  datagrams through the server's UDP relay
//
// Everything is one machine: the nodes, the server, and every sender share its
// cores, so this measures the library's cost and ceiling, not a network's.
//
// Datagrams are measured twice on the same mesh. First flooded, unpaced: what
// arrives is the ceiling under overload, with the share of what was sent that
// arrived beside it. Then paced, up a ladder of per-link rates, each held
// briefly: the highest rate at which at least 99% arrives is the sustainable
// one. TCP needs neither -- it paces itself. The gap between the two is worth
// reading: a sender spinning on send_datagram() holds the node's lock that the
// node's own loop needs to drain its socket.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "config.hpp"
#include "rendezvous.hpp"
#include "uconnect/uconnect.hpp"

using namespace uconnect;
using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;

namespace {

enum class Mode { Tcp, TcpRelay, Udp, UdpRelay };

const char* name(Mode m) {
    switch (m) {
        case Mode::Tcp:      return "tcp";
        case Mode::TcpRelay: return "tcp-relay";
        case Mode::Udp:      return "udp";
        case Mode::UdpRelay: return "udp-relay";
    }
    return "?";
}

bool relayed(Mode m) { return m == Mode::TcpRelay || m == Mode::UdpRelay; }
bool datagrams(Mode m) { return m == Mode::Udp || m == Mode::UdpRelay; }

struct Options {
    std::vector<int>  nodes{2, 4, 6, 8};
    std::vector<Mode> modes{Mode::Tcp, Mode::TcpRelay, Mode::Udp, Mode::UdpRelay};
    double            seconds  = 5;
    double            warmup   = 1;
    double            ladder_seconds = 1.5;  // each paced datagram step
    size_t            msg_size = 64 * 1024;
    std::string       server_config;
    std::string       csv;
    bool              verbose = false;
};

// The rendezvous server, on its own thread.
class Server {
public:
    explicit Server(server::RendezvousConfig cfg) : rv_(std::move(cfg)) {
        if (!rv_.open()) throw std::runtime_error("server: " + rv_.error());
        thread_ = std::thread([this] {
            while (!stop_) rv_.poll_once(5ms);
        });
    }
    ~Server() {
        stop_ = true;
        thread_.join();
    }
    std::string address() const { return "127.0.0.1:" + std::to_string(rv_.port()); }

private:
    server::Rendezvous rv_;
    std::atomic<bool>  stop_{false};
    std::thread        thread_;
};

// One node and what it has counted. The counters come first, so they outlive
// the node whose loop thread updates them.
struct Member {
    std::atomic<uint64_t> rx_bytes{0}, rx_units{0};
    std::atomic<uint64_t> tx_bytes{0}, tx_units{0};
    std::unique_ptr<Node> node;
    Topic*                topic = nullptr;
    DevId                 id{};
};

// What one measured window counted, across every node.
struct Count {
    double   window   = 0;  // seconds actually measured
    uint64_t rx_bytes = 0, rx_units = 0, tx_bytes = 0, tx_units = 0;

    double delivered() const {
        return tx_units ? static_cast<double>(rx_units) / static_cast<double>(tx_units) : 0;
    }
};

struct Result {
    Mode        mode{};
    int         nodes = 0;
    bool        ok    = false;
    std::string error;
    double      setup = 0;  // seconds to connect and verify the mesh
    Count       flood;      // unpaced: TCP's only measurement
    // Datagrams only: the highest paced rate per link, in datagrams/s, at
    // which at least kSustained of what was sent arrived; 0 if none did.
    uint32_t    sustained_rate = 0;
    Count       sustained;
    std::string sustained_stop;  // why the ladder stopped climbing
};

constexpr double kSustained = 0.99;
// Doubling, with a step between each pair from 4000 up, where the limits lie.
constexpr uint32_t kLadder[] = {500,   1000,  2000,  4000,  6000,  8000,  12000, 16000,
                                24000, 32000, 48000, 64000, 96000, 128000};

template <typename F>
bool wait_until(F&& cond, std::chrono::milliseconds timeout) {
    const auto deadline = Clock::now() + timeout;
    while (Clock::now() < deadline) {
        if (cond()) return true;
        std::this_thread::sleep_for(10ms);
    }
    return cond();
}

Result run(Mode mode, int n, const server::RendezvousConfig& scfg, const Options& o) {
    Result r;
    r.mode  = mode;
    r.nodes = n;

    server::RendezvousConfig cfg = scfg;
    cfg.port = 0;
    Server srv{cfg};

    const auto        t_setup = Clock::now();
    const TopicCreds  creds   = TopicCreds::generate_keyed();
    std::atomic<bool> counting{false};

    std::vector<std::unique_ptr<Member>> m;
    for (int i = 0; i < n; ++i) {
        auto mb = std::make_unique<Member>();
        Node::Config c;
        c.server            = srv.address();
        c.force_relay       = relayed(mode);
        c.verbose           = o.verbose;
        c.datagram_fallback = mode == Mode::UdpRelay ? DatagramFallback::Relay : DatagramFallback::None;
        mb->node = std::make_unique<Node>(c);
        mb->node->run_in_background();
        mb->topic = &mb->node->join(creds);
        mb->topic->set_max_peers(static_cast<size_t>(n));
        Member* self = mb.get();
        auto count = [self, &counting](DevId, std::span<const uint8_t> d) {
            if (!counting.load(std::memory_order_relaxed)) return;
            self->rx_bytes.fetch_add(d.size(), std::memory_order_relaxed);
            self->rx_units.fetch_add(1, std::memory_order_relaxed);
        };
        if (datagrams(mode)) mb->topic->on_datagram(count);
        else mb->topic->on_data(count);
        m.push_back(std::move(mb));
    }
    for (auto& mb : m) {
        if (!mb->topic->publish() || !mb->topic->self()) {
            r.error = "publish failed";
            return r;
        }
        mb->id = *mb->topic->self();
    }

    // The mesh: each node learns the others' candidates, then dials those
    // after it, so every pair is dialed once.
    for (int i = 0; i < n; ++i) {
        (void)m[i]->topic->peers(static_cast<uint8_t>(std::min(n, 100)));
        for (int j = i + 1; j < n; ++j) m[i]->topic->connect(m[j]->id);
    }
    auto all_pairs = [&](auto&& ok) {
        for (int i = 0; i < n; ++i) {
            for (int j = 0; j < n; ++j) {
                if (i != j && !ok(*m[i], *m[j])) return false;
            }
        }
        return true;
    };
    if (!wait_until([&] {
            return all_pairs([](Member& a, Member& b) {
                return a.topic->state(b.id) == PeerState::Connected;
            });
        }, std::chrono::seconds(20 + 3 * n))) {
        r.error = "mesh did not connect";
        return r;
    }
    if (!all_pairs([&](Member& a, Member& b) {
            auto li = a.topic->link(b.id);
            return li && li->relayed == relayed(mode);
        })) {
        r.error = relayed(mode) ? "a link is not relayed" : "a link is relayed, not direct";
        return r;
    }

    if (datagrams(mode)) {
        const DatagramPath want = mode == Mode::Udp ? DatagramPath::Direct : DatagramPath::Relayed;
        const DatagramFallback fb = mode == Mode::Udp ? DatagramFallback::None : DatagramFallback::Relay;
        for (int i = 0; i < n; ++i) {
            for (int j = i + 1; j < n; ++j) m[i]->topic->open_datagrams(m[j]->id, fb);
        }
        if (!wait_until([&] {
                return all_pairs([&](Member& a, Member& b) {
                    return a.topic->datagram_path(b.id) == want;
                });
            }, std::chrono::seconds(20 + 3 * n))) {
            r.error = std::string("datagram channels did not all reach ") + to_string(want);
            return r;
        }
    }
    r.setup = std::chrono::duration<double>(Clock::now() - t_setup).count();

    const size_t unit = datagrams(mode) ? Topic::max_datagram() : o.msg_size;

    // Load, then count: senders run through a warm-up with counting off, then
    // a window with it on. `rate` is datagrams/s per link; 0 sends unpaced.
    auto measure = [&](uint32_t rate, double warmup, double seconds) {
        for (auto& mb : m) mb->rx_bytes = mb->rx_units = mb->tx_bytes = mb->tx_units = 0;
        std::atomic<bool>        stop{false};
        std::vector<std::thread> senders;
        for (int i = 0; i < n; ++i) {
            senders.emplace_back([&, i] {
                Member&            me = *m[i];
                std::vector<DevId> peers;
                for (int j = 0; j < n; ++j) {
                    if (j != i) peers.push_back(m[j]->id);
                }
                std::vector<uint8_t> payload(unit, static_cast<uint8_t>(i));
                auto send_one = [&](const DevId& p) {
                    const bool sent = datagrams(mode) ? me.topic->send_datagram(p, payload)
                                                      : me.topic->send(p, payload);
                    if (sent && counting.load(std::memory_order_relaxed)) {
                        me.tx_bytes.fetch_add(unit, std::memory_order_relaxed);
                        me.tx_units.fetch_add(1, std::memory_order_relaxed);
                    }
                    return sent;
                };
                if (rate == 0) {
                    // Unpaced, round-robin over the peers. A send the library
                    // refuses -- a full queue -- moves on to the next peer;
                    // when every peer refuses, the thread yields briefly.
                    while (!stop.load(std::memory_order_relaxed)) {
                        bool any = false;
                        for (const auto& p : peers) any = send_one(p) || any;
                        if (!any) std::this_thread::sleep_for(200us);
                    }
                    return;
                }
                // Paced: as many sends as are due by now, then yield. Sleeping
                // would not do -- Windows rounds a sleep up to its timer tick,
                // and the bursts that made would overflow the receiver. A
                // sender that falls behind skips ahead rather than bursting.
                const double total    = static_cast<double>(rate) * static_cast<double>(peers.size());
                const auto   cap      = static_cast<uint64_t>(std::max(1.0, total / 1000));
                const auto   start    = Clock::now();
                uint64_t     due_done = 0;
                size_t       next     = 0;
                while (!stop.load(std::memory_order_relaxed)) {
                    const auto due = static_cast<uint64_t>(
                        std::chrono::duration<double>(Clock::now() - start).count() * total);
                    if (due > due_done + cap) due_done = due - cap;
                    while (due_done < due && !stop.load(std::memory_order_relaxed)) {
                        send_one(peers[next++ % peers.size()]);
                        ++due_done;
                    }
                    std::this_thread::yield();
                }
            });
        }
        std::this_thread::sleep_for(std::chrono::duration<double>(warmup));
        const auto t0 = Clock::now();
        counting      = true;
        std::this_thread::sleep_for(std::chrono::duration<double>(seconds));
        counting      = false;
        const auto t1 = Clock::now();
        stop          = true;
        for (auto& t : senders) t.join();

        Count c;
        c.window = std::chrono::duration<double>(t1 - t0).count();
        for (auto& mb : m) {
            c.rx_bytes += mb->rx_bytes;
            c.rx_units += mb->rx_units;
            c.tx_bytes += mb->tx_bytes;
            c.tx_units += mb->tx_units;
        }
        return c;
    };

    r.flood = measure(0, o.warmup, o.seconds);
    r.ok    = r.flood.rx_bytes > 0;
    if (!r.ok) {
        r.error = "nothing arrived";
        return r;
    }

    if (datagrams(mode)) {
        // Up the ladder until a rate loses more than kSustained allows, or the
        // senders cannot even offer it -- then the bottleneck is sending.
        const double links = static_cast<double>(n) * (n - 1);
        for (uint32_t rate : kLadder) {
            const Count  c       = measure(rate, 0.3, o.ladder_seconds);
            const double offered = static_cast<double>(c.tx_units) / c.window / links;
            if (offered < 0.9 * rate) {
                r.sustained_stop = "senders could not offer " + std::to_string(rate) + "/s";
                break;
            }
            if (c.delivered() < kSustained) {
                char why[96];
                std::snprintf(why, sizeof why, "%.1f%% arrived at %u/s", 100 * c.delivered(), rate);
                r.sustained_stop = why;
                break;
            }
            r.sustained_rate = rate;
            r.sustained      = c;
        }
        if (r.sustained_stop.empty()) r.sustained_stop = "top of the ladder";
    }
    return r;
}

double mib_per_s(uint64_t bytes, double secs) {
    return secs > 0 ? static_cast<double>(bytes) / (1024.0 * 1024.0) / secs : 0;
}

void print_flood(const Result& r) {
    if (!r.ok) {
        std::printf("%-10s %5d   FAILED: %s\n", name(r.mode), r.nodes, r.error.c_str());
        std::fflush(stdout);
        return;
    }
    const Count& c     = r.flood;
    const int    links = r.nodes * (r.nodes - 1);
    const double agg   = mib_per_s(c.rx_bytes, c.window);
    char         arrived[32] = "      -";
    if (datagrams(r.mode)) std::snprintf(arrived, sizeof arrived, "%6.1f%%", 100 * c.delivered());
    std::printf("%-10s %5d %6d %11.1f %10.1f %10.1f %11.0f %s %8.1fs\n", name(r.mode), r.nodes, links,
                agg, agg / links, agg / r.nodes, static_cast<double>(c.rx_units) / c.window, arrived,
                r.setup);
    std::fflush(stdout);
}

void print_sustained(const Result& r) {
    if (!r.ok || !datagrams(r.mode)) return;
    const int links = r.nodes * (r.nodes - 1);
    if (r.sustained_rate == 0) {
        std::printf("%-10s %5d %6d %14s %11s %10s %8s  %s\n", name(r.mode), r.nodes, links, "-", "-",
                    "-", "-", r.sustained_stop.c_str());
        return;
    }
    const Count& c   = r.sustained;
    const double agg = mib_per_s(c.rx_bytes, c.window);
    std::printf("%-10s %5d %6d %14u %11.1f %10.2f %7.2f%%  %s\n", name(r.mode), r.nodes, links,
                r.sustained_rate, agg, agg / links, 100 * c.delivered(), r.sustained_stop.c_str());
}

std::vector<std::string> split(const std::string& s) {
    std::vector<std::string> out;
    size_t                   pos = 0;
    while (pos <= s.size()) {
        const size_t c = s.find(',', pos);
        out.push_back(s.substr(pos, c == std::string::npos ? std::string::npos : c - pos));
        if (c == std::string::npos) break;
        pos = c + 1;
    }
    return out;
}

void usage() {
    std::printf(
        "uconn-bench -- throughput between nodes, by node count and path\n"
        "\n"
        "  --server-config <yaml>  the in-process server's limits; without it the\n"
        "                          shipped defaults, which cap relayed runs\n"
        "  --nodes <list>          node counts (default 2,4,6,8)\n"
        "  --modes <list>          tcp, tcp-relay, udp, udp-relay (default all)\n"
        "  --seconds <s>           measured window per run (default 5)\n"
        "  --warmup <s>            sending before the window opens (default 1)\n"
        "  --ladder-seconds <s>    each paced datagram step (default 1.5)\n"
        "  --msg-size <bytes>      TCP message size (default 65536)\n"
        "  --csv <file>            also write the results as CSV\n"
        "  --verbose               protocol tracing from every node\n");
}

bool parse(int argc, char** argv, Options& o) {
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : nullptr; };
        const char* v = nullptr;
        if (a == "--help" || a == "-h") {
            usage();
            std::exit(0);
        } else if (a == "--verbose") {
            o.verbose = true;
        } else if (!(v = next())) {
            std::fprintf(stderr, "%s needs a value\n", a.c_str());
            return false;
        } else if (a == "--server-config") {
            o.server_config = v;
        } else if (a == "--csv") {
            o.csv = v;
        } else if (a == "--seconds") {
            o.seconds = std::atof(v);
        } else if (a == "--warmup") {
            o.warmup = std::atof(v);
        } else if (a == "--ladder-seconds") {
            o.ladder_seconds = std::atof(v);
        } else if (a == "--msg-size") {
            o.msg_size = static_cast<size_t>(std::atoll(v));
        } else if (a == "--nodes") {
            o.nodes.clear();
            for (const auto& s : split(v)) o.nodes.push_back(std::atoi(s.c_str()));
        } else if (a == "--modes") {
            o.modes.clear();
            for (const auto& s : split(v)) {
                if (s == "tcp") o.modes.push_back(Mode::Tcp);
                else if (s == "tcp-relay") o.modes.push_back(Mode::TcpRelay);
                else if (s == "udp") o.modes.push_back(Mode::Udp);
                else if (s == "udp-relay") o.modes.push_back(Mode::UdpRelay);
                else {
                    std::fprintf(stderr, "unknown mode: %s\n", s.c_str());
                    return false;
                }
            }
        } else {
            std::fprintf(stderr, "unknown option: %s\n", a.c_str());
            return false;
        }
    }
    for (int n : o.nodes) {
        if (n < 2 || n > 30) {
            std::fprintf(stderr, "node counts must be 2..30\n");
            return false;
        }
    }
    if (o.seconds <= 0 || o.warmup < 0 || o.ladder_seconds <= 0 || o.msg_size == 0 ||
        o.msg_size > Topic::max_message()) {
        std::fprintf(stderr, "bad --seconds, --warmup, --ladder-seconds or --msg-size\n");
        return false;
    }
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    Options o;
    if (!parse(argc, argv, o)) return 2;

    server::RendezvousConfig scfg;
    if (!o.server_config.empty()) {
        std::string err;
        if (!server::load_config_file(o.server_config, scfg, err)) {
            std::fprintf(stderr, "%s\n", err.c_str());
            return 2;
        }
    } else {
        std::fprintf(stderr, "note: no --server-config; relayed runs meet the default limits\n");
    }

    std::printf("uconn-bench: %.1fs window after %.1fs warm-up; TCP messages %zu B, datagrams %zu B\n",
                o.seconds, o.warmup, o.msg_size, Topic::max_datagram());
    std::printf("server limits: %s\n\n",
                o.server_config.empty() ? "(defaults)" : o.server_config.c_str());
    std::printf("%-10s %5s %6s %11s %10s %10s %11s %7s %9s\n", "mode", "nodes", "links",
                "total MiB/s", "per link", "per node", "units/s", "arrived", "setup");

    std::vector<Result> results;
    for (Mode mode : o.modes) {
        for (int n : o.nodes) {
            Result r;
            try {
                r = run(mode, n, scfg, o);
            } catch (const std::exception& e) {
                r.mode  = mode;
                r.nodes = n;
                r.error = e.what();
            }
            print_flood(r);
            results.push_back(r);
        }
    }

    if (std::any_of(o.modes.begin(), o.modes.end(), datagrams)) {
        std::printf("\nDatagrams, paced: the highest rate per link with at least %.0f%% arriving\n\n",
                    100 * kSustained);
        std::printf("%-10s %5s %6s %14s %11s %10s %8s  %s\n", "mode", "nodes", "links", "dgrams/s/link",
                    "total MiB/s", "per link", "arrived", "ladder stopped at");
        for (const auto& r : results) print_sustained(r);
    }

    if (!o.csv.empty()) {
        if (FILE* f = std::fopen(o.csv.c_str(), "w")) {
            std::fprintf(f, "mode,nodes,links,phase,rate_per_link,ok,window_s,rx_bytes,rx_units,"
                            "tx_bytes,tx_units,total_mib_s,delivered,setup_s,note\n");
            auto row = [&](const Result& r, const char* phase, uint32_t rate, const Count& c,
                           const std::string& note) {
                std::fprintf(f, "%s,%d,%d,%s,%u,%d,%.3f,%llu,%llu,%llu,%llu,%.2f,%.4f,%.2f,%s\n",
                             name(r.mode), r.nodes, r.nodes * (r.nodes - 1), phase, rate, r.ok ? 1 : 0,
                             c.window, static_cast<unsigned long long>(c.rx_bytes),
                             static_cast<unsigned long long>(c.rx_units),
                             static_cast<unsigned long long>(c.tx_bytes),
                             static_cast<unsigned long long>(c.tx_units), mib_per_s(c.rx_bytes, c.window),
                             c.delivered(), r.setup, note.c_str());
            };
            for (const auto& r : results) {
                row(r, "flood", 0, r.flood, r.error);
                if (r.ok && datagrams(r.mode)) {
                    row(r, "sustained", r.sustained_rate, r.sustained, r.sustained_stop);
                }
            }
            std::fclose(f);
        }
    }
    const bool all_ok = std::all_of(results.begin(), results.end(), [](const Result& r) { return r.ok; });
    return all_ok ? 0 : 1;
}
