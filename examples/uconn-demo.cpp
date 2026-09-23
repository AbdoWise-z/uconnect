// uconn-demo -- end-to-end exercise of the library.
//
//   uconn-demo --server 127.0.0.1:4433 --create
//       prints a uconn:// URI and waits for peers
//
//   uconn-demo --server 127.0.0.1:4433 --topic uconn://<id>#<key> --name bob
//       joins, publishes, connects to everyone, and exchanges messages
//
// Each instance publishes its record, looks up the topic, punches, runs the
// Noise handshake, and then sends a greeting to every peer it connects to.

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

#include "uconnect/uconnect.hpp"

using namespace uconnect;
using namespace std::chrono_literals;

namespace {

std::string short_id(const DevId& d) { return to_hex(d).substr(0, 8); }

void usage() {
    std::printf(
        "uconn-demo -- uConnect end-to-end demo\n"
        "\n"
        "  --server <host:port>   rendezvous server (required)\n"
        "  --topic <uconn://...>  topic to join\n"
        "  --create               generate a keyed topic and print its URI\n"
        "  --create-open          generate an OPEN topic (no authentication!)\n"
        "  --name <string>        name announced in metadata (default: anon)\n"
        "  --seconds <n>          how long to run (default 20)\n"
        "  --listed               opt in to the public topic listing\n"
        "  --explore              list topics on the server and exit\n"
        "  --stats                print server stats and exit\n");
}

}  // namespace

int main(int argc, char** argv) {
    std::string server, topic_uri, name = "anon";
    int         seconds     = 20;
    bool        create      = false, create_open = false, listed = false;
    bool        explore     = false, want_stats = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](int& idx) -> const char* {
            return idx + 1 < argc ? argv[++idx] : nullptr;
        };
        if (a == "--help" || a == "-h") { usage(); return 0; }
        else if (a == "--create") create = true;
        else if (a == "--create-open") create_open = true;
        else if (a == "--listed") listed = true;
        else if (a == "--explore") explore = true;
        else if (a == "--stats") want_stats = true;
        else if (a == "--server") { if (auto* v = next(i)) server = v; }
        else if (a == "--topic") { if (auto* v = next(i)) topic_uri = v; }
        else if (a == "--name") { if (auto* v = next(i)) name = v; }
        else if (a == "--seconds") { if (auto* v = next(i)) seconds = std::atoi(v); }
        else { std::fprintf(stderr, "unknown option: %s\n", a.c_str()); usage(); return 2; }
    }

    if (server.empty()) { usage(); return 2; }

    try {
        Node::Config cfg;
        cfg.server = server;
        Node node{cfg};
        node.run_in_background();
        std::printf("[%s] local UDP port %u\n", name.c_str(), node.local_port());

        if (want_stats) {
            auto s = node.stats();
            if (!s) { std::fprintf(stderr, "no reply from server\n"); return 1; }
            std::printf("topics=%llu listed=%llu records=%llu fresh=%llu\n"
                        "registers=%llu keepalives=%llu lookups=%llu relays=%llu\n"
                        "rebinds=%llu expired=%llu rej{auth=%llu quota=%llu rate=%llu}\n",
                        (unsigned long long)s->topics_total,
                        (unsigned long long)s->topics_listed,
                        (unsigned long long)s->entries_total,
                        (unsigned long long)s->entries_fresh,
                        (unsigned long long)s->registers,
                        (unsigned long long)s->keepalives,
                        (unsigned long long)s->lookups,
                        (unsigned long long)s->connects,
                        (unsigned long long)s->rebinds,
                        (unsigned long long)s->expired,
                        (unsigned long long)s->rej_bad_auth,
                        (unsigned long long)s->rej_quota,
                        (unsigned long long)s->rej_rate_limited);
            return 0;
        }

        if (explore) {
            auto list = node.explore();
            if (list.empty()) std::printf("(no listed topics)\n");
            for (const auto& t : list) {
                std::printf("%s  mode=%s  peers=%u fresh=%u\n", to_hex(t.id).c_str(),
                            t.mode == TopicMode::Keyed ? "keyed" : "open", t.peers,
                            t.fresh_peers);
            }
            return 0;
        }

        TopicCreds creds;
        if (create || create_open) {
            creds = create_open ? TopicCreds::generate_open() : TopicCreds::generate_keyed();
            std::printf("\n  topic: %s\n\n", creds.to_uri().c_str());
            if (create_open) {
                std::printf("  WARNING: open topic. Encrypted against a passive observer\n"
                            "  only -- anyone on path, including the rendezvous server,\n"
                            "  can MITM it undetectably.\n\n");
            }
        } else if (!topic_uri.empty()) {
            auto parsed = TopicCreds::parse(topic_uri);
            if (!parsed) { std::fprintf(stderr, "bad topic URI\n"); return 2; }
            creds = *parsed;
        } else {
            std::fprintf(stderr, "need --topic or --create\n");
            return 2;
        }

        auto& topic = node.join(creds);
        std::printf("[%s] topic %s (%s)\n", name.c_str(), to_hex(creds.id).c_str(),
                    topic.is_authenticated() ? "keyed, mutually authenticated"
                                             : "OPEN, unauthenticated");

        std::atomic<int> received{0};

        topic.on_peer([&, n = name](DevId dev, PeerState st) {
            std::printf("[%s] peer %s -> %s\n", n.c_str(), short_id(dev).c_str(),
                        to_string(st));
            std::fflush(stdout);
        });

        // A peer that says goodbye is worth reporting calmly; one that simply
        // vanishes is worth retrying. Only this tells them apart.
        topic.on_peer_closed([&, n = name](DevId dev, PeerGone why) {
            std::printf("[%s] peer %s gone: %s\n", n.c_str(), short_id(dev).c_str(),
                        to_string(why));
            std::fflush(stdout);
        });

        topic.on_data([&, n = name](DevId dev, std::span<const uint8_t> data) {
            std::string s(reinterpret_cast<const char*>(data.data()), data.size());
            std::printf("[%s] <- %s: %s\n", n.c_str(), short_id(dev).c_str(), s.c_str());
            std::fflush(stdout);
            ++received;
        });

        std::vector<uint8_t> meta(name.begin(), name.end());
        if (!topic.publish(meta, listed)) {
            std::fprintf(stderr, "[%s] publish failed (is the server running?)\n",
                         name.c_str());
            return 1;
        }
        auto self = topic.self();
        std::printf("[%s] published as %s", name.c_str(),
                    self ? short_id(*self).c_str() : "?");
        if (auto r = node.reflexive()) {
            std::printf("  (server sees us at %s)", to_hex(r->ip.bytes.data(), 4).c_str());
        }
        std::printf("\n");
        std::fflush(stdout);

        auto   deadline   = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
        int    greeted    = 0;
        size_t last_peers = 0;

        while (std::chrono::steady_clock::now() < deadline) {
            auto list = topic.peers();
            if (list.size() != last_peers) {
                std::printf("[%s] %zu peer(s) in topic\n", name.c_str(), list.size());
                std::fflush(stdout);
                last_peers = list.size();
            }
            for (const auto& p : list) {
                if (p.stale) continue;
                if (topic.state(p.dev_id) == PeerState::Unknown) topic.connect(p.dev_id);
            }

            for (const auto& dev : topic.connected()) {
                if (greeted > 200) break;
                std::string msg = "hello from " + name;
                if (topic.send(dev, std::span(reinterpret_cast<const uint8_t*>(msg.data()),
                                              msg.size()))) {
                    std::printf("[%s] -> %s: %s\n", name.c_str(), short_id(dev).c_str(),
                                msg.c_str());
                    std::fflush(stdout);
                    ++greeted;
                }
                if (auto s = topic.sas(dev)) {
                    if (!topic.is_authenticated()) {
                        std::printf("[%s] SAS for %s: %s  (compare out of band)\n",
                                    name.c_str(), short_id(dev).c_str(), s->c_str());
                    }
                }
            }

            std::this_thread::sleep_for(2s);
        }

        std::printf("[%s] done: %d message(s) received, %zu peer(s) connected\n",
                    name.c_str(), received.load(), topic.connected().size());
        node.shutdown();
        return received > 0 ? 0 : 3;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "fatal: %s\n", e.what());
        return 1;
    }
}
