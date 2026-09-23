// uconn-observe -- read the rendezvous server's public view and print it as JSON.
//
//   uconn-observe --server host:port                 topics + stats
//   uconn-observe --server host:port --topic <hex>   one topic's members
//   uconn-observe --server host:port --members       every listed topic's members
//
// This exists so the web dashboard never has to speak the wire protocol. A
// second implementation of the framing in Python would drift from this one the
// first time a field moved, and the failure would be a silently wrong dashboard
// rather than a build error. Here the protocol has exactly one implementation
// and the boundary between C++ and Python is JSON on a pipe.
//
// It observes without participating: it never calls publish(), so it does not
// register a record and does not appear in the listings it reports. Measuring a
// swarm should not change its size.
//
// Everything it can see is already public to anyone who can reach the server:
// `listed` is opt-in, LOOKUP needs no key -- K is never sent to the server and
// is only ever used between peers -- and metadata is plaintext by design. This
// tool adds no exposure; it makes existing exposure visible.

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "uconnect/uconnect.hpp"

using namespace uconnect;
using namespace std::chrono_literals;

namespace {

// --- minimal JSON emission -------------------------------------------------
// Hand-rolled because the library has no external dependencies and this is not
// enough JSON to justify acquiring one.
std::string json_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

// Metadata is an opaque blob the application chose, so it may be any bytes at
// all. Hex is always emitted because it always round-trips; the text field
// appears only when the bytes are printable, so a dashboard can show a
// human-chosen name without inventing one for binary.
bool printable(const std::vector<uint8_t>& v) {
    if (v.empty()) return false;
    for (uint8_t b : v) {
        if (b < 0x20 || b > 0x7E) return false;
    }
    return true;
}

const char* mode_name(TopicMode m) { return m == TopicMode::Keyed ? "keyed" : "open"; }

void print_peer(const PeerInfo& p, bool last) {
    std::printf("      {\"dev_id\":\"%s\",\"age_s\":%lld,\"stale\":%s",
                to_hex(p.dev_id).c_str(),
                static_cast<long long>(p.age.count()),
                p.stale ? "true" : "false");
    if (!p.meta.empty()) {
        std::printf(",\"meta_hex\":\"%s\"", to_hex(p.meta.data(), p.meta.size()).c_str());
        if (printable(p.meta)) {
            std::string s(p.meta.begin(), p.meta.end());
            std::printf(",\"meta_text\":\"%s\"", json_escape(s).c_str());
        }
    }
    std::printf("}%s\n", last ? "" : ",");
}

// Look up one topic's members. No key is needed: LOOKUP is keyed by topic_id
// alone, so a bogus key here is never used for anything.
std::vector<PeerInfo> members_of(Node& node, const TopicId& id, uint8_t limit,
                                 std::chrono::milliseconds timeout) {
    TopicCreds creds;
    creds.id  = id;
    creds.key = std::nullopt;
    auto& t   = node.join(creds);
    auto  out = t.peers(limit, /*want_meta=*/true, timeout);
    node.leave(id);
    return out;
}

void usage() {
    std::printf(
        "uconn-observe -- print the rendezvous server's public view as JSON\n"
        "\n"
        "  --server <host:port>   rendezvous server (required)\n"
        "  --topic <hex>          report one topic's members (listed or not)\n"
        "  --members              include members for every listed topic\n"
        "  --limit <n>            members per topic, max 100 (default 30)\n"
        "  --timeout <ms>         per-request timeout (default 3000)\n");
}

}  // namespace

int main(int argc, char** argv) {
    std::string server, one_topic;
    bool        want_members = false;
    int         limit        = 30;
    int         timeout_ms   = 3000;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](int& idx) -> const char* { return idx + 1 < argc ? argv[++idx] : nullptr; };
        if (a == "--help" || a == "-h") { usage(); return 0; }
        else if (a == "--members") want_members = true;
        else if (a == "--server")  { if (auto* v = next(i)) server = v; }
        else if (a == "--topic")   { if (auto* v = next(i)) one_topic = v; }
        else if (a == "--limit")   { if (auto* v = next(i)) limit = std::atoi(v); }
        else if (a == "--timeout") { if (auto* v = next(i)) timeout_ms = std::atoi(v); }
        else { std::fprintf(stderr, "unknown option: %s\n", a.c_str()); usage(); return 2; }
    }
    if (server.empty()) { usage(); return 2; }
    if (limit < 1) limit = 1;
    if (limit > 100) limit = 100;   // the server's own hard cap
    const auto timeout = std::chrono::milliseconds(timeout_ms);

    // Errors go to stdout as JSON too. A dashboard needs to distinguish "the
    // server said there is nothing" from "we could not reach the server", and a
    // non-zero exit with an empty body cannot carry that.
    auto fail = [](const char* what) {
        std::printf("{\"ok\":false,\"error\":\"%s\"}\n", what);
        return 1;
    };

    try {
        Node::Config cfg;
        cfg.server = server;
        Node node{cfg};
        node.run_in_background();

        std::printf("{\"ok\":true,\"server\":\"%s\"", json_escape(server).c_str());

        if (!one_topic.empty()) {
            auto id = from_hex<16>(one_topic);
            if (!id) { std::printf("}\n"); return fail("bad topic id"); }
            auto peers = members_of(node, *id, static_cast<uint8_t>(limit), timeout);
            std::printf(",\n  \"topic\":{\"id\":\"%s\",\"members\":[\n",
                        to_hex(*id).c_str());
            for (size_t i = 0; i < peers.size(); ++i) print_peer(peers[i], i + 1 == peers.size());
            std::printf("  ]}\n}\n");
            node.shutdown();
            return 0;
        }

        if (auto s = node.stats(timeout)) {
            std::printf(
                ",\n  \"stats\":{"
                "\"topics_total\":%llu,\"topics_listed\":%llu,"
                "\"entries_total\":%llu,\"entries_fresh\":%llu,"
                "\"registers\":%llu,\"keepalives\":%llu,\"lookups\":%llu,"
                "\"connects\":%llu,\"rebinds\":%llu,\"expired\":%llu,"
                "\"rej_bad_auth\":%llu,\"rej_quota\":%llu,\"rej_rate_limited\":%llu,"
                "\"relays_open\":%llu,\"relays_allocated\":%llu,\"relay_bytes\":%llu}",
                (unsigned long long)s->topics_total, (unsigned long long)s->topics_listed,
                (unsigned long long)s->entries_total, (unsigned long long)s->entries_fresh,
                (unsigned long long)s->registers, (unsigned long long)s->keepalives,
                (unsigned long long)s->lookups, (unsigned long long)s->connects,
                (unsigned long long)s->rebinds, (unsigned long long)s->expired,
                (unsigned long long)s->rej_bad_auth, (unsigned long long)s->rej_quota,
                (unsigned long long)s->rej_rate_limited,
                (unsigned long long)s->relays_open, (unsigned long long)s->relays_allocated,
                (unsigned long long)s->relay_bytes);
        } else {
            std::printf(",\n  \"stats\":null");
        }

        // Only topics that opted in to the listing appear here. An unlisted
        // topic is still reachable by id -- see --topic -- exactly as it is for
        // any other client; "unlisted" means absent from the directory, not
        // secret.
        auto topics = node.explore(100, timeout);
        std::printf(",\n  \"topics\":[\n");
        for (size_t i = 0; i < topics.size(); ++i) {
            const auto& t = topics[i];
            std::printf("    {\"id\":\"%s\",\"mode\":\"%s\",\"peers\":%u,\"fresh_peers\":%u",
                        to_hex(t.id).c_str(), mode_name(t.mode), t.peers, t.fresh_peers);
            if (want_members) {
                auto peers = members_of(node, t.id, static_cast<uint8_t>(limit), timeout);
                std::printf(",\"members\":[\n");
                for (size_t j = 0; j < peers.size(); ++j) {
                    print_peer(peers[j], j + 1 == peers.size());
                }
                std::printf("    ]");
            }
            std::printf("}%s\n", i + 1 == topics.size() ? "" : ",");
        }
        std::printf("  ]\n}\n");

        node.shutdown();
        return 0;
    } catch (const std::exception& e) {
        std::printf("{\"ok\":false,\"error\":\"%s\"}\n", json_escape(e.what()).c_str());
        return 1;
    }
}
