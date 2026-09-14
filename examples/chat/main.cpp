// uconn-chat -- an interactive peer-to-peer chat client built on uConnect.
//
// There is no chat server. The rendezvous server introduces peers and then has
// nothing further to do with the conversation: it never sees a message, and on
// a keyed topic it cannot impersonate a participant either, because it does not
// hold K.
//
//   uconn-chat --server 127.0.0.1:4433 --create --nick alice
//   uconn-chat --server 127.0.0.1:4433 --topic 'uconn://<id>#<key>' --nick bob
//
// Type to send to everyone. Commands start with '/'; try /help.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "terminal.hpp"
#include "uconnect/uconnect.hpp"

using namespace uconnect;
using namespace std::chrono_literals;

namespace {

// ---------------------------------------------------------------------------
// Application-layer message format
// ---------------------------------------------------------------------------
// uConnect delivers authenticated, encrypted bytes and takes no view on what
// they mean. This is the smallest thing that works: a type byte and a UTF-8
// body.
//
// Note what is deliberately NOT here: any cryptographic identity. The transport
// proves "this peer holds K", i.e. membership of the topic, and nothing about
// *which* member. The nickname below is therefore a display convenience and not
// a security claim -- any topic member can announce any nickname.
//
// A real application that needs per-user identity would give each user a
// signing key and send, on connect:
//
//     { pubkey, Sign(privkey, "uconn-chat:v1" || topic.channel_binding(dev)) }
//
// Binding the signature to the channel hash is the load-bearing part. Without
// it, a topic member can run two sessions and relay someone else's identity
// proof into the second one to impersonate them.
enum class MsgType : uint8_t {
    Hello = 1,  // announce nickname
    Text  = 2,  // chat message
    Bye   = 3,  // leaving cleanly
};

std::vector<uint8_t> encode(MsgType t, std::string_view body) {
    std::vector<uint8_t> out;
    out.reserve(body.size() + 1);
    out.push_back(static_cast<uint8_t>(t));
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

bool decode(std::span<const uint8_t> in, MsgType& t, std::string& body) {
    if (in.empty()) return false;
    uint8_t raw = in[0];
    if (raw < 1 || raw > 3) return false;
    t = static_cast<MsgType>(raw);
    body.assign(reinterpret_cast<const char*>(in.data()) + 1, in.size() - 1);
    // Cap it: a peer is authenticated as a topic member, not trusted to be
    // well-behaved.
    if (body.size() > 4000) body.resize(4000);
    // Strip control characters so a peer cannot rewrite our terminal with
    // escape sequences.
    std::erase_if(body, [](char c) {
        auto u = static_cast<unsigned char>(c);
        return u < 0x20 && c != '\t';
    });
    return true;
}

std::string short_id(const DevId& d) { return to_hex(d).substr(0, 8); }

// ---------------------------------------------------------------------------
// Roster
// ---------------------------------------------------------------------------
struct Roster {
    struct Entry {
        std::string nick;
        PeerState   state = PeerState::Unknown;
        bool        greeted = false;
    };

    std::mutex                 mu;
    std::map<std::string, Entry> by_id;  // hex dev_id -> entry

    std::string name_of(const DevId& d) {
        std::lock_guard<std::mutex> lk(mu);
        auto it = by_id.find(to_hex(d));
        if (it == by_id.end() || it->second.nick.empty()) return short_id(d);
        return it->second.nick + "(" + short_id(d) + ")";
    }

    void set_nick(const DevId& d, const std::string& n) {
        std::lock_guard<std::mutex> lk(mu);
        by_id[to_hex(d)].nick = n;
    }

    void set_state(const DevId& d, PeerState s) {
        std::lock_guard<std::mutex> lk(mu);
        by_id[to_hex(d)].state = s;
    }

    bool mark_greeted(const DevId& d) {
        std::lock_guard<std::mutex> lk(mu);
        auto& e = by_id[to_hex(d)];
        if (e.greeted) return false;
        e.greeted = true;
        return true;
    }

    void forget_greeting(const DevId& d) {
        std::lock_guard<std::mutex> lk(mu);
        by_id[to_hex(d)].greeted = false;
    }
};

// A stable colour per peer, so the eye can follow a conversation.
const char* color_for(const DevId& d, const chatui::Palette& p, bool ansi) {
    if (!ansi) return "";
    const char* wheel[] = {p.cyan, p.green, p.yellow, p.blue, p.red};
    return wheel[d[0] % 5];
}

void usage() {
    std::printf(
        "uconn-chat -- peer-to-peer chat over uConnect\n"
        "\n"
        "  --server <host:port>    rendezvous server (required)\n"
        "  --topic <uconn://...>   join an existing topic\n"
        "  --create                create a keyed topic and print its invite\n"
        "  --create-open           create an OPEN topic (no authentication)\n"
        "  --nick <name>           your display name (default: your username)\n"
        "  --listed                opt in to the server's public topic listing\n"
        "  --port <n>              bind a specific local UDP port\n"
        "\n"
        "Type a message and press Enter to send it to everyone.\n"
        "Commands: /help /who /peers /invite /sas /nick /connect /part /quit\n");
}

std::string default_nick() {
    const char* candidates[] = {"USERNAME", "USER", "LOGNAME"};
    for (const char* c : candidates) {
        if (const char* v = std::getenv(c)) {
            if (*v) return v;
        }
    }
    return "anon";
}

std::string trim(std::string s) {
    size_t b = s.find_first_not_of(" \t");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t");
    return s.substr(b, e - b + 1);
}

std::string timestamp() {
    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%02d:%02d", tm.tm_hour, tm.tm_min);
    return buf;
}

}  // namespace

int main(int argc, char** argv) {
    std::string server, topic_uri, nick = default_nick();
    bool        create = false, create_open = false, listed = false;
    uint16_t    port = 0;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](int& idx) -> const char* {
            return idx + 1 < argc ? argv[++idx] : nullptr;
        };
        if (a == "--help" || a == "-h") { usage(); return 0; }
        else if (a == "--create") create = true;
        else if (a == "--create-open") create_open = true;
        else if (a == "--listed") listed = true;
        else if (a == "--server") { if (auto* v = next(i)) server = v; }
        else if (a == "--topic")  { if (auto* v = next(i)) topic_uri = v; }
        else if (a == "--nick")   { if (auto* v = next(i)) nick = v; }
        else if (a == "--port")   { if (auto* v = next(i)) port = static_cast<uint16_t>(std::atoi(v)); }
        else { std::fprintf(stderr, "unknown option: %s\n\n", a.c_str()); usage(); return 2; }
    }

    if (server.empty()) { usage(); return 2; }
    if (!create && !create_open && topic_uri.empty()) {
        std::fprintf(stderr, "need --topic, --create or --create-open\n\n");
        usage();
        return 2;
    }

    TopicCreds creds;
    if (create || create_open) {
        creds = create_open ? TopicCreds::generate_open() : TopicCreds::generate_keyed();
    } else {
        auto parsed = TopicCreds::parse(topic_uri);
        if (!parsed) { std::fprintf(stderr, "malformed topic URI\n"); return 2; }
        creds = *parsed;
    }

    chatui::Terminal term;
    const auto&      C    = term.colors();
    const bool       ansi = term.has_ansi();
    Roster           roster;
    std::atomic<bool> stop{false};

    auto say = [&](const std::string& s) { term.print(s); };
    auto sys = [&](const std::string& s) {
        term.print(std::string(C.dim) + "* " + s + C.reset);
    };

    try {
        Node::Config cfg;
        cfg.server    = server;
        cfg.bind_port = port;
        Node node{cfg};
        node.run_in_background();

        auto& topic = node.join(creds);

        say(std::string(C.bold) + "uconn-chat" + C.reset + C.dim +
            "  peer-to-peer, no chat server" + C.reset);
        sys("topic " + to_hex(creds.id));
        if (topic.is_authenticated()) {
            sys(std::string(C.green) + "keyed topic: mutually authenticated, "
                "forward secret" + C.reset);
        } else {
            sys(std::string(C.red) +
                "OPEN topic: encrypted against passive observers ONLY." + C.reset);
            sys(std::string(C.red) +
                "anyone on path, including the rendezvous server, can read and "
                "alter messages." + C.reset);
            sys(std::string(C.dim) + "use /sas <peer> and compare out of band to "
                "detect a MITM." + C.reset);
        }
        if (create || create_open) {
            say("");
            say(std::string(C.bold) + "invite others with:" + C.reset);
            say("  " + std::string(C.cyan) + creds.to_uri() + C.reset);
            say("");
        }

        // --- wire the library's callbacks -----------------------------------
        // These run on the node's loop thread with no lock held, so calling
        // back into the library from here is safe.
        topic.on_peer([&](DevId dev, PeerState st) {
            roster.set_state(dev, st);
            switch (st) {
                case PeerState::Connected: {
                    // Announce ourselves. This is application-layer identity;
                    // the transport has already proven topic membership.
                    if (roster.mark_greeted(dev)) {
                        auto hello = encode(MsgType::Hello, nick);
                        topic.send(dev, hello);
                    }
                    term.printf("%s* %s connected%s", C.green,
                                roster.name_of(dev).c_str(), C.reset);
                    break;
                }
                case PeerState::Failed:
                    term.printf("%s* %s unreachable (punch failed -- likely "
                                "symmetric NAT on both ends)%s",
                                C.dim, short_id(dev).c_str(), C.reset);
                    roster.forget_greeting(dev);
                    break;
                case PeerState::Closed:
                    term.printf("%s* %s disconnected%s", C.dim,
                                roster.name_of(dev).c_str(), C.reset);
                    roster.forget_greeting(dev);
                    break;
                default:
                    break;
            }
        });

        topic.on_data([&](DevId dev, std::span<const uint8_t> bytes) {
            MsgType     t{};
            std::string body;
            if (!decode(bytes, t, body)) return;

            switch (t) {
                case MsgType::Hello: {
                    if (body.empty() || body.size() > 32) body = short_id(dev);
                    roster.set_nick(dev, body);
                    term.printf("%s* %s is %s%s", C.dim, short_id(dev).c_str(),
                                body.c_str(), C.reset);
                    break;
                }
                case MsgType::Text:
                    term.printf("%s %s%s%s: %s", timestamp().c_str(),
                                color_for(dev, C, ansi), roster.name_of(dev).c_str(),
                                C.reset, body.c_str());
                    break;
                case MsgType::Bye:
                    term.printf("%s* %s left%s", C.dim, roster.name_of(dev).c_str(),
                                C.reset);
                    break;
            }
        });

        std::vector<uint8_t> meta(nick.begin(), nick.end());
        if (!topic.publish(meta, listed)) {
            std::fprintf(stderr,
                         "could not register with %s -- is the rendezvous server "
                         "running?\n",
                         server.c_str());
            return 1;
        }
        auto self = topic.self();
        sys("joined as " + nick + " (" + (self ? short_id(*self) : "?") + ")");
        sys("type /help for commands");

        term.set_prompt("[" + nick + "] ");

        // --- background: discover and connect to new peers -------------------
        std::thread discovery([&] {
            while (!stop) {
                auto list = topic.peers();
                for (const auto& p : list) {
                    if (stop) break;
                    if (p.stale) continue;
                    if (topic.state(p.dev_id) == PeerState::Unknown) {
                        // Metadata carries the nickname, so the roster has a
                        // name even before the peer connects. It is unsigned and
                        // server-visible -- display only.
                        if (!p.meta.empty()) {
                            roster.set_nick(p.dev_id,
                                            std::string(p.meta.begin(), p.meta.end()));
                        }
                        topic.connect(p.dev_id);
                    }
                }
                for (int i = 0; i < 30 && !stop; ++i) std::this_thread::sleep_for(100ms);
            }
        });

        // --- main loop: read input -------------------------------------------
        while (!stop) {
            auto line = term.poll_line(stop);
            if (!line) break;
            std::string s = trim(*line);
            if (s.empty()) continue;

            if (s[0] != '/') {
                size_t n = topic.broadcast(
                    encode(MsgType::Text,
                           std::string_view(s)));
                if (n == 0) {
                    sys(std::string(C.dim) + "no one connected yet -- message not sent" +
                        C.reset);
                } else {
                    term.printf("%s %s%s%s: %s", timestamp().c_str(), C.bold, nick.c_str(),
                                C.reset, s.c_str());
                }
                continue;
            }

            // --- commands ---
            std::string cmd = s, arg;
            if (auto sp = s.find(' '); sp != std::string::npos) {
                cmd = s.substr(0, sp);
                arg = trim(s.substr(sp + 1));
            }

            if (cmd == "/quit" || cmd == "/exit") {
                topic.broadcast(encode(MsgType::Bye, nick));
                std::this_thread::sleep_for(100ms);
                stop = true;
                break;
            }
            else if (cmd == "/help") {
                sys("/who              peers you are connected to");
                sys("/peers            everyone registered in the topic");
                sys("/invite           print the topic URI");
                sys("/sas [peer]       authentication string to compare out of band");
                sys("/nick <name>      change your display name");
                sys("/connect <peer>   connect to a peer by dev_id prefix");
                sys("/part <peer>      disconnect from a peer");
                sys("/stats            rendezvous server counters");
                sys("/quit             leave");
            }
            else if (cmd == "/who") {
                auto conn = topic.connected();
                if (conn.empty()) { sys("no peers connected"); continue; }
                sys(std::to_string(conn.size()) + " connected:");
                for (const auto& d : conn) {
                    std::string line2 = "  " + roster.name_of(d);
                    if (auto sasv = topic.sas(d)) line2 += "  sas:" + *sasv;
                    sys(line2);
                }
            }
            else if (cmd == "/peers") {
                auto list = topic.peers(30, true);
                if (list.empty()) { sys("no other peers registered"); continue; }
                sys(std::to_string(list.size()) + " registered in topic:");
                for (const auto& p : list) {
                    std::string nm(p.meta.begin(), p.meta.end());
                    sys("  " + short_id(p.dev_id) + "  " + (nm.empty() ? "?" : nm) +
                        "  " + to_string(topic.state(p.dev_id)) +
                        (p.stale ? "  (stale)" : "") + "  age=" +
                        std::to_string(p.age.count()) + "s");
                }
            }
            else if (cmd == "/invite") {
                say("  " + std::string(C.cyan) + creds.to_uri() + C.reset);
                if (!topic.is_authenticated()) {
                    sys(std::string(C.red) + "this is an OPEN topic -- anyone who "
                        "learns the id can join and read everything" + C.reset);
                }
            }
            else if (cmd == "/nick") {
                if (arg.empty() || arg.size() > 32) { sys("usage: /nick <name>"); continue; }
                nick = arg;
                term.set_prompt("[" + nick + "] ");
                std::vector<uint8_t> m(nick.begin(), nick.end());
                topic.publish(m, listed);  // republish metadata
                topic.broadcast(encode(MsgType::Hello, nick));
                sys("you are now " + nick);
            }
            else if (cmd == "/sas") {
                auto conn = topic.connected();
                if (conn.empty()) { sys("no peers connected"); continue; }
                for (const auto& d : conn) {
                    if (!arg.empty() && to_hex(d).rfind(arg, 0) != 0) continue;
                    auto sasv = topic.sas(d);
                    sys(roster.name_of(d) + ": " +
                        (sasv ? *sasv : std::string("(not established)")));
                }
                sys(std::string(C.dim) +
                    "compare over a channel an attacker does not control. "
                    "matching strings mean no MITM." + C.reset);
            }
            else if (cmd == "/connect") {
                if (arg.empty()) { sys("usage: /connect <dev_id prefix>"); continue; }
                bool found = false;
                for (const auto& p : topic.peers()) {
                    if (to_hex(p.dev_id).rfind(arg, 0) == 0) {
                        topic.connect(p.dev_id);
                        sys("connecting to " + short_id(p.dev_id));
                        found = true;
                    }
                }
                if (!found) sys("no peer matching '" + arg + "'");
            }
            else if (cmd == "/part") {
                if (arg.empty()) { sys("usage: /part <dev_id prefix>"); continue; }
                for (const auto& d : topic.connected()) {
                    if (to_hex(d).rfind(arg, 0) == 0) {
                        topic.send(d, encode(MsgType::Bye, nick));
                        topic.disconnect(d);
                        sys("disconnected " + short_id(d));
                    }
                }
            }
            else if (cmd == "/stats") {
                auto st = node.stats();
                if (!st) { sys("no reply from server"); continue; }
                sys("records=" + std::to_string(st->entries_total) +
                    " fresh=" + std::to_string(st->entries_fresh) +
                    " topics=" + std::to_string(st->topics_total) +
                    " lookups=" + std::to_string(st->lookups) +
                    " relays=" + std::to_string(st->connects));
            }
            else {
                sys("unknown command: " + cmd + "  (try /help)");
            }
        }

        stop = true;
        if (discovery.joinable()) discovery.join();
        term.restore();
        std::printf("\nleaving...\n");
        node.shutdown();
        return 0;

    } catch (const std::exception& e) {
        term.restore();
        std::fprintf(stderr, "\nfatal: %s\n", e.what());
        return 1;
    }
}
