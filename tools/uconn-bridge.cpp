// uconn-bridge -- join a topic as a real peer and speak JSON lines on stdio.
//
//   echo 'uconn://<id>#<key>' | uconn-bridge --server host:port --nick alice
//
// This is what lets a browser take part in a topic. A browser cannot be a
// uConnect peer: it has no UDP socket, cannot hole-punch, and cannot run the
// Noise handshake. So the web app runs one of these per chat session and
// relays between it and the page.
//
// THE KEY IS THE POINT OF THIS FILE, AND THE PRICE OF IT.
//
// To join a keyed topic something must hold K and run the handshake. For a
// browser client that something is the server. A web chat therefore trusts the
// host it is talking to with the topic key, and that host can read everything
// in the topic. Native clients do not make that trade. Every caller of this
// binary is obliged to say so plainly to whoever is typing.
//
// The topic URI arrives on STDIN, never as an argument: argv is visible in
// `ps` to every user on the machine, and a topic key in a process listing is
// a key in a log, a monitoring agent, and a support ticket.
//
// Protocol on stdout, one JSON object per line:
//   {"t":"ready","dev":"..","topic":"..","keyed":true}
//   {"t":"peer","dev":"..","state":"connected"}
//   {"t":"gone","dev":"..","why":"going-away"}
//   {"t":"nick","dev":"..","nick":".."}
//   {"t":"msg","dev":"..","text":".."}
//   {"t":"error","message":".."}
// On stdin, one per line:
//   {"cmd":"say","text":".."}
//   {"cmd":"bye"}

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "uconnect/uconnect.hpp"

using namespace uconnect;
using namespace std::chrono_literals;

namespace {

// Same framing as examples/chat, so a browser peer and a terminal peer are in
// the same conversation rather than two that merely share a topic id.
enum class MsgType : uint8_t { Hello = 1, Text = 2, Bye = 3 };

std::vector<uint8_t> encode(MsgType t, std::string_view body) {
    std::vector<uint8_t> out;
    out.reserve(body.size() + 1);
    out.push_back(static_cast<uint8_t>(t));
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

std::mutex g_out;

std::string json_escape(std::string_view s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char b[8];
                    std::snprintf(b, sizeof(b), "\\u%04x", c);
                    o += b;
                } else {
                    o += c;
                }
        }
    }
    return o;
}

void emit(const std::string& line) {
    std::lock_guard<std::mutex> lk(g_out);
    std::fputs(line.c_str(), stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);   // the reader is a pipe; without this nothing arrives
}

std::string short_id(const DevId& d) { return to_hex(d).substr(0, 12); }

// A peer is authenticated as a topic member, not trusted to be well behaved.
// Strip control characters before anything downstream renders them, and cap
// the length so one peer cannot flood a page.
std::string sanitise(std::string s) {
    if (s.size() > 2000) s.resize(2000);
    std::erase_if(s, [](char c) {
        auto u = static_cast<unsigned char>(c);
        return u < 0x20 && c != '\t';
    });
    return s;
}

// Enough of a JSON reader for two commands with one string field. Pulling in a
// parser for this would be the only external dependency in the project.
std::string field(std::string_view line, std::string_view key) {
    std::string pat = "\"";
    pat += key;
    pat += "\"";
    auto k = line.find(pat);
    if (k == std::string_view::npos) return {};
    auto c = line.find(':', k + pat.size());
    if (c == std::string_view::npos) return {};
    auto q = line.find('"', c);
    if (q == std::string_view::npos) return {};

    std::string out;
    for (size_t i = q + 1; i < line.size(); ++i) {
        char ch = line[i];
        if (ch == '\\' && i + 1 < line.size()) {
            char n = line[++i];
            switch (n) {
                case 'n': out += '\n'; break;
                case 't': out += '\t'; break;
                case 'r': break;
                case 'u': {
                    // Decode \uXXXX so text typed in a browser survives. Only
                    // the BMP below 0x800 is handled directly; anything higher
                    // is passed through as a replacement rather than mangled.
                    if (i + 4 < line.size()) {
                        unsigned code = std::strtoul(std::string(line.substr(i + 1, 4)).c_str(),
                                                     nullptr, 16);
                        i += 4;
                        if (code < 0x80) {
                            out += static_cast<char>(code);
                        } else if (code < 0x800) {
                            out += static_cast<char>(0xC0 | (code >> 6));
                            out += static_cast<char>(0x80 | (code & 0x3F));
                        } else {
                            out += static_cast<char>(0xE0 | (code >> 12));
                            out += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
                            out += static_cast<char>(0x80 | (code & 0x3F));
                        }
                    }
                    break;
                }
                default: out += n;
            }
        } else if (ch == '"') {
            break;
        } else {
            out += ch;
        }
    }
    return out;
}

void usage() {
    std::printf(
        "uconn-bridge -- join a topic and relay it over stdio as JSON\n"
        "\n"
        "  --server <host:port>   rendezvous server (required)\n"
        "  --nick <name>          name announced to the topic\n"
        "  --seconds <n>          hard lifetime, default 1800\n"
        "\n"
        "The topic URI is read from the FIRST LINE OF STDIN, not from argv,\n"
        "so the key never appears in a process listing.\n");
}

}  // namespace

int main(int argc, char** argv) {
    std::string server, nick = "web";
    int         seconds = 1800;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](int& idx) -> const char* { return idx + 1 < argc ? argv[++idx] : nullptr; };
        if (a == "--help" || a == "-h") { usage(); return 0; }
        else if (a == "--server")  { if (auto* v = next(i)) server = v; }
        else if (a == "--nick")    { if (auto* v = next(i)) nick = v; }
        else if (a == "--seconds") { if (auto* v = next(i)) seconds = std::atoi(v); }
        else { std::fprintf(stderr, "unknown option: %s\n", a.c_str()); return 2; }
    }
    if (server.empty()) { usage(); return 2; }

    std::string uri;
    if (!std::getline(std::cin, uri)) {
        emit(R"({"t":"error","message":"no topic on stdin"})");
        return 2;
    }
    while (!uri.empty() && (uri.back() == '\r' || uri.back() == '\n')) uri.pop_back();

    auto creds = TopicCreds::parse(uri);
    if (!creds) {
        emit(R"({"t":"error","message":"bad topic URI"})");
        return 2;
    }
    nick = sanitise(nick);
    if (nick.empty() || nick.size() > 24) nick = "web";

    try {
        Node::Config cfg;
        cfg.server = server;
        Node node{cfg};
        node.run_in_background();

        auto& topic = node.join(*creds);

        topic.on_data([&](DevId dev, std::span<const uint8_t> bytes) {
            if (bytes.empty()) return;
            uint8_t raw = bytes[0];
            if (raw < 1 || raw > 3) return;
            std::string body(reinterpret_cast<const char*>(bytes.data()) + 1,
                             bytes.size() - 1);
            body = sanitise(std::move(body));

            switch (static_cast<MsgType>(raw)) {
                case MsgType::Hello:
                    if (body.empty() || body.size() > 24) body = short_id(dev);
                    emit("{\"t\":\"nick\",\"dev\":\"" + to_hex(dev) + "\",\"nick\":\"" +
                         json_escape(body) + "\"}");
                    break;
                case MsgType::Text:
                    emit("{\"t\":\"msg\",\"dev\":\"" + to_hex(dev) + "\",\"text\":\"" +
                         json_escape(body) + "\"}");
                    break;
                case MsgType::Bye:
                    emit("{\"t\":\"gone\",\"dev\":\"" + to_hex(dev) +
                         "\",\"why\":\"said-bye\"}");
                    break;
            }
        });

        topic.on_peer([&](DevId dev, PeerState st) {
            emit("{\"t\":\"peer\",\"dev\":\"" + to_hex(dev) + "\",\"state\":\"" +
                 to_string(st) + "\"}");
            if (st == PeerState::Connected) {
                topic.send(dev, encode(MsgType::Hello, nick));
            }
        });

        topic.on_peer_closed([&](DevId dev, PeerGone why) {
            emit("{\"t\":\"gone\",\"dev\":\"" + to_hex(dev) + "\",\"why\":\"" +
                 to_string(why) + "\"}");
        });

        // Metadata is the nickname, so this peer shows up in the dashboard
        // roster the same way a terminal client does. Listed by default -- the
        // topic should appear in the directory once someone is actually in it.
        std::vector<uint8_t> meta(nick.begin(), nick.end());
        if (!topic.publish(meta)) {
            emit(R"({"t":"error","message":"publish failed; is the rendezvous server up?"})");
            return 1;
        }
        topic.set_auto_connect(true);

        auto self = topic.self();
        emit("{\"t\":\"ready\",\"dev\":\"" + (self ? to_hex(*self) : std::string("")) +
             "\",\"topic\":\"" + to_hex(creds->id) + "\",\"keyed\":" +
             (creds->is_keyed() ? "true" : "false") + "}");

        // A hard lifetime. These are spawned by a web request, and without a
        // ceiling a browser that vanished mid-conversation would leave a real
        // UDP node registered and punching until the box was rebooted.
        std::atomic<bool> stop{false};
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
        std::thread timer([&] {
            while (!stop && std::chrono::steady_clock::now() < deadline) {
                std::this_thread::sleep_for(500ms);
            }
            if (!stop) {
                emit(R"({"t":"error","message":"session lifetime reached"})");
                stop = true;
                // Nudge the reader loop: it is blocked on stdin, and closing
                // stdin from another thread is the portable way out.
                std::fclose(stdin);
            }
        });

        std::string line;
        while (!stop && std::getline(std::cin, line)) {
            auto cmd = field(line, "cmd");
            if (cmd == "bye") break;
            if (cmd != "say") continue;
            auto text = sanitise(field(line, "text"));
            if (text.empty()) continue;
            topic.broadcast(encode(MsgType::Text, text));
            // Echo it back so the page renders one source of truth rather than
            // optimistically painting a message that may never have been sent.
            emit("{\"t\":\"msg\",\"dev\":\"" + (self ? to_hex(*self) : std::string("")) +
                 "\",\"text\":\"" + json_escape(text) + "\",\"self\":true}");
        }

        stop = true;
        timer.join();
        topic.broadcast(encode(MsgType::Bye, nick));
        std::this_thread::sleep_for(150ms);   // let the Bye actually leave
        node.shutdown();
        return 0;
    } catch (const std::exception& e) {
        emit("{\"t\":\"error\",\"message\":\"" + json_escape(e.what()) + "\"}");
        return 1;
    }
}
