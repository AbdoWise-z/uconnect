// The rendezvous server's configuration: the YAML subset, the schema behind
// it, the command line's precedence over the file, and -- once -- that a
// value read from the file really governs a running server.

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "config.hpp"
#include "rendezvous.hpp"
#include "socket.hpp"
#include "testing.hpp"

using namespace uconnect;
using namespace uconnect::server;
using namespace std::chrono_literals;

namespace {

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

// Every value away from its default, and in range.
RendezvousConfig scrambled() {
    RendezvousConfig c;
    c.port                            = 5001;
    c.bind_host                       = "127.0.0.1";
    c.threads                         = 3;
    c.max_connections                 = 123;
    c.max_connections_per_ip          = 7;
    c.idle_timeout                    = 61s;
    c.first_frame_timeout             = 3s;
    c.registry.stale_after            = 2h;
    c.registry.max_per_ip_per_topic   = 2;
    c.registry.max_per_ip_total       = 9;
    c.registry.max_entries            = 77;
    c.registry.max_topics             = 55;
    c.registry.relay_enabled          = false;
    c.registry.relay_expiry           = 5s;
    c.registry.max_relays             = 11;
    c.registry.max_relays_per_ip      = 99;
    c.registry.relay_max_bytes        = 3ull << 30;
    c.relay_join_timeout              = 4s;
    c.splice_buffer                   = 4097;
    c.control.rate_bytes_per_sec      = 1;
    c.control.rate_burst_bytes        = 64 * 1024;
    c.control.udp_bytes_per_sec       = 12345;
    c.control.udp_burst_bytes         = 1 << 20;
    return c;
}

// The value lines of a to_yaml() document: "key: value", sections excluded.
std::vector<std::string> value_lines(const std::string& doc) {
    std::vector<std::string> out;
    size_t                   pos = 0;
    while (pos < doc.size()) {
        size_t nl = doc.find('\n', pos);
        if (nl == std::string::npos) nl = doc.size();
        std::string line = doc.substr(pos, nl - pos);
        pos              = nl + 1;
        if (!line.empty() && line[0] != '#' && line.back() != ':') out.push_back(line);
    }
    return out;
}

// A file of `text` in the temp directory, removed when this goes.
struct TempFile {
    std::filesystem::path path;
    explicit TempFile(const std::string& text) {
        std::random_device rd;
        path = std::filesystem::temp_directory_path() /
               ("uconnect-config-" + std::to_string(rd()) + ".yaml");
        std::ofstream(path, std::ios::binary) << text;
    }
    ~TempFile() {
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
    std::string str() const { return path.string(); }
};

// The error apply_config gives for `doc`, or "" if it accepted it.
std::string rejection(const std::string& doc) {
    RendezvousConfig cfg;
    std::string      err;
    return apply_config(doc, cfg, err) ? "" : err;
}

}  // namespace

// ---------------------------------------------------------------------------
// The file
// ---------------------------------------------------------------------------
TEST(config_example_file_sets_every_key_to_its_default) {
    // Loaded over a config whose every value differs from the defaults, the
    // example must give back the defaults exactly -- so it names every key,
    // and names it at its true default.
    const RendezvousConfig defaults;
    const auto             base = value_lines(to_yaml(defaults));
    const auto             away = value_lines(to_yaml(scrambled()));
    REQUIRE(base.size() == away.size());
    for (size_t i = 0; i < base.size(); ++i) CHECK(base[i] != away[i]);  // scrambled() is complete

    RendezvousConfig cfg = scrambled();
    std::string      err;
    REQUIRE(load_config_file(UCONNECT_SOURCE_DIR "/server/rendezvous.example.yaml", cfg, err));
    CHECK(to_yaml(cfg) == to_yaml(defaults));
}

TEST(config_round_trips_through_to_yaml) {
    const RendezvousConfig want = scrambled();
    RendezvousConfig       got;
    std::string            err;
    REQUIRE(apply_config(to_yaml(want), got, err));
    CHECK(to_yaml(got) == to_yaml(want));
}

TEST(config_changes_only_the_keys_it_names) {
    RendezvousConfig cfg;
    std::string      err;
    REQUIRE(apply_config("relay:\n"
                         "  max_bytes: 1GiB\n"
                         "  max_per_ip: 100\n"
                         "connections:\n"
                         "  idle_timeout: 2m\n"
                         "rate_limits:\n"
                         "  udp_bytes_per_sec: 512 KiB\n",
                         cfg, err));
    CHECK(cfg.registry.relay_max_bytes == (1ull << 30));
    CHECK_EQ(cfg.registry.max_relays_per_ip, 100u);
    CHECK(cfg.idle_timeout == 120s);
    CHECK_EQ(cfg.control.udp_bytes_per_sec, 512u * 1024);

    const RendezvousConfig d;
    CHECK_EQ(cfg.port, d.port);
    CHECK_EQ(cfg.registry.max_relays, d.registry.max_relays);
    CHECK(cfg.registry.stale_after == d.registry.stale_after);
}

TEST(config_reads_comments_quotes_crlf_and_a_document_start) {
    RendezvousConfig cfg;
    std::string      err;
    REQUIRE(apply_config("---\r\n"
                         "# a comment\r\n"
                         "\r\n"
                         "port: 0   # ephemeral\r\n"
                         "bind: '10.0.0.1 # not a comment'\r\n"
                         "relay:\r\n"
                         "    enabled: false\r\n",
                         cfg, err));
    CHECK_EQ(cfg.port, 0u);
    CHECK(cfg.bind_host == "10.0.0.1 # not a comment");
    CHECK(!cfg.registry.relay_enabled);

    REQUIRE(apply_config("bind: \"a\\\"b\\\\c\"\n", cfg, err));
    CHECK(cfg.bind_host == "a\"b\\c");
    REQUIRE(apply_config("bind: 'it''s'\n", cfg, err));
    CHECK(cfg.bind_host == "it's");
    REQUIRE(apply_config("", cfg, err));  // empty: nothing changes
    REQUIRE(apply_config("# only a comment\n", cfg, err));
}

TEST(config_rejects_what_it_cannot_read_and_says_where) {
    struct Case {
        const char* doc;
        const char* says;
    };
    const Case cases[] = {
        {"port: 1\nrelay:\n  max_byte: 1MiB\n", "line 3: unknown key 'relay.max_byte'"},
        {"nonsense: 1\n", "line 1: unknown key 'nonsense'"},
        {"relay:\n\tmax: 1\n", "line 2: tabs are not allowed"},
        {"port:\n  - 1\n", "line 2: lists are not supported"},
        {"relay: {max: 1}\n", "line 1: flow collections are not supported"},
        {"port: &p 1\n", "line 1: anchors and aliases"},
        {"port: !!int 1\n", "line 1: tags are not supported"},
        {"bind: |\n  x\n", "line 1: block scalars are not supported"},
        {"port: 1\nport: 2\n", "line 2: duplicate key 'port' (first on line 1)"},
        {"relay:\n    max: 1\n  expiry: 5s\n", "line 3: unexpected indentation"},
        {"  port: 1\n", "line 1: the top level must not be indented"},
        {"port:\n", "line 1: 'port' has no value"},
        {"relay: 5\n", "line 1: 'relay' is a section"},
        {"port:\n  x: 1\n", "line 1: 'port' takes a value, not a section"},
        {"port 1\n", "line 1: expected 'key: value'"},
        {"port: 44x\n", "line 1: 'port' must be a whole number, not '44x'"},
        {"port: -1\n", "must be a whole number"},
        {"port: 70000\n", "line 1: 'port' must be at most 65535"},
        {"threads: 0\n", "line 1: 'threads' must be at least 1"},
        {"threads: 1000\n", "line 1: 'threads' must be at most 256"},
        {"registry:\n  max_entries: 99999999999999999999999\n", "line 2: 'registry.max_entries' must be a whole number"},
        {"registry:\n  max_entries: 0\n", "'registry.max_entries' must be at least 1"},
        {"relay:\n  max_bytes: 32MB\n", "'relay.max_bytes' must be a size"},
        {"relay:\n  max_bytes: 5000GiB\n", "'relay.max_bytes' must be at most"},
        {"relay:\n  max_bytes: 100\n", "'relay.max_bytes' must be at least 1KiB"},
        {"relay:\n  enabled: yes\n", "'relay.enabled' must be true or false"},
        {"relay:\n  expiry: 0s\n", "'relay.expiry' must be at least 1s"},
        {"relay:\n  expiry: 5 minutes\n", "must be a duration"},
        {"rate_limits:\n  control_bytes_per_sec: 0\n", "'rate_limits.control_bytes_per_sec' must be at least 1"},
        {"rate_limits:\n  control_burst_bytes: 32KiB\n", "'rate_limits.control_burst_bytes' must be at least 32832"},
        {"rate_limits:\n  udp_burst_bytes: 1KiB\n", "'rate_limits.udp_burst_bytes' must be at least 2KiB"},
        {"bind: 'open\n", "line 1: unterminated quoted value"},
        {"bind: \"a\" b\n", "line 1: unexpected text after a quoted value"},
        {"bind: \"\\q\"\n", "line 1: unsupported escape"},
        {"port: 1\n---\nport: 2\n", "line 2: only one document is supported"},
    };
    for (const auto& c : cases) {
        const std::string got = rejection(c.doc);
        if (!contains(got, c.says)) {
            ::testing::fail(__FILE__, __LINE__,
                            std::string("for:\n") + c.doc + "expected: " + c.says + "\ngot: " +
                                (got.empty() ? "(accepted)" : got));
        }
    }
}

TEST(config_that_fails_changes_nothing) {
    RendezvousConfig cfg;
    std::string      err;
    CHECK(!apply_config("port: 1\nrelay:\n  max: 3\nbogus: 2\n", cfg, err));
    CHECK_EQ(cfg.port, RendezvousConfig{}.port);
    CHECK_EQ(cfg.registry.max_relays, RendezvousConfig{}.registry.max_relays);
}

TEST(config_file_errors_name_the_file_and_line) {
    TempFile         f("port: 1\nrelay:\n  max: none\n");
    RendezvousConfig cfg;
    std::string      err;
    CHECK(!load_config_file(f.str(), cfg, err));
    CHECK(contains(err, f.str() + ":3: 'relay.max' must be a whole number"));

    CHECK(!load_config_file(f.str() + ".missing", cfg, err));
    CHECK(contains(err, "cannot open"));
}

// ---------------------------------------------------------------------------
// The command line
// ---------------------------------------------------------------------------
TEST(server_flags_override_the_config_file_wherever_they_appear) {
    TempFile f("port: 5000\nregistry:\n  max_per_ip_per_topic: 3\n  stale_after: 1m\n");

    ServerOptions o;
    std::string   err;
    REQUIRE(parse_server_args({"--port", "6000", "--config", f.str(), "--no-relay", "--quiet"}, o, err));
    CHECK_EQ(o.cfg.port, 6000u);                         // the flag, though it came first
    CHECK_EQ(o.cfg.registry.max_per_ip_per_topic, 3u);   // the file
    CHECK(o.cfg.registry.stale_after == 60s);            // the file
    CHECK(!o.cfg.registry.relay_enabled);                // the flag
    CHECK(o.quiet);
    CHECK(!o.print_config);

    REQUIRE(parse_server_args({"--config", f.str(), "--stale", "90s", "--max-per-ip", "9",
                               "--bind", "0.0.0.0", "--threads", "4", "--print-config"}, o, err));
    CHECK_EQ(o.cfg.threads, 4u);
    CHECK(o.cfg.registry.stale_after == 90s);
    CHECK_EQ(o.cfg.registry.max_per_ip_per_topic, 9u);
    CHECK(o.cfg.bind_host == "0.0.0.0");
    CHECK_EQ(o.cfg.port, 5000u);
    CHECK(o.print_config);

    REQUIRE(parse_server_args({}, o, err));  // nothing at all: the defaults
    CHECK(to_yaml(o.cfg) == to_yaml(RendezvousConfig{}));
}

TEST(server_flags_are_held_to_the_same_rules_as_the_file) {
    struct Case {
        std::vector<std::string> args;
        const char*              says;
    };
    const Case cases[] = {
        {{"--bogus"}, "unknown option: --bogus"},
        {{"--port"}, "--port needs a value"},
        {{"--port", "abc"}, "--port: 'port' must be a whole number"},
        {{"--port", "65536"}, "--port: 'port' must be at most 65535"},
        {{"--max-per-ip", "0"}, "--max-per-ip: 'registry.max_per_ip_per_topic' must be at least 1"},
        {{"--stale", "0"}, "'registry.stale_after' must be at least 1s"},
        {{"--config", "a.yaml", "--config", "b.yaml"}, "--config given twice"},
        {{"--config", "/no/such/uconnect.yaml"}, "cannot open"},
    };
    for (const auto& c : cases) {
        ServerOptions o;
        std::string   err;
        if (parse_server_args(c.args, o, err) || !contains(err, c.says)) {
            ::testing::fail(__FILE__, __LINE__,
                            std::string("expected: ") + c.says + "\ngot: " + (err.empty() ? "(accepted)" : err));
        }
    }
}

// ---------------------------------------------------------------------------
// The running server
// ---------------------------------------------------------------------------
TEST(a_configured_limit_governs_the_running_server) {
    // connections.max_per_ip: 1 -- the second connection from loopback must
    // be turned away while the first stays.
    RendezvousConfig cfg;
    std::string      err;
    REQUIRE(apply_config("port: 0\nconnections:\n  max_per_ip: 1\n", cfg, err));
    Rendezvous rv{cfg};
    REQUIRE(rv.open());

    std::atomic<bool> stop{false};
    std::thread       loop([&] {
        while (!stop) rv.poll_once(5ms);
    });

    const Endpoint to{IpAddr::v4(127, 0, 0, 1), rv.port()};
    auto dial = [&](io::TcpSocket& s) {
        if (!s.open(0) || !s.connect(to)) return false;
        const auto deadline = std::chrono::steady_clock::now() + 2s;
        while (s.state() == io::TcpSocket::State::Connecting &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(2ms);
        }
        return s.state() == io::TcpSocket::State::Connected;
    };
    // Closed: recv reports the end rather than "nothing yet".
    auto closed_within = [](io::TcpSocket& s, std::chrono::milliseconds t) {
        std::vector<uint8_t> buf(64);
        const auto           deadline = std::chrono::steady_clock::now() + t;
        while (std::chrono::steady_clock::now() < deadline) {
            if (!s.recv(buf)) return true;
            std::this_thread::sleep_for(5ms);
        }
        return false;
    };

    io::TcpSocket first, second;
    const bool    first_up = dial(first);
    std::this_thread::sleep_for(100ms);  // accepted, and counted against the address
    const bool second_up = dial(second);
    const bool second_closed = second_up && closed_within(second, 3s);
    const bool first_closed  = first_up && closed_within(first, 300ms);

    stop = true;
    loop.join();
    REQUIRE(first_up && second_up);
    CHECK(second_closed);
    CHECK(!first_closed);
}
