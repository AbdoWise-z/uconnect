// The configuration file and command line; see config.hpp.
//
// Three parts. A parser for the YAML subset, which knows nothing of the
// server. A schema -- one row per key -- which every path goes through:
// reading the file, checking ranges, applying a flag, printing the result. And
// the command line, which leans on the schema for its values.

#include "config.hpp"

#include <chrono>
#include <cstdint>
#include <fstream>
#include <functional>
#include <initializer_list>
#include <limits>
#include <optional>
#include <sstream>
#include <utility>

#include "control.hpp"

namespace uconnect::server {

namespace {

// ---------------------------------------------------------------------------
// The YAML subset
// ---------------------------------------------------------------------------
struct YamlNode {
    int                                         line   = 0;
    bool                                        is_map = false;
    std::string                                 scalar;
    std::vector<std::pair<std::string, YamlNode>> entries;  // in document order
};

// One non-blank line, reduced to its indentation, key, and value -- absent
// when the line opens a nested mapping.
struct YamlLine {
    int                        number = 0;
    size_t                     indent = 0;
    std::string                key;
    std::optional<std::string> value;
};

struct ParseError {
    int         line = 0;
    std::string message;
};

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
    return s;
}

// The line without its comment: a '#' that starts the line or follows a
// space, outside quotes.
std::string_view strip_comment(std::string_view s) {
    char quote = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (quote == '"' && c == '\\') {
            ++i;  // the escaped character, whatever it is
        } else if (quote) {
            if (c == quote) quote = 0;
        } else if (c == '\'' || c == '"') {
            quote = c;
        } else if (c == '#' && (i == 0 || s[i - 1] == ' ')) {
            return s.substr(0, i);
        }
    }
    return s;
}

bool key_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '_' || c == '-';
}

std::optional<std::string> parse_scalar(std::string_view s, int line, ParseError& err) {
    const char c = s.front();
    if (c == '\'') {
        std::string out;
        for (size_t i = 1; i < s.size(); ++i) {
            if (s[i] != '\'') {
                out += s[i];
            } else if (i + 1 < s.size() && s[i + 1] == '\'') {
                out += '\'';  // '' is a quote inside single quotes
                ++i;
            } else if (i + 1 == s.size()) {
                return out;
            } else {
                err = {line, "unexpected text after a quoted value"};
                return std::nullopt;
            }
        }
        err = {line, "unterminated quoted value"};
        return std::nullopt;
    }
    if (c == '"') {
        std::string out;
        for (size_t i = 1; i < s.size(); ++i) {
            if (s[i] == '\\' && i + 1 < s.size()) {
                switch (s[++i]) {
                    case '\\': out += '\\'; break;
                    case '"':  out += '"'; break;
                    case 'n':  out += '\n'; break;
                    case 't':  out += '\t'; break;
                    default:
                        err = {line, std::string("unsupported escape \\") + s[i]};
                        return std::nullopt;
                }
            } else if (s[i] == '"') {
                if (i + 1 != s.size()) {
                    err = {line, "unexpected text after a quoted value"};
                    return std::nullopt;
                }
                return out;
            } else {
                out += s[i];
            }
        }
        err = {line, "unterminated quoted value"};
        return std::nullopt;
    }
    // YAML would read these as something other than a plain value. Saying so
    // beats handing the server a string it never meant.
    switch (c) {
        case '[': case '{': err = {line, "flow collections are not supported"}; return std::nullopt;
        case '&': case '*': err = {line, "anchors and aliases are not supported"}; return std::nullopt;
        case '!':           err = {line, "tags are not supported"}; return std::nullopt;
        case '|': case '>': err = {line, "block scalars are not supported"}; return std::nullopt;
        default: break;
    }
    return std::string(s);
}

std::optional<std::vector<YamlLine>> split_lines(std::string_view text, ParseError& err) {
    std::vector<YamlLine> out;
    int                   number = 0;
    for (size_t pos = 0; pos < text.size();) {
        const size_t     nl  = text.find('\n', pos);
        std::string_view raw = text.substr(pos, nl == std::string_view::npos ? std::string_view::npos
                                                                             : nl - pos);
        pos = nl == std::string_view::npos ? text.size() : nl + 1;
        ++number;
        if (!raw.empty() && raw.back() == '\r') raw.remove_suffix(1);

        size_t indent = 0;
        while (indent < raw.size() && raw[indent] == ' ') ++indent;
        std::string_view content = trim(strip_comment(raw.substr(indent)));
        if (content.empty()) continue;
        if (raw[indent] == '\t') {
            err = {number, "tabs are not allowed in indentation"};
            return std::nullopt;
        }
        if (content == "---" && out.empty()) continue;  // the optional document start
        if (content == "---" || content == "...") {
            err = {number, "only one document is supported"};
            return std::nullopt;
        }
        if (content.front() == '-' && (content.size() == 1 || content[1] == ' ')) {
            err = {number, "lists are not supported"};
            return std::nullopt;
        }
        if (content.front() == '[' || content.front() == '{') {
            err = {number, "flow collections are not supported"};
            return std::nullopt;
        }

        size_t k = 0;
        while (k < content.size() && key_char(content[k])) ++k;
        if (k == 0 || k == content.size() || content[k] != ':' ||
            (k + 1 < content.size() && content[k + 1] != ' ')) {
            err = {number, "expected 'key: value' or 'key:'"};
            return std::nullopt;
        }

        YamlLine l;
        l.number = number;
        l.indent = indent;
        l.key    = std::string(content.substr(0, k));
        const std::string_view rest = trim(content.substr(k + 1));
        if (!rest.empty()) {
            l.value = parse_scalar(rest, number, err);
            if (!l.value) return std::nullopt;
        }
        out.push_back(std::move(l));
    }
    return out;
}

// The mapping whose keys sit at `indent`, starting at lines[i].
bool parse_block(const std::vector<YamlLine>& lines, size_t& i, size_t indent, YamlNode& out,
                 ParseError& err) {
    out.is_map = true;
    out.line   = i < lines.size() ? lines[i].number : 0;
    while (i < lines.size() && lines[i].indent == indent) {
        const YamlLine& l = lines[i];
        for (const auto& [key, node] : out.entries) {
            if (key == l.key) {
                err = {l.number, "duplicate key '" + l.key + "' (first on line " +
                                     std::to_string(node.line) + ")"};
                return false;
            }
        }
        YamlNode child;
        child.line = l.number;
        ++i;
        if (l.value) {
            child.scalar = *l.value;
        } else if (i < lines.size() && lines[i].indent > indent) {
            if (!parse_block(lines, i, lines[i].indent, child, err)) return false;
            child.line = l.number;
        } else {
            err = {l.number, "'" + l.key + "' has no value"};
            return false;
        }
        out.entries.emplace_back(l.key, std::move(child));
    }
    if (i < lines.size() && lines[i].indent > indent) {
        err = {lines[i].number, "unexpected indentation"};
        return false;
    }
    return true;
}

std::optional<YamlNode> parse_yaml(std::string_view text, ParseError& err) {
    auto lines = split_lines(text, err);
    if (!lines) return std::nullopt;
    YamlNode root;
    root.is_map = true;
    if (lines->empty()) return root;
    if ((*lines)[0].indent != 0) {
        err = {(*lines)[0].number, "the top level must not be indented"};
        return std::nullopt;
    }
    size_t i = 0;
    if (!parse_block(*lines, i, 0, root, err)) return std::nullopt;
    if (i < lines->size()) {  // a line indented between two levels
        err = {(*lines)[i].number, "unexpected indentation"};
        return std::nullopt;
    }
    return root;
}

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------
enum class Kind { Count, Bytes, Seconds, Bool, Text };

std::optional<uint64_t> parse_uint(std::string_view s) {
    if (s.empty()) return std::nullopt;
    uint64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return std::nullopt;
        const uint64_t d = static_cast<uint64_t>(c - '0');
        if (v > (std::numeric_limits<uint64_t>::max() - d) / 10) return std::nullopt;
        v = v * 10 + d;
    }
    return v;
}

// "123" with an optional unit from `units`, perhaps after one space.
std::optional<uint64_t> parse_with_unit(std::string_view s,
                                        std::initializer_list<std::pair<const char*, uint64_t>> units) {
    size_t digits = 0;
    while (digits < s.size() && s[digits] >= '0' && s[digits] <= '9') ++digits;
    auto n = parse_uint(s.substr(0, digits));
    if (!n) return std::nullopt;
    std::string_view unit = s.substr(digits);
    if (!unit.empty() && unit.front() == ' ') unit.remove_prefix(1);
    if (unit.empty()) return n;
    for (const auto& [name, scale] : units) {
        if (unit == name) {
            if (*n > std::numeric_limits<uint64_t>::max() / scale) return std::nullopt;
            return *n * scale;
        }
    }
    return std::nullopt;
}

std::string format_bytes(uint64_t v) {
    if (v != 0 && v % (1ull << 30) == 0) return std::to_string(v >> 30) + "GiB";
    if (v != 0 && v % (1ull << 20) == 0) return std::to_string(v >> 20) + "MiB";
    if (v != 0 && v % (1ull << 10) == 0) return std::to_string(v >> 10) + "KiB";
    return std::to_string(v);
}

std::string format_seconds(uint64_t v) {
    if (v != 0 && v % 3600 == 0) return std::to_string(v / 3600) + "h";
    if (v != 0 && v % 60 == 0 && v < 3600) return std::to_string(v / 60) + "m";
    return std::to_string(v) + "s";
}

std::string quote(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\t': out += "\\t"; break;
            default:   out += c; break;
        }
    }
    return out + "\"";
}

// ---------------------------------------------------------------------------
// The schema
// ---------------------------------------------------------------------------
// One configurable value. Numbers and booleans travel as uint64_t; text as a
// string. `lo` and `hi` bound numbers, inclusively.
struct Field {
    const char* path;
    Kind        kind;
    uint64_t    lo = 0;
    uint64_t    hi = std::numeric_limits<uint64_t>::max();
    std::function<uint64_t(const RendezvousConfig&)>    get;
    std::function<void(RendezvousConfig&, uint64_t)>    set;
    std::function<std::string(const RendezvousConfig&)> get_text;
    std::function<void(RendezvousConfig&, std::string)> set_text;
};

constexpr uint64_t kKiB      = 1024;
constexpr uint64_t kMaxSize  = std::numeric_limits<size_t>::max();
// Far beyond any sensible timeout, and far inside what steady_clock can add.
constexpr uint64_t kMaxSecs  = 10ull * 365 * 24 * 3600;

#define UC_NUM(path, kind, member, lo, hi)                                                     \
    Field{path, kind, lo, hi,                                                                  \
          [](const RendezvousConfig& c) { return static_cast<uint64_t>(c.member); },          \
          [](RendezvousConfig& c, uint64_t v) { c.member = static_cast<decltype(c.member)>(v); }, \
          nullptr, nullptr}

#define UC_SECS(path, member)                                                                  \
    Field{path, Kind::Seconds, 1, kMaxSecs,                                                    \
          [](const RendezvousConfig& c) { return static_cast<uint64_t>(c.member.count()); },  \
          [](RendezvousConfig& c, uint64_t v) {                                                \
              c.member = std::chrono::seconds(static_cast<std::chrono::seconds::rep>(v));      \
          },                                                                                   \
          nullptr, nullptr}

// In document order: to_yaml prints them so, and rendezvous.example.yaml
// follows it.
const std::vector<Field>& schema() {
    static const std::vector<Field> fields = {
        UC_NUM("port", Kind::Count, port, 0, 65535),
        Field{"bind", Kind::Text, 0, 0, nullptr, nullptr,
              [](const RendezvousConfig& c) { return c.bind_host; },
              [](RendezvousConfig& c, std::string v) { c.bind_host = std::move(v); }},
        UC_NUM("threads", Kind::Count, threads, 1, 256),

        UC_NUM("connections.max", Kind::Count, max_connections, 1, kMaxSize),
        UC_NUM("connections.max_per_ip", Kind::Count, max_connections_per_ip, 1, kMaxSize),
        UC_SECS("connections.idle_timeout", idle_timeout),
        UC_SECS("connections.first_frame_timeout", first_frame_timeout),

        UC_SECS("registry.stale_after", registry.stale_after),
        UC_NUM("registry.max_per_ip_per_topic", Kind::Count, registry.max_per_ip_per_topic, 1, kMaxSize),
        UC_NUM("registry.max_per_ip_total", Kind::Count, registry.max_per_ip_total, 1, kMaxSize),
        UC_NUM("registry.max_entries", Kind::Count, registry.max_entries, 1, kMaxSize),
        UC_NUM("registry.max_topics", Kind::Count, registry.max_topics, 1, kMaxSize),

        UC_NUM("relay.enabled", Kind::Bool, registry.relay_enabled, 0, 1),
        UC_SECS("relay.expiry", registry.relay_expiry),
        UC_NUM("relay.max", Kind::Count, registry.max_relays, 1, kMaxSize),
        UC_NUM("relay.max_per_ip", Kind::Count, registry.max_relays_per_ip, 1, kMaxSize),
        // Clients are told the cap in KiB, as 32 bits.
        UC_NUM("relay.max_bytes", Kind::Bytes, registry.relay_max_bytes, kKiB,
               uint64_t{0xFFFFFFFF} * kKiB),
        UC_SECS("relay.join_timeout", relay_join_timeout),
        // Smaller only throttles every relay to a crawl; zero would stall them.
        UC_NUM("relay.splice_buffer", Kind::Bytes, splice_buffer, kKiB, kMaxSize),

        UC_NUM("rate_limits.control_bytes_per_sec", Kind::Bytes, control.rate_bytes_per_sec, 1, kMaxSize),
        // Below one largest frame, a node that sends one is disconnected.
        UC_NUM("rate_limits.control_burst_bytes", Kind::Bytes, control.rate_burst_bytes,
               wire::ctl::kMaxFrame + ControlService::kMessageOverhead, kMaxSize),
        UC_NUM("rate_limits.udp_bytes_per_sec", Kind::Bytes, control.udp_bytes_per_sec, 1, kMaxSize),
        // Below one largest datagram, a relayed datagram of that size never passes.
        UC_NUM("rate_limits.udp_burst_bytes", Kind::Bytes, control.udp_burst_bytes,
               kMaxUdpDatagram, kMaxSize),
    };
    return fields;
}

#undef UC_NUM
#undef UC_SECS

const Field* find_field(std::string_view path) {
    for (const auto& f : schema()) {
        if (path == f.path) return &f;
    }
    return nullptr;
}

bool is_section(std::string_view path) {
    for (const auto& f : schema()) {
        const std::string_view p = f.path;
        if (p.size() > path.size() && p.substr(0, path.size()) == path && p[path.size()] == '.') {
            return true;
        }
    }
    return false;
}

std::string show(const Field& f, uint64_t v) {
    switch (f.kind) {
        case Kind::Bytes:   return format_bytes(v);
        case Kind::Seconds: return format_seconds(v);
        case Kind::Bool:    return v ? "true" : "false";
        default:            return std::to_string(v);
    }
}

bool in_range(const Field& f, uint64_t v, std::string& error) {
    if (v < f.lo) {
        error = std::string("'") + f.path + "' must be at least " + show(f, f.lo);
        return false;
    }
    if (v > f.hi) {
        error = std::string("'") + f.path + "' must be at most " + show(f, f.hi);
        return false;
    }
    return true;
}

// Parses `text` as f's kind and stores it. `error` is unprefixed.
bool set_field(const Field& f, std::string_view text, RendezvousConfig& cfg, std::string& error) {
    if (f.kind == Kind::Text) {
        f.set_text(cfg, std::string(text));
        return true;
    }
    std::optional<uint64_t> v;
    const char*             expected = "";
    switch (f.kind) {
        case Kind::Count:
            v        = parse_uint(text);
            expected = "a whole number";
            break;
        case Kind::Bytes:
            v        = parse_with_unit(text, {{"B", 1}, {"KiB", kKiB}, {"MiB", kKiB * kKiB},
                                              {"GiB", kKiB * kKiB * kKiB}});
            expected = "a size, such as 4096, 256KiB, 32MiB or 1GiB";
            break;
        case Kind::Seconds:
            v        = parse_with_unit(text, {{"s", 1}, {"m", 60}, {"h", 3600}});
            expected = "a duration, such as 45, 90s, 2m or 1h";
            break;
        case Kind::Bool:
            if (text == "true") v = 1;
            if (text == "false") v = 0;
            expected = "true or false";
            break;
        case Kind::Text:
            break;
    }
    if (!v) {
        error = std::string("'") + f.path + "' must be " + expected + ", not '" +
                std::string(text) + "'";
        return false;
    }
    if (!in_range(f, *v, error)) return false;
    f.set(cfg, *v);
    return true;
}

bool apply_node(const YamlNode& map, const std::string& prefix, RendezvousConfig& cfg,
                ParseError& err) {
    for (const auto& [key, child] : map.entries) {
        const std::string path = prefix.empty() ? key : prefix + "." + key;
        if (const Field* f = find_field(path)) {
            if (child.is_map) {
                err = {child.line, "'" + path + "' takes a value, not a section"};
                return false;
            }
            std::string why;
            if (!set_field(*f, child.scalar, cfg, why)) {
                err = {child.line, why};
                return false;
            }
        } else if (is_section(path)) {
            if (!child.is_map) {
                err = {child.line, "'" + path + "' is a section: indent its keys beneath it"};
                return false;
            }
            if (!apply_node(child, path, cfg, err)) return false;
        } else {
            err = {child.line, "unknown key '" + path + "'"};
            return false;
        }
    }
    return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// The file
// ---------------------------------------------------------------------------
bool apply_config(std::string_view yaml, RendezvousConfig& cfg, std::string& error) {
    ParseError err;
    auto       root = parse_yaml(yaml, err);
    RendezvousConfig next = cfg;
    if (!root || !apply_node(*root, "", next, err)) {
        error = "line " + std::to_string(err.line) + ": " + err.message;
        return false;
    }
    cfg = std::move(next);
    return true;
}

bool load_config_file(const std::string& path, RendezvousConfig& cfg, std::string& error) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        error = path + ": cannot open";
        return false;
    }
    std::ostringstream text;
    text << in.rdbuf();
    if (!apply_config(text.str(), cfg, error)) {
        // "line N: ..." becomes "<path>:N: ...", as compilers put it.
        error = path + ":" + error.substr(5);
        return false;
    }
    return true;
}

bool validate_config(const RendezvousConfig& cfg, std::string& error) {
    for (const auto& f : schema()) {
        if (f.kind == Kind::Text) continue;
        if (!in_range(f, f.get(cfg), error)) return false;
    }
    return true;
}

std::string to_yaml(const RendezvousConfig& cfg) {
    std::string out = "# uconnect-rendezvous configuration\n";
    std::string section;
    for (const auto& f : schema()) {
        const std::string_view path = f.path;
        const size_t           dot  = path.find('.');
        const std::string      here = dot == std::string_view::npos ? "" : std::string(path.substr(0, dot));
        if (here != section) {
            out += "\n" + here + ":\n";
            section = here;
        }
        out += here.empty() ? "" : "  ";
        out += std::string(path.substr(dot == std::string_view::npos ? 0 : dot + 1)) + ": ";
        out += f.kind == Kind::Text ? quote(f.get_text(cfg)) : show(f, f.get(cfg));
        out += "\n";
    }
    return out;
}

// ---------------------------------------------------------------------------
// The command line
// ---------------------------------------------------------------------------
bool parse_server_args(const std::vector<std::string>& args, ServerOptions& out,
                       std::string& error) {
    ServerOptions opts;

    // Flags that set a configuration value, by the key they set.
    const std::pair<const char*, const char*> valued[] = {
        {"--port", "port"},
        {"--bind", "bind"},
        {"--threads", "threads"},
        {"--stale", "registry.stale_after"},
        {"--max-per-ip", "registry.max_per_ip_per_topic"},
    };
    auto key_for = [&](const std::string& a) -> const char* {
        for (const auto& [flag, key] : valued) {
            if (a == flag) return key;
        }
        return nullptr;
    };

    // First the shape of the command line and the file, so that the flags
    // after it -- whatever their position -- land on top of the file.
    std::optional<std::string>                       config_path;
    std::vector<std::pair<std::string, std::string>> settings;  // (flag, value)
    for (size_t i = 0; i < args.size(); ++i) {
        const std::string& a = args[i];
        if (a == "--help" || a == "-h") {
            opts.help = true;
        } else if (a == "--quiet") {
            opts.quiet = true;
        } else if (a == "--nat-check") {
            opts.nat_check = true;
        } else if (a == "--print-config") {
            opts.print_config = true;
        } else if (a == "--no-relay") {
            settings.emplace_back(a, "false");
        } else if (a == "--config" || key_for(a)) {
            if (i + 1 >= args.size()) {
                error = a + " needs a value";
                return false;
            }
            const std::string& v = args[++i];
            if (a != "--config") {
                settings.emplace_back(a, v);
            } else if (config_path) {
                error = "--config given twice";
                return false;
            } else {
                config_path = v;
            }
        } else {
            error = "unknown option: " + a;
            return false;
        }
    }

    if (config_path && !load_config_file(*config_path, opts.cfg, error)) return false;
    for (const auto& [flag, value] : settings) {
        const Field* f = find_field(flag == "--no-relay" ? "relay.enabled" : key_for(flag));
        std::string  why;
        if (!set_field(*f, value, opts.cfg, why)) {
            error = flag + ": " + why;
            return false;
        }
    }
    if (!validate_config(opts.cfg, error)) return false;
    out = std::move(opts);
    return true;
}

}  // namespace uconnect::server
