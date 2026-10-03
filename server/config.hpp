#pragma once
// The rendezvous server's configuration file, and its command line.
//
// The file is YAML -- a strict subset of it: nested mappings of scalars,
// comments, and quoted strings. Anything outside that subset (lists, flow
// collections, anchors, tags, block scalars, several documents) is an error
// with its line number, never a guess. So is an unknown key, so that a typo
// cannot quietly leave a default in force, and so is a value out of range.
//
// rendezvous.example.yaml, next to this file, lists every key with its
// default; --print-config prints the configuration in force in the same form.
//
// Durations are seconds, optionally suffixed s, m or h ("90s", "2m"). Sizes
// are bytes, optionally suffixed KiB, MiB or GiB ("256KiB", "32MiB").

#include <string>
#include <string_view>
#include <vector>

#include "rendezvous.hpp"

namespace uconnect::server {

// Applies a configuration document on top of `cfg`. On failure `cfg` is left
// untouched and `error` reads "line N: ...".
bool apply_config(std::string_view yaml, RendezvousConfig& cfg, std::string& error);

// As apply_config, from a file; errors read "<path>:N: ...".
bool load_config_file(const std::string& path, RendezvousConfig& cfg, std::string& error);

// Every value in range, by the same rules the file is held to. The command
// line can set values the file never saw, so this runs on the final result.
bool validate_config(const RendezvousConfig& cfg, std::string& error);

// The whole configuration as a document apply_config reads back unchanged.
std::string to_yaml(const RendezvousConfig& cfg);

// What the command line asked for. Precedence is defaults, then --config,
// then every other flag, wherever --config appears among them.
struct ServerOptions {
    RendezvousConfig cfg;
    bool             help         = false;
    bool             quiet        = false;
    bool             nat_check    = false;
    bool             print_config = false;
};

// argv without the program name. False with `error` on an unknown option, a
// missing or malformed value, or a config file that does not load.
bool parse_server_args(const std::vector<std::string>& args, ServerOptions& out,
                       std::string& error);

}  // namespace uconnect::server
