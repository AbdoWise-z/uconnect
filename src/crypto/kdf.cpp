#include "kdf.hpp"

namespace uconnect::crypto {
namespace {

// A small, deliberately unambiguous word list: no two words share a prefix of
// three letters, and none are homophones, because the whole point is that a
// human reads these aloud over a channel the attacker does not control.
constexpr const char* kWords[64] = {
    "amber",  "anchor", "banjo",  "beacon", "cactus", "canyon", "cobalt", "copper",
    "dagger", "delta",  "ember",  "engine", "falcon", "fossil", "gadget", "granite",
    "harbor", "helium", "indigo", "ivory",  "jacket", "jungle", "kernel", "kiwi",
    "lagoon", "lumber", "magnet", "marble", "nectar", "nickel", "oak",    "onyx",
    "pelican","pepper", "quartz", "quiver", "rabbit", "ribbon", "saddle", "sierra",
    "tundra", "turbo",  "umber",  "unity",  "valley", "velvet", "walnut", "willow",
    "xenon",  "yellow", "yonder", "zebra",  "zenith", "acorn",  "bronze", "cedar",
    "dune",   "echo",   "fern",   "glacier","hazel",  "iris",   "jasper", "koala"};

}  // namespace

std::string sas_string(const Hash& handshake_hash) {
    std::array<uint8_t, 3> bits{};
    hkdf(handshake_hash, {}, kInfoSas, bits);

    // 3 bytes -> 4 x 6-bit indices -> 4 words = 24 bits of verification. An
    // attacker gets one shot at a 1-in-16-million guess, and a wrong guess is
    // visible to both humans immediately.
    uint32_t v = static_cast<uint32_t>(bits[0]) << 16 |
                 static_cast<uint32_t>(bits[1]) << 8 | static_cast<uint32_t>(bits[2]);

    std::string out;
    for (int i = 3; i >= 0; --i) {
        if (!out.empty()) out += '-';
        out += kWords[(v >> (i * 6)) & 0x3F];
    }
    return out;
}

}  // namespace uconnect::crypto
