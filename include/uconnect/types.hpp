#pragma once
// Core value types shared by every layer. No I/O, no allocation policy, no
// dependencies beyond the standard library.

#include <array>
#include <chrono>
#include <cstdint>
#include <compare>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace uconnect {

// --- identifiers -----------------------------------------------------------
// topic_id : 16 B / 32 hex, public, the server's index key
// dev_id   : 16 B / 32 hex, server-derived per (topic, address)
// Key      : 32 B / 64 hex, secret, never transmitted
using TopicId = std::array<uint8_t, 16>;
using DevId   = std::array<uint8_t, 16>;
using Key     = std::array<uint8_t, 32>;

inline constexpr size_t kTopicIdLen = 16;
inline constexpr size_t kDevIdLen   = 16;
inline constexpr size_t kKeyLen     = 32;

// --- time ------------------------------------------------------------------
// A monotonic instant supplied by the caller. Nothing below the io layer is
// allowed to read a clock; `now` is always a parameter. This is what makes the
// protocol state machines deterministically testable.
using Instant  = std::chrono::steady_clock::time_point;
using Duration = std::chrono::milliseconds;

// --- addresses -------------------------------------------------------------
struct IpAddr {
    enum class Family : uint8_t { V4 = 4, V6 = 6 };

    Family                  family = Family::V4;
    std::array<uint8_t, 16> bytes{};  // v4 occupies bytes[0..3]

    constexpr size_t addr_len() const { return family == Family::V4 ? 4u : 16u; }

    static IpAddr v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
        IpAddr ip;
        ip.family = Family::V4;
        ip.bytes = {a, b, c, d};
        return ip;
    }

    bool is_loopback() const {
        if (family == Family::V4) return bytes[0] == 127;
        static constexpr std::array<uint8_t, 16> kLoop6{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        return bytes == kLoop6;
    }

    // RFC1918 / CGNAT / link-local. Used to rank candidates and to detect the
    // "both peers report the same srflx" same-NAT case.
    bool is_private() const {
        if (family == Family::V4) {
            if (bytes[0] == 10) return true;
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            if (bytes[0] == 172 && (bytes[1] & 0xF0) == 16) return true;
            if (bytes[0] == 100 && (bytes[1] & 0xC0) == 64) return true;  // CGNAT 100.64/10
            if (bytes[0] == 169 && bytes[1] == 254) return true;          // link-local
            return false;
        }
        if ((bytes[0] & 0xFE) == 0xFC) return true;                        // ULA fc00::/7
        if (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80) return true;    // link-local fe80::/10
        return false;
    }

    friend bool operator==(const IpAddr& a, const IpAddr& b) {
        return a.family == b.family &&
               std::memcmp(a.bytes.data(), b.bytes.data(), a.addr_len()) == 0;
    }
};

struct Endpoint {
    IpAddr   ip{};
    uint16_t port = 0;

    friend bool operator==(const Endpoint& a, const Endpoint& b) {
        return a.port == b.port && a.ip == b.ip;
    }
};

struct Candidate {
    // Host  : a local interface address, supplied by the client. Essential for
    //         same-NAT peers, whose srflx pair fails when the router does not
    //         hairpin.
    // Srflx : the mapping the rendezvous server observed. Client never sets it.
    // Relay : a relay-allocated address (not implemented yet).
    enum class Kind : uint8_t { Host = 0, Srflx = 1, Relay = 2 };

    Kind     kind = Kind::Host;
    Endpoint ep{};

    friend bool operator==(const Candidate&, const Candidate&) = default;
};

// --- topic mode ------------------------------------------------------------
enum class TopicMode : uint8_t {
    // No pre-shared key. Noise_NN: forward secrecy against a passive observer,
    // and nothing else. Anyone may join; the rendezvous server, or anyone on
    // path, can MITM undetectably. Fine for public swarms, never for secrets.
    Open = 0,
    // Pre-shared K. Noise_NNpsk0: mutual authentication as topic members, plus
    // resistance to harvest-now-decrypt-later because the PSK is mixed into the
    // chaining key.
    Keyed = 1,
};

// --- errors ----------------------------------------------------------------
enum class ErrorCode : uint16_t {
    None          = 0,
    BadRequest    = 1,
    BadAuth       = 2,   // MAC did not verify, or seq replayed
    NotFound      = 3,
    RateLimited   = 4,
    QuotaExceeded = 5,   // too many records for this source address
    NeedCookie    = 6,   // address not validated; a Retry was sent
    Unsupported   = 7,
};

const char* to_string(ErrorCode);

// --- hex helpers -----------------------------------------------------------
std::string to_hex(const uint8_t* data, size_t len);

template <size_t N>
std::string to_hex(const std::array<uint8_t, N>& a) { return to_hex(a.data(), N); }

bool from_hex(std::string_view hex, uint8_t* out, size_t out_len);

template <size_t N>
std::optional<std::array<uint8_t, N>> from_hex(std::string_view hex) {
    std::array<uint8_t, N> out{};
    if (!from_hex(hex, out.data(), N)) return std::nullopt;
    return out;
}

}  // namespace uconnect
