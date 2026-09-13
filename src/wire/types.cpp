#include "uconnect/types.hpp"

namespace uconnect {

const char* to_string(ErrorCode c) {
    switch (c) {
        case ErrorCode::None:          return "none";
        case ErrorCode::BadRequest:    return "bad request";
        case ErrorCode::BadAuth:       return "bad auth";
        case ErrorCode::NotFound:      return "not found";
        case ErrorCode::RateLimited:   return "rate limited";
        case ErrorCode::QuotaExceeded: return "quota exceeded";
        case ErrorCode::NeedCookie:    return "address not validated";
        case ErrorCode::Unsupported:   return "unsupported";
    }
    return "unknown";
}

std::string to_hex(const uint8_t* data, size_t len) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[i * 2]     = kHex[data[i] >> 4];
        out[i * 2 + 1] = kHex[data[i] & 0x0F];
    }
    return out;
}

namespace {
int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
}  // namespace

bool from_hex(std::string_view hex, uint8_t* out, size_t out_len) {
    if (hex.size() != out_len * 2) return false;
    for (size_t i = 0; i < out_len; ++i) {
        int hi = nibble(hex[i * 2]);
        int lo = nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>(hi << 4 | lo);
    }
    return true;
}

}  // namespace uconnect
