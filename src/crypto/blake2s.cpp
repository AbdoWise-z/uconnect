// BLAKE2s-256, RFC 7693.

#include <cstring>

#include "primitives.hpp"

namespace uconnect::crypto {
namespace {

constexpr uint32_t kIV[8] = {0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
                             0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u};

constexpr uint8_t kSigma[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};

constexpr uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

uint32_t load32_le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | static_cast<uint32_t>(p[1]) << 8 |
           static_cast<uint32_t>(p[2]) << 16 | static_cast<uint32_t>(p[3]) << 24;
}

void store32_le(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

}  // namespace

Blake2s::Blake2s(std::span<const uint8_t> key, size_t out_len) : out_len_(out_len) {
    for (size_t i = 0; i < 8; ++i) h_[i] = kIV[i];
    // Parameter block, folded into h[0]: digest length, key length, fanout=1,
    // depth=1. Getting this wrong yields a hash that is self-consistent but
    // matches no published vector -- which is exactly why the vectors matter.
    h_[0] ^= 0x01010000u ^ (static_cast<uint32_t>(key.size()) << 8) ^
             static_cast<uint32_t>(out_len);

    if (!key.empty()) {
        // A keyed hash processes the key as a full zero-padded first block.
        std::array<uint8_t, kBlockLen> block{};
        std::memcpy(block.data(), key.data(), key.size());
        update(block);
        secure_zero(block);
    }
}

void Blake2s::compress(const uint8_t block[kBlockLen], bool last) {
    uint32_t m[16];
    uint32_t v[16];

    for (size_t i = 0; i < 16; ++i) m[i] = load32_le(block + i * 4);
    for (size_t i = 0; i < 8; ++i) v[i] = h_[i];
    for (size_t i = 0; i < 8; ++i) v[i + 8] = kIV[i];

    v[12] ^= static_cast<uint32_t>(counter_);
    v[13] ^= static_cast<uint32_t>(counter_ >> 32);
    if (last) v[14] = ~v[14];

    auto G = [&](size_t a, size_t b, size_t c, size_t d, uint32_t x, uint32_t y) {
        v[a] = v[a] + v[b] + x;
        v[d] = rotr32(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = rotr32(v[b] ^ v[c], 12);
        v[a] = v[a] + v[b] + y;
        v[d] = rotr32(v[d] ^ v[a], 8);
        v[c] = v[c] + v[d];
        v[b] = rotr32(v[b] ^ v[c], 7);
    };

    for (size_t r = 0; r < 10; ++r) {
        const uint8_t* s = kSigma[r];
        G(0, 4, 8, 12, m[s[0]], m[s[1]]);
        G(1, 5, 9, 13, m[s[2]], m[s[3]]);
        G(2, 6, 10, 14, m[s[4]], m[s[5]]);
        G(3, 7, 11, 15, m[s[6]], m[s[7]]);
        G(0, 5, 10, 15, m[s[8]], m[s[9]]);
        G(1, 6, 11, 12, m[s[10]], m[s[11]]);
        G(2, 7, 8, 13, m[s[12]], m[s[13]]);
        G(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for (size_t i = 0; i < 8; ++i) h_[i] ^= v[i] ^ v[i + 8];
}

void Blake2s::update(std::span<const uint8_t> in) {
    if (in.empty()) return;
    const uint8_t* p   = in.data();
    size_t         len = in.size();

    // BLAKE2 must not compress the final block here: the last block needs the
    // finalization flag, and we do not yet know whether more input is coming.
    // So we always keep at least one byte buffered.
    if (buf_len_ + len > kBlockLen) {
        size_t fill = kBlockLen - buf_len_;
        std::memcpy(buf_.data() + buf_len_, p, fill);
        counter_ += kBlockLen;
        compress(buf_.data(), false);
        buf_len_ = 0;
        p += fill;
        len -= fill;

        while (len > kBlockLen) {
            counter_ += kBlockLen;
            compress(p, false);
            p += kBlockLen;
            len -= kBlockLen;
        }
    }
    std::memcpy(buf_.data() + buf_len_, p, len);
    buf_len_ += len;
}

void Blake2s::update(std::string_view s) {
    update(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(s.data()), s.size()));
}

void Blake2s::finish(std::span<uint8_t> out) {
    if (done_) return;
    done_ = true;

    counter_ += buf_len_;
    std::memset(buf_.data() + buf_len_, 0, kBlockLen - buf_len_);
    compress(buf_.data(), true);

    std::array<uint8_t, kHashLen> full{};
    for (size_t i = 0; i < 8; ++i) store32_le(full.data() + i * 4, h_[i]);

    size_t n = out.size() < out_len_ ? out.size() : out_len_;
    std::memcpy(out.data(), full.data(), n);
    secure_zero(full);
    secure_zero(buf_);
}

Hash Blake2s::finish() {
    Hash out{};
    finish(out);
    return out;
}

Hash Blake2s::hash(std::span<const uint8_t> in) {
    Blake2s h;
    h.update(in);
    return h.finish();
}

Hash Blake2s::mac(std::span<const uint8_t> key, std::span<const uint8_t> msg) {
    Blake2s h{key};
    h.update(msg);
    return h.finish();
}

}  // namespace uconnect::crypto
