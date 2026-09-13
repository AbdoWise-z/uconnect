// ChaCha20 (RFC 8439 s2.4) and the AEAD_CHACHA20_POLY1305 construction
// (RFC 8439 s2.8). Poly1305 itself is vendored; see third_party/poly1305.c.

#include <cstring>

#include "poly1305.h"
#include "primitives.hpp"

namespace uconnect::crypto {
namespace {

constexpr uint32_t rotl32(uint32_t x, unsigned n) {
    return (x << n) | (x >> (32 - n));
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

void store64_le(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = static_cast<uint8_t>(v >> (i * 8));
}

// Noise encodes the 64-bit nonce as 4 zero bytes followed by the counter in
// little-endian order.
void noise_nonce(uint64_t n, uint8_t out[12]) {
    std::memset(out, 0, 4);
    store64_le(out + 4, n);
}

}  // namespace

void chacha20_block(const SymKey& key, uint32_t counter, const uint8_t nonce[12],
                    uint8_t out[64]) {
    uint32_t s[16];
    s[0] = 0x61707865u;  // "expa"
    s[1] = 0x3320646Eu;  // "nd 3"
    s[2] = 0x79622D32u;  // "2-by"
    s[3] = 0x6B206574u;  // "te k"
    for (size_t i = 0; i < 8; ++i) s[4 + i] = load32_le(key.data() + i * 4);
    s[12] = counter;
    for (size_t i = 0; i < 3; ++i) s[13 + i] = load32_le(nonce + i * 4);

    uint32_t x[16];
    std::memcpy(x, s, sizeof(x));

    auto qr = [&](size_t a, size_t b, size_t c, size_t d) {
        x[a] += x[b]; x[d] ^= x[a]; x[d] = rotl32(x[d], 16);
        x[c] += x[d]; x[b] ^= x[c]; x[b] = rotl32(x[b], 12);
        x[a] += x[b]; x[d] ^= x[a]; x[d] = rotl32(x[d], 8);
        x[c] += x[d]; x[b] ^= x[c]; x[b] = rotl32(x[b], 7);
    };

    for (int i = 0; i < 10; ++i) {  // 20 rounds = 10 column/diagonal pairs
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14);
    }

    for (size_t i = 0; i < 16; ++i) store32_le(out + i * 4, x[i] + s[i]);
}

void chacha20_xor(const SymKey& key, uint32_t counter, const uint8_t nonce[12],
                  std::span<const uint8_t> in, std::span<uint8_t> out) {
    uint8_t block[64];
    size_t  off = 0;
    while (off < in.size()) {
        chacha20_block(key, counter, nonce, block);
        size_t n = in.size() - off;
        if (n > 64) n = 64;
        for (size_t i = 0; i < n; ++i) out[off + i] = in[off + i] ^ block[i];
        off += n;
        ++counter;
    }
    secure_zero(std::span<uint8_t>(block, sizeof(block)));
}

namespace {

// RFC 8439 s2.8: the tag covers
//   aad || pad16(aad) || ciphertext || pad16(ciphertext) || le64(|aad|) || le64(|ct|)
// The length suffix is what stops an attacker shifting bytes between the aad
// and the ciphertext while keeping the tag valid.
Tag poly1305_tag(const SymKey& key, const uint8_t nonce[12], std::span<const uint8_t> ad,
                 std::span<const uint8_t> ct) {
    uint8_t poly_key_block[64];
    chacha20_block(key, 0, nonce, poly_key_block);

    uconnect_poly1305_ctx ctx;
    uconnect_poly1305_init(&ctx, poly_key_block);
    secure_zero(std::span<uint8_t>(poly_key_block, sizeof(poly_key_block)));

    static const uint8_t zeros[16] = {0};

    uconnect_poly1305_update(&ctx, ad.data(), ad.size());
    if (ad.size() % 16) uconnect_poly1305_update(&ctx, zeros, 16 - (ad.size() % 16));

    uconnect_poly1305_update(&ctx, ct.data(), ct.size());
    if (ct.size() % 16) uconnect_poly1305_update(&ctx, zeros, 16 - (ct.size() % 16));

    uint8_t lens[16];
    store64_le(lens, ad.size());
    store64_le(lens + 8, ct.size());
    uconnect_poly1305_update(&ctx, lens, 16);

    Tag tag{};
    uconnect_poly1305_finish(&ctx, tag.data());
    return tag;
}

}  // namespace

void aead_encrypt_n12(const SymKey& key, const uint8_t nonce[12], std::span<const uint8_t> ad,
                      std::span<const uint8_t> plaintext, std::span<uint8_t> out) {
    // Counter starts at 1; block 0 generated the Poly1305 key.
    chacha20_xor(key, 1, nonce, plaintext, out.first(plaintext.size()));

    Tag tag = poly1305_tag(key, nonce, ad, out.first(plaintext.size()));
    std::memcpy(out.data() + plaintext.size(), tag.data(), kTagLen);
}

bool aead_decrypt_n12(const SymKey& key, const uint8_t nonce[12], std::span<const uint8_t> ad,
                      std::span<const uint8_t> ciphertext, std::span<uint8_t> out) {
    if (ciphertext.size() < kTagLen) return false;
    size_t pt_len = ciphertext.size() - kTagLen;
    if (out.size() < pt_len) return false;

    Tag expected = poly1305_tag(key, nonce, ad, ciphertext.first(pt_len));
    if (!ct_equal(expected, ciphertext.last(kTagLen))) {
        // Never leave the caller holding unauthenticated plaintext -- the
        // classic way this goes wrong is decrypting first and checking later.
        secure_zero(out.first(pt_len));
        return false;
    }

    chacha20_xor(key, 1, nonce, ciphertext.first(pt_len), out.first(pt_len));
    return true;
}

void aead_encrypt(const SymKey& key, uint64_t nonce, std::span<const uint8_t> ad,
                  std::span<const uint8_t> plaintext, std::span<uint8_t> out) {
    uint8_t n12[12];
    noise_nonce(nonce, n12);
    aead_encrypt_n12(key, n12, ad, plaintext, out);
}

bool aead_decrypt(const SymKey& key, uint64_t nonce, std::span<const uint8_t> ad,
                  std::span<const uint8_t> ciphertext, std::span<uint8_t> out) {
    uint8_t n12[12];
    noise_nonce(nonce, n12);
    return aead_decrypt_n12(key, n12, ad, ciphertext, out);
}

}  // namespace uconnect::crypto
