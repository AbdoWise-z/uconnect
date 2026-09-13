// CSPRNG, constant-time helpers, X25519 wrapper, HMAC and HKDF.

#include <cstring>
#include <stdexcept>

#include "primitives.hpp"
#include "x25519.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
// bcrypt.h must follow windows.h
#include <bcrypt.h>
#else
#include <sys/random.h>
#endif

namespace uconnect::crypto {

// --- randomness ------------------------------------------------------------
void random_bytes(std::span<uint8_t> out) {
    if (out.empty()) return;
#if defined(_WIN32)
    NTSTATUS st = BCryptGenRandom(nullptr, out.data(), static_cast<ULONG>(out.size()),
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st < 0) {
        // There is no safe way to continue. Returning weak or predictable bytes
        // here would silently compromise every key the process generates, so a
        // hard failure is the only correct behaviour.
        throw std::runtime_error("BCryptGenRandom failed; refusing to produce weak keys");
    }
#else
    size_t off = 0;
    while (off < out.size()) {
        ssize_t n = getrandom(out.data() + off, out.size() - off, 0);
        if (n < 0) throw std::runtime_error("getrandom failed; refusing to produce weak keys");
        off += static_cast<size_t>(n);
    }
#endif
}

// --- constant-time ---------------------------------------------------------
bool ct_equal(std::span<const uint8_t> a, std::span<const uint8_t> b) {
    if (a.size() != b.size()) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i) diff = static_cast<uint8_t>(diff | (a[i] ^ b[i]));
    return diff == 0;
}

void secure_zero(std::span<uint8_t> buf) {
    if (buf.empty()) return;
#if defined(_WIN32)
    SecureZeroMemory(buf.data(), buf.size());
#else
    // volatile write through a barrier so the compiler cannot elide the store
    // to memory it can prove is never read again.
    volatile uint8_t* p = buf.data();
    for (size_t i = 0; i < buf.size(); ++i) p[i] = 0;
    __asm__ __volatile__("" : : "r"(buf.data()) : "memory");
#endif
}

// --- X25519 ----------------------------------------------------------------
KeyPair KeyPair::generate() {
    KeyPair kp;
    random_bytes(kp.secret);
    uconnect_x25519_base(kp.pub.data(), kp.secret.data());
    return kp;
}

KeyPair KeyPair::from_secret(const SecretKey& sk) {
    KeyPair kp;
    kp.secret = sk;
    uconnect_x25519_base(kp.pub.data(), kp.secret.data());
    return kp;
}

bool x25519(const SecretKey& sk, const PublicKey& pk, PublicKey& out) {
    uconnect_x25519(out.data(), sk.data(), pk.data());
    // An all-zero output means the peer sent a small-order point and forced a
    // shared secret it already knows. Noise tolerates this, but refusing costs
    // nothing.
    uint8_t acc = 0;
    for (uint8_t b : out) acc = static_cast<uint8_t>(acc | b);
    return acc != 0;
}

// --- HMAC (RFC 2104) over BLAKE2s -----------------------------------------
Hash hmac_blake2s(std::span<const uint8_t> key, std::span<const uint8_t> msg) {
    std::array<uint8_t, kBlockLen> k_block{};
    if (key.size() > kBlockLen) {
        Hash kh = Blake2s::hash(key);
        std::memcpy(k_block.data(), kh.data(), kh.size());
    } else if (!key.empty()) {
        std::memcpy(k_block.data(), key.data(), key.size());
    }

    std::array<uint8_t, kBlockLen> ipad{}, opad{};
    for (size_t i = 0; i < kBlockLen; ++i) {
        ipad[i] = static_cast<uint8_t>(k_block[i] ^ 0x36);
        opad[i] = static_cast<uint8_t>(k_block[i] ^ 0x5C);
    }

    Blake2s inner;
    inner.update(ipad);
    inner.update(msg);
    Hash inner_hash = inner.finish();

    Blake2s outer;
    outer.update(opad);
    outer.update(inner_hash);
    Hash out = outer.finish();

    secure_zero(k_block);
    secure_zero(ipad);
    secure_zero(opad);
    return out;
}

// --- Noise HKDF (spec s4.3) ------------------------------------------------
void hkdf2(std::span<const uint8_t> chaining_key, std::span<const uint8_t> ikm,
           Hash& out1, Hash& out2) {
    Hash                   temp_key = hmac_blake2s(chaining_key, ikm);
    std::array<uint8_t, 1> one{0x01};
    out1 = hmac_blake2s(temp_key, one);

    std::array<uint8_t, kHashLen + 1> buf{};
    std::memcpy(buf.data(), out1.data(), kHashLen);
    buf[kHashLen] = 0x02;
    out2          = hmac_blake2s(temp_key, buf);

    secure_zero(temp_key);
    secure_zero(buf);
}

void hkdf3(std::span<const uint8_t> chaining_key, std::span<const uint8_t> ikm,
           Hash& out1, Hash& out2, Hash& out3) {
    Hash                   temp_key = hmac_blake2s(chaining_key, ikm);
    std::array<uint8_t, 1> one{0x01};
    out1 = hmac_blake2s(temp_key, one);

    std::array<uint8_t, kHashLen + 1> buf{};
    std::memcpy(buf.data(), out1.data(), kHashLen);
    buf[kHashLen] = 0x02;
    out2          = hmac_blake2s(temp_key, buf);

    std::memcpy(buf.data(), out2.data(), kHashLen);
    buf[kHashLen] = 0x03;
    out3          = hmac_blake2s(temp_key, buf);

    secure_zero(temp_key);
    secure_zero(buf);
}

// --- RFC 5869 HKDF ---------------------------------------------------------
void hkdf(std::span<const uint8_t> ikm, std::span<const uint8_t> salt,
          std::string_view info, std::span<uint8_t> out) {
    Hash prk = hmac_blake2s(salt, ikm);

    std::vector<uint8_t> t;
    size_t               off     = 0;
    uint8_t              counter = 1;
    while (off < out.size()) {
        std::vector<uint8_t> input;
        input.reserve(t.size() + info.size() + 1);
        input.insert(input.end(), t.begin(), t.end());
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter);

        Hash block = hmac_blake2s(prk, input);
        size_t n   = out.size() - off;
        if (n > kHashLen) n = kHashLen;
        std::memcpy(out.data() + off, block.data(), n);
        off += n;

        t.assign(block.begin(), block.end());
        ++counter;
    }

    secure_zero(prk);
    if (!t.empty()) secure_zero(t);
}

}  // namespace uconnect::crypto
