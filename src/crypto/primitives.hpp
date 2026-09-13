#pragma once
// Cryptographic primitives for uConnect.
//
// Cipher suite, fixed: Noise_*_25519_ChaChaPoly_BLAKE2s
//   ECDH   X25519          (RFC 7748)  -- vendored, third_party/x25519.c
//   AEAD   ChaCha20-Poly1305 (RFC 8439) -- Poly1305 vendored, ChaCha20 here
//   Hash   BLAKE2s         (RFC 7693)  -- here
//
// Every one of these is validated against published test vectors in
// tests/test_crypto.cpp. That is not decoration: a wrong implementation of any
// of them still produces plausible-looking bytes and still "works" against
// itself, so self-consistency proves nothing. The vectors are the only thing
// standing between a working handshake and a broken one.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace uconnect::crypto {

inline constexpr size_t kHashLen  = 32;  // BLAKE2s-256
inline constexpr size_t kBlockLen = 64;  // BLAKE2s block, needed for HMAC
inline constexpr size_t kDhLen    = 32;  // X25519
inline constexpr size_t kTagLen   = 16;  // Poly1305
inline constexpr size_t kKeyLen   = 32;

using Hash      = std::array<uint8_t, kHashLen>;
using SymKey    = std::array<uint8_t, kKeyLen>;
using PublicKey = std::array<uint8_t, kDhLen>;
using SecretKey = std::array<uint8_t, kDhLen>;
using Tag       = std::array<uint8_t, kTagLen>;

// --- randomness ------------------------------------------------------------
// Backed by BCryptGenRandom on Windows and getrandom/urandom elsewhere.
//
// Deliberately NOT std::random_device: on MinGW-w64, which is the toolchain
// CLion ships, std::random_device has historically been a deterministic
// Mersenne Twister. It returns the same sequence on every run, with no error
// and no warning. A key generated from it would be identical on every machine
// that ever ran the binary.
void random_bytes(std::span<uint8_t> out);

template <size_t N>
std::array<uint8_t, N> random_array() {
    std::array<uint8_t, N> a{};
    random_bytes(a);
    return a;
}

// --- constant-time helpers -------------------------------------------------
// Comparing MACs or tags with memcmp leaks, through timing, how many leading
// bytes matched -- which is enough to forge one byte at a time.
bool ct_equal(std::span<const uint8_t> a, std::span<const uint8_t> b);
void secure_zero(std::span<uint8_t> buf);

// --- BLAKE2s ---------------------------------------------------------------
class Blake2s {
public:
    // key may be empty (plain hash) or up to 32 bytes (keyed hash = MAC).
    explicit Blake2s(std::span<const uint8_t> key = {}, size_t out_len = kHashLen);

    void update(std::span<const uint8_t> in);
    void update(std::string_view s);
    void finish(std::span<uint8_t> out);
    Hash finish();

    static Hash hash(std::span<const uint8_t> in);
    // Keyed BLAKE2s is a MAC by design; this is what authenticates lease
    // tokens and probe tags.
    static Hash mac(std::span<const uint8_t> key, std::span<const uint8_t> msg);

private:
    void compress(const uint8_t block[kBlockLen], bool last);

    std::array<uint32_t, 8>          h_{};
    std::array<uint8_t, kBlockLen>   buf_{};
    size_t                           buf_len_ = 0;
    uint64_t                         counter_ = 0;
    size_t                           out_len_ = kHashLen;
    bool                             done_    = false;
};

// --- HMAC / HKDF -----------------------------------------------------------
// The Noise spec defines its KDF in terms of HMAC-HASH (RFC 2104), so this uses
// HMAC-BLAKE2s rather than BLAKE2s native keying, even though the latter is
// also a sound MAC. Deviating here would break interoperability with any other
// Noise implementation.
Hash hmac_blake2s(std::span<const uint8_t> key, std::span<const uint8_t> msg);

// Noise HKDF: returns 2 or 3 outputs chained from (chaining_key, input).
void hkdf2(std::span<const uint8_t> chaining_key, std::span<const uint8_t> ikm,
           Hash& out1, Hash& out2);
void hkdf3(std::span<const uint8_t> chaining_key, std::span<const uint8_t> ikm,
           Hash& out1, Hash& out2, Hash& out3);

// Standard RFC 5869 HKDF, for deriving uConnect subkeys from K.
void hkdf(std::span<const uint8_t> ikm, std::span<const uint8_t> salt,
          std::string_view info, std::span<uint8_t> out);

// --- X25519 ----------------------------------------------------------------
struct KeyPair {
    SecretKey secret{};
    PublicKey pub{};

    static KeyPair generate();
    static KeyPair from_secret(const SecretKey&);
};

// Returns false if the result is the all-zero point, which signals a
// small-order (degenerate) public key. Noise permits ignoring this, but an
// explicit check costs nothing and refuses a peer trying to force a known
// shared secret.
bool x25519(const SecretKey& sk, const PublicKey& pk, PublicKey& out);

// --- ChaCha20-Poly1305 (RFC 8439) ------------------------------------------
// Noise nonce encoding: 4 zero bytes followed by the 64-bit counter in
// little-endian order.
void aead_encrypt(const SymKey& key, uint64_t nonce, std::span<const uint8_t> ad,
                  std::span<const uint8_t> plaintext, std::span<uint8_t> out);

// out must be at least ciphertext.size() - kTagLen. Returns false on tag
// mismatch, in which case out is left zeroed -- never hand a caller plaintext
// that failed authentication.
bool aead_decrypt(const SymKey& key, uint64_t nonce, std::span<const uint8_t> ad,
                  std::span<const uint8_t> ciphertext, std::span<uint8_t> out);

// Explicit 96-bit nonce. The Noise-facing functions above are thin wrappers
// over these. Exposed because the RFC 8439 vectors use a nonce that the Noise
// encoding cannot represent (its first 4 bytes are non-zero), and a Poly1305
// implementation that is only ever tested against itself is not tested.
void aead_encrypt_n12(const SymKey& key, const uint8_t nonce[12], std::span<const uint8_t> ad,
                      std::span<const uint8_t> plaintext, std::span<uint8_t> out);
bool aead_decrypt_n12(const SymKey& key, const uint8_t nonce[12], std::span<const uint8_t> ad,
                      std::span<const uint8_t> ciphertext, std::span<uint8_t> out);

void chacha20_block(const SymKey& key, uint32_t counter, const uint8_t nonce[12],
                    uint8_t out[64]);
void chacha20_xor(const SymKey& key, uint32_t counter, const uint8_t nonce[12],
                  std::span<const uint8_t> in, std::span<uint8_t> out);

}  // namespace uconnect::crypto
