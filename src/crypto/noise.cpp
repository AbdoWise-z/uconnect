#include "noise.hpp"

#include <cstring>

namespace uconnect::crypto {
namespace {

constexpr std::string_view kNameNN     = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
constexpr std::string_view kNameNNpsk0 = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";

constexpr std::string_view protocol_name(Pattern p) {
    return p == Pattern::NNpsk0 ? kNameNNpsk0 : kNameNN;
}

std::span<const uint8_t> as_bytes(std::string_view s) {
    return {reinterpret_cast<const uint8_t*>(s.data()), s.size()};
}

}  // namespace

// ---------------------------------------------------------------------------
// CipherState
// ---------------------------------------------------------------------------
size_t CipherState::encrypt_with_ad(std::span<const uint8_t> ad,
                                    std::span<const uint8_t> plaintext,
                                    std::span<uint8_t> out) {
    if (!has_key_) {
        std::memcpy(out.data(), plaintext.data(), plaintext.size());
        return plaintext.size();
    }
    aead_encrypt(key_, nonce_, ad, plaintext, out);
    ++nonce_;
    return plaintext.size() + kTagLen;
}

std::optional<size_t> CipherState::decrypt_with_ad(std::span<const uint8_t> ad,
                                                   std::span<const uint8_t> ciphertext,
                                                   std::span<uint8_t> out) {
    if (!has_key_) {
        if (out.size() < ciphertext.size()) return std::nullopt;
        std::memcpy(out.data(), ciphertext.data(), ciphertext.size());
        return ciphertext.size();
    }
    if (ciphertext.size() < kTagLen) return std::nullopt;
    if (!aead_decrypt(key_, nonce_, ad, ciphertext, out)) return std::nullopt;
    // Advance only on success: a forged packet must not be able to burn a nonce
    // and desynchronise the stream.
    ++nonce_;
    return ciphertext.size() - kTagLen;
}

size_t CipherState::encrypt_at(uint64_t n, std::span<const uint8_t> ad,
                               std::span<const uint8_t> plaintext,
                               std::span<uint8_t> out) const {
    aead_encrypt(key_, n, ad, plaintext, out);
    return plaintext.size() + kTagLen;
}

std::optional<size_t> CipherState::decrypt_at(uint64_t n, std::span<const uint8_t> ad,
                                              std::span<const uint8_t> ciphertext,
                                              std::span<uint8_t> out) const {
    if (ciphertext.size() < kTagLen) return std::nullopt;
    if (!aead_decrypt(key_, n, ad, ciphertext, out)) return std::nullopt;
    return ciphertext.size() - kTagLen;
}

void CipherState::rekey() {
    // Noise s11.3: k = ENCRYPT(k, 2^64-1, zerolen, zeros[32])
    std::array<uint8_t, kKeyLen>            zeros{};
    std::array<uint8_t, kKeyLen + kTagLen>  out{};
    aead_encrypt(key_, UINT64_MAX, {}, zeros, out);
    std::memcpy(key_.data(), out.data(), kKeyLen);
    secure_zero(out);
}

void CipherState::clear() {
    secure_zero(key_);
    has_key_ = false;
    nonce_   = 0;
}

// ---------------------------------------------------------------------------
// SymmetricState
// ---------------------------------------------------------------------------
SymmetricState::SymmetricState(std::string_view protocol) {
    // Noise s5.2: if the name fits in HASHLEN, it is zero-padded; otherwise it
    // is hashed. Both of our names are 33 and 37 bytes, so both hash.
    if (protocol.size() <= kHashLen) {
        std::memcpy(h_.data(), protocol.data(), protocol.size());
    } else {
        h_ = Blake2s::hash(as_bytes(protocol));
    }
    ck_ = h_;
}

void SymmetricState::mix_hash(std::span<const uint8_t> data) {
    Blake2s hasher;
    hasher.update(h_);
    hasher.update(data);
    h_ = hasher.finish();
}

void SymmetricState::mix_key(std::span<const uint8_t> ikm) {
    Hash new_ck{}, temp_k{};
    hkdf2(ck_, ikm, new_ck, temp_k);
    ck_ = new_ck;
    SymKey k{};
    std::memcpy(k.data(), temp_k.data(), kKeyLen);
    cipher_ = CipherState{k};
    secure_zero(temp_k);
    secure_zero(k);
}

void SymmetricState::mix_key_and_hash(std::span<const uint8_t> ikm) {
    Hash new_ck{}, temp_h{}, temp_k{};
    hkdf3(ck_, ikm, new_ck, temp_h, temp_k);
    ck_ = new_ck;
    mix_hash(temp_h);
    SymKey k{};
    std::memcpy(k.data(), temp_k.data(), kKeyLen);
    cipher_ = CipherState{k};
    secure_zero(temp_h);
    secure_zero(temp_k);
    secure_zero(k);
}

size_t SymmetricState::encrypt_and_hash(std::span<const uint8_t> pt, std::span<uint8_t> out) {
    size_t n = cipher_.encrypt_with_ad(h_, pt, out);
    mix_hash(out.first(n));
    return n;
}

std::optional<size_t> SymmetricState::decrypt_and_hash(std::span<const uint8_t> ct,
                                                       std::span<uint8_t> out) {
    // h must be captured before it is mixed, because it is the AD for this
    // decryption.
    auto n = cipher_.decrypt_with_ad(h_, ct, out);
    if (!n) return std::nullopt;
    mix_hash(ct);
    return n;
}

void SymmetricState::split(CipherState& c1, CipherState& c2) {
    Hash t1{}, t2{};
    hkdf2(ck_, {}, t1, t2);
    SymKey k1{}, k2{};
    std::memcpy(k1.data(), t1.data(), kKeyLen);
    std::memcpy(k2.data(), t2.data(), kKeyLen);
    c1 = CipherState{k1};
    c2 = CipherState{k2};
    secure_zero(t1);
    secure_zero(t2);
    secure_zero(k1);
    secure_zero(k2);
}

// ---------------------------------------------------------------------------
// HandshakeState
// ---------------------------------------------------------------------------
HandshakeState::HandshakeState(Pattern p, bool is_initiator,
                               std::span<const uint8_t> prologue, const SymKey* psk)
    : pattern_(p), initiator_(is_initiator), sym_(protocol_name(p)) {
    sym_.mix_hash(prologue);
    if (psk) {
        psk_     = *psk;
        has_psk_ = true;
    }
}

HandshakeState HandshakeState::initiator(Pattern p, std::span<const uint8_t> prologue,
                                         const SymKey* psk) {
    return HandshakeState{p, true, prologue, psk};
}

HandshakeState HandshakeState::responder(Pattern p, std::span<const uint8_t> prologue,
                                         const SymKey* psk) {
    return HandshakeState{p, false, prologue, psk};
}

void HandshakeState::mix_ephemeral(const PublicKey& pub) {
    sym_.mix_hash(pub);
    // Noise s9.3: in a PSK handshake the "e" token additionally calls MixKey on
    // the ephemeral public key. Omitting this yields a handshake that is
    // self-consistent but interoperates with nothing.
    if (pattern_ == Pattern::NNpsk0) sym_.mix_key(pub);
}

size_t HandshakeState::message_overhead(Pattern p, int message_index) {
    if (p == Pattern::NNpsk0) return kDhLen + kTagLen;  // both messages are keyed
    return message_index == 0 ? kDhLen : kDhLen + kTagLen;  // NN msg1 has no key yet
}

std::optional<size_t> HandshakeState::write_message(std::span<const uint8_t> payload,
                                                    std::span<uint8_t> out) {
    if (finished_) return std::nullopt;
    const bool our_turn = (msg_index_ == 0) == initiator_;
    if (!our_turn) return std::nullopt;
    if (out.size() < payload.size() + message_overhead(pattern_, msg_index_)) {
        return std::nullopt;
    }

    size_t off = 0;

    if (msg_index_ == 0) {
        // -> [psk], e
        if (pattern_ == Pattern::NNpsk0) sym_.mix_key_and_hash(psk_);
        e_ = KeyPair::generate();
        std::memcpy(out.data() + off, e_.pub.data(), kDhLen);
        off += kDhLen;
        mix_ephemeral(e_.pub);
    } else {
        // <- e, ee
        e_ = KeyPair::generate();
        std::memcpy(out.data() + off, e_.pub.data(), kDhLen);
        off += kDhLen;
        mix_ephemeral(e_.pub);

        if (!have_re_) return std::nullopt;
        PublicKey shared{};
        if (!x25519(e_.secret, re_, shared)) return std::nullopt;
        sym_.mix_key(shared);
        secure_zero(shared);
    }

    off += sym_.encrypt_and_hash(payload, out.subspan(off));
    ++msg_index_;
    if (msg_index_ == 2) finished_ = true;
    return off;
}

std::optional<size_t> HandshakeState::read_message(std::span<const uint8_t> message,
                                                   std::span<uint8_t> payload_out) {
    if (finished_) return std::nullopt;
    const bool our_turn = (msg_index_ == 0) != initiator_;
    if (!our_turn) return std::nullopt;
    if (message.size() < message_overhead(pattern_, msg_index_)) return std::nullopt;

    size_t off = 0;

    if (msg_index_ == 0) {
        // -> [psk], e
        if (pattern_ == Pattern::NNpsk0) sym_.mix_key_and_hash(psk_);
        std::memcpy(re_.data(), message.data() + off, kDhLen);
        have_re_ = true;
        off += kDhLen;
        mix_ephemeral(re_);
    } else {
        // <- e, ee
        std::memcpy(re_.data(), message.data() + off, kDhLen);
        have_re_ = true;
        off += kDhLen;
        mix_ephemeral(re_);

        PublicKey shared{};
        if (!x25519(e_.secret, re_, shared)) return std::nullopt;
        sym_.mix_key(shared);
        secure_zero(shared);
    }

    auto n = sym_.decrypt_and_hash(message.subspan(off), payload_out);
    if (!n) return std::nullopt;

    ++msg_index_;
    if (msg_index_ == 2) finished_ = true;
    return n;
}

Split HandshakeState::split() {
    Split s;
    CipherState c1, c2;
    sym_.split(c1, c2);
    // c1 is the initiator-to-responder direction.
    if (initiator_) {
        s.send = c1;
        s.recv = c2;
    } else {
        s.send = c2;
        s.recv = c1;
    }
    s.handshake_hash = sym_.handshake_hash();
    secure_zero(psk_);
    return s;
}

}  // namespace uconnect::crypto
