#pragma once
// Noise Protocol Framework -- the NN and NNpsk0 patterns.
//
//   Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s   (keyed topics)
//     -> psk, e
//     <- e, ee
//
//   Noise_NN_25519_ChaChaPoly_BLAKE2s       (open topics)
//     -> e
//     <- e, ee
//
// NNpsk0 gives confidentiality, forward secrecy from the ephemeral DH, and
// mutual authentication as topic members: completing the handshake proves the
// peer holds K. It deliberately gives no individual identity -- that belongs to
// the application layer, above this transport.
//
// It is also resistant to harvest-now-decrypt-later. An adversary who breaks
// X25519 with a future quantum computer still faces a 256-bit symmetric unknown
// mixed into the chaining key. NN has no such protection.
//
// Two properties of NNpsk0 that shape how the caller must use it:
//
//  1. The message-1 payload has NO forward secrecy. It is encrypted under a key
//     derived from the PSK alone, before any DH has happened. Send padding
//     only; put real data in the first transport message.
//  2. Message 1 is replayable and costs the responder a DH. The caller must
//     gate handshake acceptance on a completed probe exchange -- see
//     Session::accept() in the path layer.

#include <optional>

#include "primitives.hpp"

namespace uconnect::crypto {

// --- CipherState (Noise spec s5.1) -----------------------------------------
class CipherState {
public:
    CipherState() = default;
    explicit CipherState(const SymKey& k) : key_(k), has_key_(true) {}

    bool     has_key() const { return has_key_; }
    uint64_t nonce() const { return nonce_; }
    void     set_nonce(uint64_t n) { nonce_ = n; }

    // Returns ciphertext length (plaintext + tag), or plaintext length if no
    // key has been established yet.
    size_t encrypt_with_ad(std::span<const uint8_t> ad, std::span<const uint8_t> plaintext,
                           std::span<uint8_t> out);

    // Returns plaintext length on success. Nonce advances only on success, so a
    // forged or corrupt packet cannot desynchronise the stream.
    std::optional<size_t> decrypt_with_ad(std::span<const uint8_t> ad,
                                          std::span<const uint8_t> ciphertext,
                                          std::span<uint8_t> out);

    // Decrypt at an explicit nonce, for the out-of-order transport path where
    // the counter travels on the wire.
    std::optional<size_t> decrypt_at(uint64_t n, std::span<const uint8_t> ad,
                                     std::span<const uint8_t> ciphertext,
                                     std::span<uint8_t> out) const;
    size_t encrypt_at(uint64_t n, std::span<const uint8_t> ad,
                      std::span<const uint8_t> plaintext, std::span<uint8_t> out) const;

    void rekey();
    void clear();

private:
    SymKey   key_{};
    uint64_t nonce_   = 0;
    bool     has_key_ = false;
};

// --- SymmetricState (Noise spec s5.2) --------------------------------------
class SymmetricState {
public:
    explicit SymmetricState(std::string_view protocol_name);

    void mix_hash(std::span<const uint8_t> data);
    void mix_key(std::span<const uint8_t> ikm);
    void mix_key_and_hash(std::span<const uint8_t> ikm);

    size_t                encrypt_and_hash(std::span<const uint8_t> pt, std::span<uint8_t> out);
    std::optional<size_t> decrypt_and_hash(std::span<const uint8_t> ct, std::span<uint8_t> out);

    void split(CipherState& c1, CipherState& c2);

    const Hash& handshake_hash() const { return h_; }

private:
    Hash        ck_{};
    Hash        h_{};
    CipherState cipher_;
};

// --- HandshakeState --------------------------------------------------------
enum class Pattern { NN, NNpsk0 };

// Result of a completed handshake.
struct Split {
    CipherState send;
    CipherState recv;
    // Unique to this session and identical on both ends. The application layer
    // MUST bind its identity proofs to this value -- signing it is what stops
    // an insider (anyone holding K) from relaying A's identity proof into a
    // second session and impersonating them to B.
    Hash handshake_hash{};
};

class HandshakeState {
public:
    // prologue is mixed in before anything else, so both sides must agree on it
    // or the handshake fails cryptographically rather than via a check someone
    // might forget to write. uConnect sets it to
    //   "uconnect:v1" || topic_id || key_epoch || probe_txn
    // which binds the session to the topic, the key epoch, and the specific
    // validated path.
    static HandshakeState initiator(Pattern, std::span<const uint8_t> prologue,
                                    const SymKey* psk);
    static HandshakeState responder(Pattern, std::span<const uint8_t> prologue,
                                    const SymKey* psk);

    // Writes the next handshake message. Returns bytes written, or nullopt if
    // it is not our turn / the handshake is finished.
    std::optional<size_t> write_message(std::span<const uint8_t> payload,
                                        std::span<uint8_t> out);

    // Reads the next handshake message, placing any payload in `payload_out`.
    // Returns payload length, or nullopt on any failure -- which callers must
    // treat as "drop the packet silently", never as an error to report, or the
    // responder becomes an oracle for topic membership.
    std::optional<size_t> read_message(std::span<const uint8_t> message,
                                       std::span<uint8_t> payload_out);

    bool is_finished() const { return finished_; }

    // Valid only once is_finished(). Initiator's `send` is the responder's
    // `recv` and vice versa.
    Split split();

    // Overhead added to a payload by each handshake message, so callers can
    // size buffers without guessing.
    static size_t message_overhead(Pattern p, int message_index);

private:
    HandshakeState(Pattern, bool initiator, std::span<const uint8_t> prologue,
                   const SymKey* psk);

    void mix_ephemeral(const PublicKey& pub);

    Pattern        pattern_   = Pattern::NNpsk0;
    bool           initiator_ = true;
    bool           finished_  = false;
    int            msg_index_ = 0;
    bool           has_psk_   = false;
    SymKey         psk_{};
    KeyPair        e_{};
    PublicKey      re_{};
    bool           have_re_ = false;
    SymmetricState sym_;
};

}  // namespace uconnect::crypto
