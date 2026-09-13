#pragma once
// uConnect key derivation.
//
// K is 32 bytes / 64 hex of CSPRNG output. It is never used directly and never
// transmitted. Everything is derived from it with domain-separated HKDF so that
// exposure of one subkey cannot cross over into another use.
//
// On sizing: 32 bytes is the right answer, not 64. Every construction
// downstream is 256-bit -- the Noise PSK slot, the ChaCha20 key, the BLAKE2s
// output -- so a 512-bit input is compressed to 256 bits regardless, and the
// security of a chain is bounded by its narrowest link. A longer key buys
// nothing but characters to copy around.

#include "primitives.hpp"
#include "uconnect/types.hpp"

namespace uconnect::crypto {

inline constexpr std::string_view kInfoPsk   = "uconnect:v1:psk";
inline constexpr std::string_view kInfoProbe = "uconnect:v1:probe";
inline constexpr std::string_view kInfoTopic = "uconnect:v1:topic";
inline constexpr std::string_view kInfoSas   = "uconnect:v1:sas";

struct TopicKeys {
    SymKey psk{};    // mixed into the Noise handshake
    SymKey probe{};  // keys the probe tag, so non-members cannot elicit a reply

    static TopicKeys derive(const Key& k) {
        TopicKeys out;
        hkdf(k, {}, kInfoPsk, out.psk);
        hkdf(k, {}, kInfoProbe, out.probe);
        return out;
    }

    ~TopicKeys() {
        secure_zero(psk);
        secure_zero(probe);
    }

    TopicKeys()                            = default;
    TopicKeys(const TopicKeys&)            = default;
    TopicKeys& operator=(const TopicKeys&) = default;
};

// Optional: derive the topic id from K so only one value has to be distributed
// and the two can never be mismatched. Independent ids remain supported --
// keeping them separate lets K rotate without changing the topic.
inline TopicId derive_topic_id(const Key& k) {
    TopicId id{};
    hkdf(k, {}, kInfoTopic, id);
    return id;
}

// Short Authentication String for open topics. Both ends derive it from the
// handshake hash and compare out of band (voice, screen, whatever the attacker
// does not control). An interposed MITM necessarily produces two different
// handshake hashes and therefore two different strings.
//
// This gives an open topic real authentication with no PSK and no PKI, which
// suits the anonymity model: it proves channel integrity without attaching any
// persistent identity.
std::string sas_string(const Hash& handshake_hash);

}  // namespace uconnect::crypto
