// Validation against published test vectors.
//
// This file is the entire reason to trust the crypto layer. Every primitive
// here is self-consistent when implemented wrongly -- a broken BLAKE2s hashes
// happily, a broken X25519 returns 32 plausible bytes, and two peers running
// the same broken code will complete a handshake and talk to each other. Only
// the published vectors distinguish "works" from "correct".

#include <algorithm>
#include <cstring>
#include <string>

#include "kdf.hpp"
#include "noise.hpp"
#include "poly1305.h"
#include "primitives.hpp"
#include "testing.hpp"
#include "uconnect/types.hpp"

using namespace uconnect;
using namespace uconnect::crypto;

namespace {

std::vector<uint8_t> unhex(std::string_view s) {
    std::vector<uint8_t> out(s.size() / 2);
    from_hex(s, out.data(), out.size());
    return out;
}

template <size_t N>
std::array<uint8_t, N> unhex_arr(std::string_view s) {
    std::array<uint8_t, N> out{};
    from_hex(s, out.data(), N);
    return out;
}

std::string hex(std::span<const uint8_t> b) { return to_hex(b.data(), b.size()); }

}  // namespace

// ---------------------------------------------------------------------------
// BLAKE2s -- RFC 7693 Appendix B and the official test suite
// ---------------------------------------------------------------------------
TEST(blake2s_matches_rfc7693_vector) {
    // RFC 7693 Appendix B: BLAKE2s-256 of "abc"
    auto h = Blake2s::hash(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>("abc"), 3));
    CHECK(hex(h) == "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
}

TEST(blake2s_matches_empty_input_vector) {
    auto h = Blake2s::hash({});
    CHECK(hex(h) == "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
}

TEST(blake2s_keyed_matches_reference_vector) {
    // From the BLAKE2 reference test suite (blake2s-kat): key = 00..1f,
    // input = 00 (single byte).
    std::array<uint8_t, 32> key{};
    for (uint8_t i = 0; i < 32; ++i) key[i] = i;
    std::array<uint8_t, 1> in{0x00};
    auto h = Blake2s::mac(key, in);
    CHECK(hex(h) == "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1");
}

TEST(blake2s_handles_block_boundaries) {
    // The finalization flag applies only to the last block, and the buffering
    // code must never compress a block it might have to re-flag. Exercise the
    // sizes where that goes wrong: 63, 64, 65, 127, 128, 129.
    for (size_t len : {0u, 1u, 63u, 64u, 65u, 127u, 128u, 129u, 1000u}) {
        std::vector<uint8_t> data(len);
        for (size_t i = 0; i < len; ++i) data[i] = static_cast<uint8_t>(i & 0xFF);

        Hash one_shot = Blake2s::hash(data);

        // Same input fed one byte at a time must produce the same digest.
        Blake2s incremental;
        for (size_t i = 0; i < len; ++i) incremental.update(std::span(data).subspan(i, 1));
        Hash streamed = incremental.finish();

        if (one_shot != streamed) {
            ::testing::fail(__FILE__, __LINE__,
                            "streaming mismatch at len " + std::to_string(len));
        }
    }
}

TEST(blake2s_multiblock_streaming_agrees_with_one_shot) {
    // Vector coverage for the compression function comes from the "abc" and
    // empty-input vectors above. What this adds is the buffering path: a
    // 1000-byte message fed in 7-byte chunks crosses block boundaries at every
    // offset, which is where the "never compress a block that might turn out to
    // be last" rule gets violated.
    std::vector<uint8_t> in(1000);
    for (size_t i = 0; i < in.size(); ++i) in[i] = static_cast<uint8_t>(i * 31 & 0xFF);

    Hash one_shot = Blake2s::hash(in);

    for (size_t chunk : {1u, 7u, 63u, 64u, 65u, 200u}) {
        Blake2s inc;
        for (size_t i = 0; i < in.size(); i += chunk) {
            size_t n = in.size() - i < chunk ? in.size() - i : chunk;
            inc.update(std::span(in).subspan(i, n));
        }
        if (inc.finish() != one_shot) {
            ::testing::fail(__FILE__, __LINE__,
                            "chunked update mismatch at chunk " + std::to_string(chunk));
        }
    }
}

TEST(poly1305_matches_rfc8439_section_2_5_2) {
    // The vendored Poly1305 needs its own vector -- an AEAD round-trip only
    // proves the tag function agrees with itself, which a broken one does too.
    auto key = unhex("85d6be7857556d337f4452fe42d506a8"
                     "0103808afb0db2fd4abff6af4149f51b");
    const char* msg = "Cryptographic Forum Research Group";

    uconnect_poly1305_ctx ctx;
    uconnect_poly1305_init(&ctx, key.data());
    uconnect_poly1305_update(&ctx, reinterpret_cast<const uint8_t*>(msg),
                             std::strlen(msg));
    std::array<uint8_t, 16> tag{};
    uconnect_poly1305_finish(&ctx, tag.data());

    CHECK(hex(tag) == "a8061dc1305136c6c22b8baf0c0127a9");
}

// ---------------------------------------------------------------------------
// ChaCha20 -- RFC 8439 s2.3.2 and s2.4.2
// ---------------------------------------------------------------------------
TEST(chacha20_block_matches_rfc8439_section_2_3_2) {
    SymKey key{};
    for (uint8_t i = 0; i < 32; ++i) key[i] = i;
    uint8_t nonce[12] = {0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};

    uint8_t block[64];
    chacha20_block(key, 1, nonce, block);

    CHECK(hex(std::span<const uint8_t>(block, 64)) ==
          "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
          "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
}

TEST(chacha20_encrypts_rfc8439_sunscreen_plaintext) {
    SymKey key{};
    for (uint8_t i = 0; i < 32; ++i) key[i] = i;
    uint8_t nonce[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};

    const char* pt =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for "
        "the future, sunscreen would be it.";
    size_t               n = std::strlen(pt);
    std::vector<uint8_t> in(reinterpret_cast<const uint8_t*>(pt),
                            reinterpret_cast<const uint8_t*>(pt) + n);
    std::vector<uint8_t> out(n);
    chacha20_xor(key, 1, nonce, in, out);

    CHECK(hex(out).substr(0, 64) ==
          "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b");

    // Round-trip: the stream cipher is its own inverse.
    std::vector<uint8_t> back(n);
    chacha20_xor(key, 1, nonce, out, back);
    CHECK(back == in);
}

// ---------------------------------------------------------------------------
// AEAD_CHACHA20_POLY1305 -- RFC 8439 s2.8.2
// ---------------------------------------------------------------------------
TEST(aead_matches_rfc8439_section_2_8_2) {
    // Full vector: exact ciphertext and exact tag. The RFC nonce starts with a
    // non-zero byte, which the Noise encoding cannot express, so this drives
    // the explicit-nonce entry point.
    SymKey key{};
    for (uint8_t i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(0x80 + i);

    const uint8_t nonce[12] = {0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                               0x42, 0x43, 0x44, 0x45, 0x46, 0x47};
    auto          ad  = unhex("50515253c0c1c2c3c4c5c6c7");
    const char*   msg = "Ladies and Gentlemen of the class of '99: If I could offer you "
                        "only one tip for the future, sunscreen would be it.";
    std::vector<uint8_t> pt(reinterpret_cast<const uint8_t*>(msg),
                            reinterpret_cast<const uint8_t*>(msg) + std::strlen(msg));

    std::vector<uint8_t> ct(pt.size() + kTagLen);
    aead_encrypt_n12(key, nonce, ad, pt, ct);

    CHECK(hex(std::span(ct).first(pt.size())) ==
          "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
          "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
          "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
          "3ff4def08e4b7a9de576d26586cec64b6116");
    CHECK(hex(std::span(ct).last(kTagLen)) == "1ae10b594f09e26a7e902ecbd0600691");

    std::vector<uint8_t> back(pt.size());
    CHECK(aead_decrypt_n12(key, nonce, ad, ct, back));
    CHECK(back == pt);
}

TEST(aead_rejects_tampered_ciphertext_tag_and_ad) {
    SymKey key{};
    random_bytes(key);
    std::vector<uint8_t> ad{1, 2, 3, 4};
    std::vector<uint8_t> pt{'h', 'e', 'l', 'l', 'o', '!'};
    std::vector<uint8_t> ct(pt.size() + kTagLen);
    aead_encrypt(key, 42, ad, pt, ct);

    std::vector<uint8_t> out(pt.size());

    // Flip a bit in the ciphertext body.
    auto t1 = ct;
    t1[0] ^= 0x01;
    CHECK(!aead_decrypt(key, 42, ad, t1, out));

    // Flip a bit in the tag.
    auto t2 = ct;
    t2[t2.size() - 1] ^= 0x01;
    CHECK(!aead_decrypt(key, 42, ad, t2, out));

    // Alter the associated data.
    auto bad_ad = ad;
    bad_ad[0] ^= 0x01;
    CHECK(!aead_decrypt(key, 42, bad_ad, ct, out));

    // Wrong nonce.
    CHECK(!aead_decrypt(key, 43, ad, ct, out));

    // Correct everything still works, so the rejections above were real.
    CHECK(aead_decrypt(key, 42, ad, ct, out));
}

TEST(aead_failure_leaves_no_plaintext_in_the_output_buffer) {
    // Decrypting before verifying is the classic AEAD misuse. A caller that
    // ignores the return value must not find usable plaintext sitting there.
    SymKey key{};
    random_bytes(key);
    std::vector<uint8_t> pt(64, 0xAB);
    std::vector<uint8_t> ct(pt.size() + kTagLen);
    aead_encrypt(key, 1, {}, pt, ct);
    ct[5] ^= 0xFF;

    std::vector<uint8_t> out(pt.size(), 0x11);
    CHECK(!aead_decrypt(key, 1, {}, ct, out));
    for (auto b : out) CHECK(b == 0);
}

// ---------------------------------------------------------------------------
// X25519 -- RFC 7748 s5.2 and s6.1
// ---------------------------------------------------------------------------
TEST(x25519_matches_rfc7748_scalarmult_vectors) {
    auto scalar = unhex_arr<32>("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    auto u      = unhex_arr<32>("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    PublicKey out{};
    x25519(scalar, u, out);
    CHECK(hex(out) == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

    auto scalar2 = unhex_arr<32>("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
    auto u2      = unhex_arr<32>("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
    x25519(scalar2, u2, out);
    CHECK(hex(out) == "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
}

TEST(x25519_matches_rfc7748_diffie_hellman_vector) {
    // RFC 7748 s6.1: Alice and Bob's keys and their shared secret.
    auto a_sk = unhex_arr<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    auto b_sk = unhex_arr<32>("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

    auto a = KeyPair::from_secret(a_sk);
    auto b = KeyPair::from_secret(b_sk);

    CHECK(hex(a.pub) == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    CHECK(hex(b.pub) == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

    PublicKey s1{}, s2{};
    CHECK(x25519(a.secret, b.pub, s1));
    CHECK(x25519(b.secret, a.pub, s2));
    CHECK(hex(s1) == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    CHECK(s1 == s2);  // the whole point of a Diffie-Hellman
}

TEST(x25519_rejects_small_order_points) {
    // An all-zero output means the peer forced a shared secret it already
    // knows. Noise permits ignoring this; refusing costs nothing.
    SecretKey sk{};
    random_bytes(sk);
    PublicKey zero{};  // the identity point
    PublicKey out{};
    CHECK(!x25519(sk, zero, out));
}

TEST(x25519_generated_keypairs_agree) {
    for (int i = 0; i < 8; ++i) {
        auto a = KeyPair::generate();
        auto b = KeyPair::generate();
        PublicKey s1{}, s2{};
        REQUIRE(x25519(a.secret, b.pub, s1));
        REQUIRE(x25519(b.secret, a.pub, s2));
        CHECK(s1 == s2);
    }
}

// ---------------------------------------------------------------------------
// Randomness
// ---------------------------------------------------------------------------
TEST(random_bytes_is_not_the_mingw_deterministic_trap) {
    // std::random_device on MinGW-w64 has historically returned an identical
    // sequence on every run. If random_bytes ever regressed to it, two calls in
    // the same process would still differ -- so instead assert on distribution,
    // which a constant or a low-entropy source would fail.
    std::array<uint8_t, 64> a{}, b{};
    random_bytes(a);
    random_bytes(b);
    CHECK(a != b);

    std::array<int, 256> counts{};
    std::array<uint8_t, 16384> big{};
    random_bytes(big);
    for (auto v : big) counts[v]++;

    int zero_buckets = 0;
    for (auto c : counts) {
        if (c == 0) ++zero_buckets;
    }
    // 16384 samples across 256 buckets: ~64 expected each. Seeing any empty
    // bucket would indicate a badly non-uniform source.
    CHECK(zero_buckets == 0);

    // Not all one value, not monotonic.
    bool all_same = true;
    for (size_t i = 1; i < big.size(); ++i) {
        if (big[i] != big[0]) { all_same = false; break; }
    }
    CHECK(!all_same);
}

TEST(ct_equal_behaves_like_equality) {
    std::array<uint8_t, 16> a{}, b{};
    random_bytes(a);
    b = a;
    CHECK(ct_equal(a, b));
    b[15] ^= 0x01;
    CHECK(!ct_equal(a, b));
    std::array<uint8_t, 15> shorter{};
    CHECK(!ct_equal(a, shorter));
}

// ---------------------------------------------------------------------------
// HKDF
// ---------------------------------------------------------------------------
TEST(hkdf_is_domain_separated) {
    Key k{};
    random_bytes(k);
    auto keys = TopicKeys::derive(k);
    // Different info strings must yield unrelated subkeys, or a leak in one use
    // compromises the others.
    CHECK(keys.psk != keys.probe);

    // Deterministic: the same K always derives the same subkeys, or two peers
    // would never agree.
    auto again = TopicKeys::derive(k);
    CHECK(keys.psk == again.psk);
    CHECK(keys.probe == again.probe);

    // A different K yields different subkeys.
    Key k2{};
    random_bytes(k2);
    auto other = TopicKeys::derive(k2);
    CHECK(other.psk != keys.psk);
}

TEST(hkdf_produces_requested_length_across_block_boundaries) {
    // RFC 5869 expands T(1) | T(2) | ... and returns the first L octets, so a
    // shorter output must be a prefix of a longer one from the same inputs.
    // That is the property this test's name is about, and it is what catches a
    // mishandled block counter at the 32-byte BLAKE2s boundary.
    //
    // It replaces a "the output is not all zeroes" check, which asserted
    // almost nothing and failed roughly one run in 256: the list of lengths
    // includes 1, and a single random byte is legitimately zero that often.
    Key k{};
    k.fill(0x5A);   // fixed: this is about determinism, not randomness

    std::vector<uint8_t> longest(100);
    hkdf(k, {}, "test", longest);

    for (size_t len : {1u, 16u, 32u, 33u, 64u, 100u}) {
        std::vector<uint8_t> out(len);
        hkdf(k, {}, "test", out);
        CHECK_EQ(out.size(), len);
        CHECK(std::equal(out.begin(), out.end(), longest.begin()));
    }

    // And the info string actually separates: same key, different purpose,
    // different bytes.
    std::vector<uint8_t> other(100);
    hkdf(k, {}, "different", other);
    CHECK(other != longest);
}

TEST(noise_hkdf_outputs_differ_from_each_other) {
    Hash ck{}, ikm{};
    random_bytes(ck);
    random_bytes(ikm);
    Hash o1{}, o2{}, o3{};
    hkdf3(ck, ikm, o1, o2, o3);
    CHECK(o1 != o2);
    CHECK(o2 != o3);
    CHECK(o1 != o3);

    Hash p1{}, p2{};
    hkdf2(ck, ikm, p1, p2);
    // hkdf2 and hkdf3 share the first two outputs by construction.
    CHECK(p1 == o1);
    CHECK(p2 == o2);
}

// ---------------------------------------------------------------------------
// Noise handshakes
// ---------------------------------------------------------------------------
namespace {

// Drive a full two-message handshake between two HandshakeStates.
bool run_handshake(HandshakeState& initiator, HandshakeState& responder, Split& si,
                   Split& sr, std::span<const uint8_t> msg1_payload = {}) {
    std::vector<uint8_t> msg1(256), msg2(256), pay(256);

    auto n1 = initiator.write_message(msg1_payload, msg1);
    if (!n1) return false;
    auto r1 = responder.read_message(std::span(msg1).first(*n1), pay);
    if (!r1) return false;

    auto n2 = responder.write_message({}, msg2);
    if (!n2) return false;
    auto r2 = initiator.read_message(std::span(msg2).first(*n2), pay);
    if (!r2) return false;

    if (!initiator.is_finished() || !responder.is_finished()) return false;
    si = initiator.split();
    sr = responder.split();
    return true;
}

}  // namespace

TEST(nnpsk0_handshake_succeeds_and_agrees_on_keys) {
    Key k{};
    random_bytes(k);
    auto tk = TopicKeys::derive(k);

    std::vector<uint8_t> prologue{'u', 'c', 'o', 'n', 'n', 'e', 'c', 't'};
    auto a = HandshakeState::initiator(Pattern::NNpsk0, prologue, &tk.psk);
    auto b = HandshakeState::responder(Pattern::NNpsk0, prologue, &tk.psk);

    Split sa, sb;
    REQUIRE(run_handshake(a, b, sa, sb));

    // Both ends must derive the same handshake hash -- this is the value the
    // application layer binds its identity proofs to.
    CHECK(sa.handshake_hash == sb.handshake_hash);

    // And the directional keys must line up: A's send is B's recv.
    std::vector<uint8_t> pt{'p', 'i', 'n', 'g'};
    std::vector<uint8_t> ct(pt.size() + kTagLen);
    sa.send.encrypt_with_ad({}, pt, ct);
    std::vector<uint8_t> out(pt.size());
    auto n = sb.recv.decrypt_with_ad({}, ct, out);
    REQUIRE(n.has_value());
    CHECK(out == pt);

    // And the reverse direction.
    std::vector<uint8_t> pt2{'p', 'o', 'n', 'g'};
    std::vector<uint8_t> ct2(pt2.size() + kTagLen);
    sb.send.encrypt_with_ad({}, pt2, ct2);
    std::vector<uint8_t> out2(pt2.size());
    auto n2 = sa.recv.decrypt_with_ad({}, ct2, out2);
    REQUIRE(n2.has_value());
    CHECK(out2 == pt2);
}

TEST(nnpsk0_fails_when_the_psk_differs) {
    // This is the property the whole keyed design rests on: a peer without K
    // cannot complete the handshake, so the rendezvous server cannot MITM.
    Key k1{}, k2{};
    random_bytes(k1);
    random_bytes(k2);
    auto tk1 = TopicKeys::derive(k1);
    auto tk2 = TopicKeys::derive(k2);

    std::vector<uint8_t> prologue{'p'};
    auto a = HandshakeState::initiator(Pattern::NNpsk0, prologue, &tk1.psk);
    auto b = HandshakeState::responder(Pattern::NNpsk0, prologue, &tk2.psk);

    std::vector<uint8_t> msg1(256), pay(256);
    auto n1 = a.write_message({}, msg1);
    REQUIRE(n1.has_value());
    // Responder must reject, and the caller must treat this as "drop silently".
    CHECK(!b.read_message(std::span(msg1).first(*n1), pay).has_value());
}

TEST(nnpsk0_fails_when_the_prologue_differs) {
    // The prologue carries topic_id, key_epoch and probe_txn. A mismatch on any
    // of them must fail cryptographically rather than relying on a check
    // someone remembered to write.
    Key k{};
    random_bytes(k);
    auto tk = TopicKeys::derive(k);

    std::vector<uint8_t> p1{'t', 'o', 'p', 'i', 'c', 'A'};
    std::vector<uint8_t> p2{'t', 'o', 'p', 'i', 'c', 'B'};
    auto a = HandshakeState::initiator(Pattern::NNpsk0, p1, &tk.psk);
    auto b = HandshakeState::responder(Pattern::NNpsk0, p2, &tk.psk);

    std::vector<uint8_t> msg1(256), pay(256);
    auto n1 = a.write_message({}, msg1);
    REQUIRE(n1.has_value());
    CHECK(!b.read_message(std::span(msg1).first(*n1), pay).has_value());
}

TEST(nnpsk0_rejects_a_tampered_first_message) {
    Key k{};
    random_bytes(k);
    auto tk = TopicKeys::derive(k);
    std::vector<uint8_t> prologue{'x'};

    for (size_t flip = 0; flip < 48; ++flip) {
        auto a = HandshakeState::initiator(Pattern::NNpsk0, prologue, &tk.psk);
        auto b = HandshakeState::responder(Pattern::NNpsk0, prologue, &tk.psk);

        std::vector<uint8_t> msg1(256), pay(256);
        auto n1 = a.write_message({}, msg1);
        REQUIRE(n1.has_value());
        if (flip >= *n1) break;
        msg1[flip] ^= 0x01;
        if (b.read_message(std::span(msg1).first(*n1), pay).has_value()) {
            ::testing::fail(__FILE__, __LINE__,
                            "tampered byte " + std::to_string(flip) + " was accepted");
        }
    }
}

TEST(nn_open_handshake_succeeds_without_a_psk) {
    std::vector<uint8_t> prologue{'o', 'p', 'e', 'n'};
    auto a = HandshakeState::initiator(Pattern::NN, prologue, nullptr);
    auto b = HandshakeState::responder(Pattern::NN, prologue, nullptr);

    Split sa, sb;
    REQUIRE(run_handshake(a, b, sa, sb));
    CHECK(sa.handshake_hash == sb.handshake_hash);

    std::vector<uint8_t> pt{'h', 'i'};
    std::vector<uint8_t> ct(pt.size() + kTagLen);
    sa.send.encrypt_with_ad({}, pt, ct);
    std::vector<uint8_t> out(pt.size());
    REQUIRE(sb.recv.decrypt_with_ad({}, ct, out).has_value());
    CHECK(out == pt);
}

TEST(nn_and_nnpsk0_are_not_interoperable) {
    // A client configured with K must fail closed against an open responder.
    // Silent downgrade is how sound protocols get broken.
    Key k{};
    random_bytes(k);
    auto tk = TopicKeys::derive(k);
    std::vector<uint8_t> prologue{'p'};

    auto a = HandshakeState::initiator(Pattern::NNpsk0, prologue, &tk.psk);
    auto b = HandshakeState::responder(Pattern::NN, prologue, nullptr);

    std::vector<uint8_t> msg1(256), pay(256);
    auto n1 = a.write_message({}, msg1);
    REQUIRE(n1.has_value());
    auto r = b.read_message(std::span(msg1).first(*n1), pay);
    // NN's reader would consume a 32-byte ephemeral and then treat the rest as
    // an unencrypted payload, so it may not error -- but the handshake hashes
    // must diverge, so no shared key can result.
    if (r.has_value()) {
        auto n2 = b.write_message({}, msg1);
        REQUIRE(n2.has_value());
        CHECK(!a.read_message(std::span(msg1).first(*n2), pay).has_value());
    }
}

TEST(handshake_message_sizes_match_the_documented_overhead) {
    Key k{};
    random_bytes(k);
    auto tk = TopicKeys::derive(k);
    std::vector<uint8_t> prologue{'p'};

    auto a = HandshakeState::initiator(Pattern::NNpsk0, prologue, &tk.psk);
    auto b = HandshakeState::responder(Pattern::NNpsk0, prologue, &tk.psk);

    std::vector<uint8_t> padding(32, 0);
    random_bytes(padding);
    std::vector<uint8_t> msg1(256), msg2(256), pay(256);

    auto n1 = a.write_message(padding, msg1);
    REQUIRE(n1.has_value());
    CHECK_EQ(*n1, 32u + 32u + 16u);  // e.pub + padding + tag = 80 bytes

    REQUIRE(b.read_message(std::span(msg1).first(*n1), pay).has_value());
    auto n2 = b.write_message({}, msg2);
    REQUIRE(n2.has_value());
    CHECK_EQ(*n2, 32u + 16u);  // e.pub + tag = 48 bytes
}

TEST(cipherstate_nonce_does_not_advance_on_failed_decrypt) {
    // A forged packet must not be able to desynchronise the stream.
    SymKey key{};
    random_bytes(key);
    CipherState cs{key};
    CipherState rx{key};

    std::vector<uint8_t> pt{'a', 'b', 'c'};
    std::vector<uint8_t> ct(pt.size() + kTagLen);
    cs.encrypt_with_ad({}, pt, ct);

    auto forged = ct;
    forged[0] ^= 0xFF;
    std::vector<uint8_t> out(pt.size());
    CHECK(!rx.decrypt_with_ad({}, forged, out).has_value());
    CHECK(rx.nonce() == 0u);  // still expecting message 0

    // The genuine packet still decrypts.
    REQUIRE(rx.decrypt_with_ad({}, ct, out).has_value());
    CHECK(out == pt);
    CHECK(rx.nonce() == 1u);
}

TEST(cipherstate_rekey_changes_the_key_deterministically) {
    SymKey key{};
    random_bytes(key);
    CipherState a{key}, b{key};
    a.rekey();
    b.rekey();

    std::vector<uint8_t> pt{'x'};
    std::vector<uint8_t> ct(pt.size() + kTagLen);
    a.encrypt_with_ad({}, pt, ct);
    std::vector<uint8_t> out(pt.size());
    CHECK(b.decrypt_with_ad({}, ct, out).has_value());

    // A peer that did not rekey can no longer read.
    CipherState stale{key};
    CHECK(!stale.decrypt_with_ad({}, ct, out).has_value());
}

// ---------------------------------------------------------------------------
// SAS
// ---------------------------------------------------------------------------
TEST(sas_differs_for_different_handshakes_and_matches_for_the_same) {
    Hash h1{}, h2{};
    random_bytes(h1);
    h2 = h1;
    CHECK(sas_string(h1) == sas_string(h2));

    random_bytes(h2);
    CHECK(sas_string(h1) != sas_string(h2));

    // Four hyphen-separated words.
    auto s = sas_string(h1);
    int dashes = 0;
    for (char c : s) {
        if (c == '-') ++dashes;
    }
    CHECK_EQ(dashes, 3);
}
