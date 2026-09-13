#ifndef UCONNECT_X25519_H
#define UCONNECT_X25519_H

// X25519 (RFC 7748) scalar multiplication, adapted from TweetNaCl.
//
// TweetNaCl is public domain, by Daniel J. Bernstein, Bernard van Gastel,
// Wesley Janssen, Tanja Lange, Peter Schwabe and Sjaak Smetsers.
// https://tweetnacl.cr.yp.to/
//
// This is vendored rather than hand-written on purpose. Curve arithmetic is
// exactly the kind of code that is easy to get subtly, silently wrong, and a
// wrong X25519 still produces plausible-looking 32-byte outputs. Correctness
// here is established by the RFC 7748 test vectors in tests/test_crypto.cpp.
//
// The Montgomery ladder below is constant-time with respect to the scalar:
// sel25519 does a branchless conditional swap, and every iteration performs the
// same operations regardless of the bit.

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UCONNECT_X25519_LEN 32

/* q = n * p. Returns 0. */
int uconnect_x25519(uint8_t q[32], const uint8_t n[32], const uint8_t p[32]);

/* q = n * basepoint(9). Derives a public key from a secret scalar. */
int uconnect_x25519_base(uint8_t q[32], const uint8_t n[32]);

#ifdef __cplusplus
}
#endif

#endif /* UCONNECT_X25519_H */
