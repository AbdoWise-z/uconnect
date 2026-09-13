#ifndef UCONNECT_POLY1305_H
#define UCONNECT_POLY1305_H

// Poly1305 (RFC 8439), the 32-bit "donna" variant by Andrew Moon.
// Public domain: https://github.com/floodyberry/poly1305-donna
//
// Vendored for the same reason as X25519: the 130-bit modular arithmetic here
// uses 5 x 26-bit limbs with hand-managed carries, and an error produces a tag
// that looks fine until an attacker forges one. Verified against the RFC 8439
// vectors in tests/test_crypto.cpp.

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    size_t   leftover;
    uint8_t  buffer[16];
    uint8_t  final;
} uconnect_poly1305_ctx;

void uconnect_poly1305_init(uconnect_poly1305_ctx *st, const uint8_t key[32]);
void uconnect_poly1305_update(uconnect_poly1305_ctx *st, const uint8_t *m, size_t bytes);
void uconnect_poly1305_finish(uconnect_poly1305_ctx *st, uint8_t mac[16]);

#ifdef __cplusplus
}
#endif

#endif /* UCONNECT_POLY1305_H */
