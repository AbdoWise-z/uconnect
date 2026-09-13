/* poly1305-donna-32 (public domain, Andrew Moon). See poly1305.h. */

#include "poly1305.h"

#include <string.h>

static uint32_t u8to32(const uint8_t *p) {
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void u32to8(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

void uconnect_poly1305_init(uconnect_poly1305_ctx *st, const uint8_t key[32]) {
    /* r &= 0xffffffc0ffffffc0ffffffc0fffffff, split into 5 x 26-bit limbs */
    st->r[0] = (u8to32(&key[0])) & 0x3ffffff;
    st->r[1] = (u8to32(&key[3]) >> 2) & 0x3ffff03;
    st->r[2] = (u8to32(&key[6]) >> 4) & 0x3ffc0ff;
    st->r[3] = (u8to32(&key[9]) >> 6) & 0x3f03fff;
    st->r[4] = (u8to32(&key[12]) >> 8) & 0x00fffff;

    st->h[0] = st->h[1] = st->h[2] = st->h[3] = st->h[4] = 0;

    st->pad[0] = u8to32(&key[16]);
    st->pad[1] = u8to32(&key[20]);
    st->pad[2] = u8to32(&key[24]);
    st->pad[3] = u8to32(&key[28]);

    st->leftover = 0;
    st->final    = 0;
}

static void poly1305_blocks(uconnect_poly1305_ctx *st, const uint8_t *m, size_t bytes) {
    const uint32_t hibit = st->final ? 0 : (1UL << 24); /* 1 << 128 */
    uint32_t       r0, r1, r2, r3, r4;
    uint32_t       s1, s2, s3, s4;
    uint32_t       h0, h1, h2, h3, h4;
    uint64_t       d0, d1, d2, d3, d4;
    uint32_t       c;

    r0 = st->r[0];
    r1 = st->r[1];
    r2 = st->r[2];
    r3 = st->r[3];
    r4 = st->r[4];

    s1 = r1 * 5;
    s2 = r2 * 5;
    s3 = r3 * 5;
    s4 = r4 * 5;

    h0 = st->h[0];
    h1 = st->h[1];
    h2 = st->h[2];
    h3 = st->h[3];
    h4 = st->h[4];

    while (bytes >= 16) {
        /* h += m[i] */
        h0 += (u8to32(m + 0)) & 0x3ffffff;
        h1 += (u8to32(m + 3) >> 2) & 0x3ffffff;
        h2 += (u8to32(m + 6) >> 4) & 0x3ffffff;
        h3 += (u8to32(m + 9) >> 6) & 0x3ffffff;
        h4 += (u8to32(m + 12) >> 8) | hibit;

        /* h *= r */
        d0 = ((uint64_t)h0 * r0) + ((uint64_t)h1 * s4) + ((uint64_t)h2 * s3) +
             ((uint64_t)h3 * s2) + ((uint64_t)h4 * s1);
        d1 = ((uint64_t)h0 * r1) + ((uint64_t)h1 * r0) + ((uint64_t)h2 * s4) +
             ((uint64_t)h3 * s3) + ((uint64_t)h4 * s2);
        d2 = ((uint64_t)h0 * r2) + ((uint64_t)h1 * r1) + ((uint64_t)h2 * r0) +
             ((uint64_t)h3 * s4) + ((uint64_t)h4 * s3);
        d3 = ((uint64_t)h0 * r3) + ((uint64_t)h1 * r2) + ((uint64_t)h2 * r1) +
             ((uint64_t)h3 * r0) + ((uint64_t)h4 * s4);
        d4 = ((uint64_t)h0 * r4) + ((uint64_t)h1 * r3) + ((uint64_t)h2 * r2) +
             ((uint64_t)h3 * r1) + ((uint64_t)h4 * r0);

        /* (partial) h %= p */
        c  = (uint32_t)(d0 >> 26);
        h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c;
        c  = (uint32_t)(d1 >> 26);
        h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c;
        c  = (uint32_t)(d2 >> 26);
        h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c;
        c  = (uint32_t)(d3 >> 26);
        h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c;
        c  = (uint32_t)(d4 >> 26);
        h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5;
        c  = (h0 >> 26);
        h0 = h0 & 0x3ffffff;
        h1 += c;

        m += 16;
        bytes -= 16;
    }

    st->h[0] = h0;
    st->h[1] = h1;
    st->h[2] = h2;
    st->h[3] = h3;
    st->h[4] = h4;
}

void uconnect_poly1305_update(uconnect_poly1305_ctx *st, const uint8_t *m, size_t bytes) {
    size_t i;

    if (st->leftover) {
        size_t want = 16 - st->leftover;
        if (want > bytes) want = bytes;
        for (i = 0; i < want; ++i) st->buffer[st->leftover + i] = m[i];
        bytes -= want;
        m += want;
        st->leftover += want;
        if (st->leftover < 16) return;
        poly1305_blocks(st, st->buffer, 16);
        st->leftover = 0;
    }

    if (bytes >= 16) {
        size_t want = (bytes & ~((size_t)15));
        poly1305_blocks(st, m, want);
        m += want;
        bytes -= want;
    }

    if (bytes) {
        for (i = 0; i < bytes; ++i) st->buffer[st->leftover + i] = m[i];
        st->leftover += bytes;
    }
}

void uconnect_poly1305_finish(uconnect_poly1305_ctx *st, uint8_t mac[16]) {
    uint32_t h0, h1, h2, h3, h4, c;
    uint32_t g0, g1, g2, g3, g4;
    uint64_t f;
    uint32_t mask;

    if (st->leftover) {
        size_t i = st->leftover;
        st->buffer[i++] = 1;
        for (; i < 16; ++i) st->buffer[i] = 0;
        st->final = 1;
        poly1305_blocks(st, st->buffer, 16);
    }

    h0 = st->h[0];
    h1 = st->h[1];
    h2 = st->h[2];
    h3 = st->h[3];
    h4 = st->h[4];

    c  = h1 >> 26;
    h1 = h1 & 0x3ffffff;
    h2 += c;
    c  = h2 >> 26;
    h2 = h2 & 0x3ffffff;
    h3 += c;
    c  = h3 >> 26;
    h3 = h3 & 0x3ffffff;
    h4 += c;
    c  = h4 >> 26;
    h4 = h4 & 0x3ffffff;
    h0 += c * 5;
    c  = h0 >> 26;
    h0 = h0 & 0x3ffffff;
    h1 += c;

    /* compute h + -p */
    g0 = h0 + 5;
    c  = g0 >> 26;
    g0 &= 0x3ffffff;
    g1 = h1 + c;
    c  = g1 >> 26;
    g1 &= 0x3ffffff;
    g2 = h2 + c;
    c  = g2 >> 26;
    g2 &= 0x3ffffff;
    g3 = h3 + c;
    c  = g3 >> 26;
    g3 &= 0x3ffffff;
    g4 = h4 + c - (1UL << 26);

    /* select h if h < p, or h + -p if h >= p -- branchless */
    mask = (g4 >> 31) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    h0   = (h0 & mask) | g0;
    h1   = (h1 & mask) | g1;
    h2   = (h2 & mask) | g2;
    h3   = (h3 & mask) | g3;
    h4   = (h4 & mask) | g4;

    /* h = h % (2^128) */
    h0 = ((h0) | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

    /* mac = (h + pad) % (2^128) */
    f  = (uint64_t)h0 + st->pad[0];
    h0 = (uint32_t)f;
    f  = (uint64_t)h1 + st->pad[1] + (f >> 32);
    h1 = (uint32_t)f;
    f  = (uint64_t)h2 + st->pad[2] + (f >> 32);
    h2 = (uint32_t)f;
    f  = (uint64_t)h3 + st->pad[3] + (f >> 32);
    h3 = (uint32_t)f;

    u32to8(mac + 0, h0);
    u32to8(mac + 4, h1);
    u32to8(mac + 8, h2);
    u32to8(mac + 12, h3);

    memset((void *)st, 0, sizeof(*st));
}
