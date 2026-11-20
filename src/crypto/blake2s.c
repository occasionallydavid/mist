#include "crypto.h"

#include <string.h>

static const uint32_t iv[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static const uint8_t sigma[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}
};

static uint32_t rotate_right(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32 - n));
}

static void mix(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d,
                uint32_t x, uint32_t y)
{
    *a += *b + x;
    *d = rotate_right(*d ^ *a, 16);
    *c += *d;
    *b = rotate_right(*b ^ *c, 12);
    *a += *b + y;
    *d = rotate_right(*d ^ *a, 8);
    *c += *d;
    *b = rotate_right(*b ^ *c, 7);
}

static void compress(uint32_t h[8], const uint8_t block[64], uint64_t count,
                     int last)
{
    uint32_t m[16], v[16];
    for (unsigned i = 0; i < 16; ++i) {
        const uint8_t *p = block + 4 * i;
        m[i] = (uint32_t)p[0] | (uint32_t)p[1] << 8 |
               (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
    }
    memcpy(v, h, 8 * sizeof *h);
    memcpy(v + 8, iv, sizeof iv);
    v[12] ^= (uint32_t)count;
    v[13] ^= (uint32_t)(count >> 32);
    if (last)
        v[14] = ~v[14];

    for (unsigned i = 0; i < 10; ++i) {
        const uint8_t *s = sigma[i];
#define G(a, b, c, d, j) mix(v + a, v + b, v + c, v + d, m[s[j]], m[s[(j) + 1]])
        G(0, 4, 8, 12, 0);
        G(1, 5, 9, 13, 2);
        G(2, 6, 10, 14, 4);
        G(3, 7, 11, 15, 6);
        G(0, 5, 10, 15, 8);
        G(1, 6, 11, 12, 10);
        G(2, 7, 8, 13, 12);
        G(3, 4, 9, 14, 14);
#undef G
    }
    for (unsigned i = 0; i < 8; ++i)
        h[i] ^= v[i] ^ v[i + 8];
    mist_wipe(m, sizeof m);
    mist_wipe(v, sizeof v);
}

void mist_blake2s(uint8_t out[32], const uint8_t *in, size_t n)
{
    uint32_t h[8];
    uint8_t last[64] = {0};
    uint64_t count = n;
    memcpy(h, iv, sizeof h);
    h[0] ^= UINT32_C(0x01010020);
    while (n > sizeof last) {
        compress(h, in, count - n + sizeof last, 0);
        in += sizeof last;
        n -= sizeof last;
    }
    if (n)
        memcpy(last, in, n);
    compress(h, last, count, 1);
    for (unsigned i = 0; i < 32; ++i)
        out[i] = (uint8_t)(h[i / 4] >> (8 * (i % 4)));
    mist_wipe(last, sizeof last);
    mist_wipe(h, sizeof h);
}
