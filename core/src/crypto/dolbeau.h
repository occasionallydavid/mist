/*
 * ISC License
 *
 * Copyright (c) 2013-2024
 * Frank Denis <j at pureftpd dot org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* ChaCha20 SIMD kernel credited upstream to Romain Dolbeau and
 * Daniel J. Bernstein.
 *
 * libsodium 1.0.20, commit 9511c982fb1d046470a8b42aa36556cdb7da15de
 * https://github.com/jedisct1/libsodium/tree/9511c982fb1d046470a8b42aa36556cdb7da15de/src/libsodium/crypto_stream/chacha20/dolbeau
 *
 * u0.h, u1.h, and u4.h come from the Dolbeau SSSE3 implementation. The
 * intrinsics map to SIMDe's Wasm SIMD128 operations. The fixed byte masks
 * are expressed as immediate shuffles. The integration removes the explicit
 * wipe of the partial block.
 */

#ifndef MIST_CRYPTO_DOLBEAU_H
#define MIST_CRYPTO_DOLBEAU_H

#include <stddef.h>
#include <stdint.h>
#include <simde/wasm/simd128.h>

#if SIMDE_ENDIAN_ORDER != SIMDE_ENDIAN_LITTLE
#error "The Dolbeau ChaCha20 kernel requires little-endian vectors"
#endif

#define DOLBEAU_ROUNDS 20
#define DOLBEAU_SHUFFLE32(v, imm) simde_wasm_i32x4_shuffle((v), (v), \
    (imm) & 3, ((imm) >> 2) & 3, ((imm) >> 4) & 3, (imm) >> 6)
#define DOLBEAU_UNPACKLO32(a, b) simde_wasm_i32x4_shuffle((a), (b), 0, 4, 1, 5)
#define DOLBEAU_UNPACKHI32(a, b) simde_wasm_i32x4_shuffle((a), (b), 2, 6, 3, 7)
#define DOLBEAU_UNPACKLO64(a, b) simde_wasm_i64x2_shuffle((a), (b), 0, 2)
#define DOLBEAU_UNPACKHI64(a, b) simde_wasm_i64x2_shuffle((a), (b), 1, 3)
#define DOLBEAU_ROT16(v) simde_wasm_i8x16_shuffle((v), (v), \
    2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13)
#define DOLBEAU_ROT8(v) simde_wasm_i8x16_shuffle((v), (v), \
    3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14)

static void chacha20_dolbeau(uint32_t x[16], const uint8_t *m, uint8_t *c, size_t bytes)
{
#define VEC4_ROT(A, IMM) \
        simde_wasm_v128_or(simde_wasm_i32x4_shl(A, IMM), simde_wasm_u32x4_shr(A, (32 - IMM)))

    /* same, but replace 2 of the shift/shift/or "rotation" by byte shuffles (8 &
     * 16) (better) */
#define VEC4_QUARTERROUND_SHUFFLE(A, B, C, D) \
        x_##A = simde_wasm_i32x4_add(x_##A, x_##B);      \
        t_##A = simde_wasm_v128_xor(x_##D, x_##A);      \
        x_##D = DOLBEAU_ROT16(t_##A);   \
        x_##C = simde_wasm_i32x4_add(x_##C, x_##D);      \
        t_##C = simde_wasm_v128_xor(x_##B, x_##C);      \
        x_##B = VEC4_ROT(t_##C, 12);              \
        x_##A = simde_wasm_i32x4_add(x_##A, x_##B);      \
        t_##A = simde_wasm_v128_xor(x_##D, x_##A);      \
        x_##D = DOLBEAU_ROT8(t_##A);    \
        x_##C = simde_wasm_i32x4_add(x_##C, x_##D);      \
        t_##C = simde_wasm_v128_xor(x_##B, x_##C);      \
        x_##B = VEC4_ROT(t_##C, 7)

#define VEC4_QUARTERROUND(A, B, C, D) VEC4_QUARTERROUND_SHUFFLE(A, B, C, D)

    if (bytes >= 256) {

        simde_v128_t x_0  = simde_wasm_u32x4_splat(x[0]);
        simde_v128_t x_1  = simde_wasm_u32x4_splat(x[1]);
        simde_v128_t x_2  = simde_wasm_u32x4_splat(x[2]);
        simde_v128_t x_3  = simde_wasm_u32x4_splat(x[3]);
        simde_v128_t x_4  = simde_wasm_u32x4_splat(x[4]);
        simde_v128_t x_5  = simde_wasm_u32x4_splat(x[5]);
        simde_v128_t x_6  = simde_wasm_u32x4_splat(x[6]);
        simde_v128_t x_7  = simde_wasm_u32x4_splat(x[7]);
        simde_v128_t x_8  = simde_wasm_u32x4_splat(x[8]);
        simde_v128_t x_9  = simde_wasm_u32x4_splat(x[9]);
        simde_v128_t x_10 = simde_wasm_u32x4_splat(x[10]);
        simde_v128_t x_11 = simde_wasm_u32x4_splat(x[11]);
        simde_v128_t x_12;
        simde_v128_t x_13;
        simde_v128_t x_14   = simde_wasm_u32x4_splat(x[14]);
        simde_v128_t x_15   = simde_wasm_u32x4_splat(x[15]);
        simde_v128_t orig0  = x_0;
        simde_v128_t orig1  = x_1;
        simde_v128_t orig2  = x_2;
        simde_v128_t orig3  = x_3;
        simde_v128_t orig4  = x_4;
        simde_v128_t orig5  = x_5;
        simde_v128_t orig6  = x_6;
        simde_v128_t orig7  = x_7;
        simde_v128_t orig8  = x_8;
        simde_v128_t orig9  = x_9;
        simde_v128_t orig10 = x_10;
        simde_v128_t orig11 = x_11;
        simde_v128_t orig12;
        simde_v128_t orig13;
        simde_v128_t orig14 = x_14;
        simde_v128_t orig15 = x_15;
        simde_v128_t t_0, t_1, t_2, t_3, t_4, t_5, t_6, t_7, t_8, t_9, t_10, t_11, t_12,
            t_13, t_14, t_15;

        uint32_t in12, in13;
        int      i;

        while (bytes >= 256) {
            const simde_v128_t addv12 = simde_wasm_u64x2_make(0, 1);
            const simde_v128_t addv13 = simde_wasm_u64x2_make(2, 3);
            simde_v128_t       t12, t13;
            uint64_t      in1213;

            x_0  = orig0;
            x_1  = orig1;
            x_2  = orig2;
            x_3  = orig3;
            x_4  = orig4;
            x_5  = orig5;
            x_6  = orig6;
            x_7  = orig7;
            x_8  = orig8;
            x_9  = orig9;
            x_10 = orig10;
            x_11 = orig11;
            x_14 = orig14;
            x_15 = orig15;

            in12   = x[12];
            in13   = x[13];
            in1213 = ((uint64_t) in12) | (((uint64_t) in13) << 32);
            t12    = simde_wasm_u64x2_splat(in1213);
            t13    = simde_wasm_u64x2_splat(in1213);

            x_12 = simde_wasm_i64x2_add(addv12, t12);
            x_13 = simde_wasm_i64x2_add(addv13, t13);

            t12 = DOLBEAU_UNPACKLO32(x_12, x_13);
            t13 = DOLBEAU_UNPACKHI32(x_12, x_13);

            x_12 = DOLBEAU_UNPACKLO32(t12, t13);
            x_13 = DOLBEAU_UNPACKHI32(t12, t13);

            orig12 = x_12;
            orig13 = x_13;

            in1213 += 4;

            x[12] = in1213 & 0xFFFFFFFF;
            x[13] = (in1213 >> 32) & 0xFFFFFFFF;

            for (i = 0; i < DOLBEAU_ROUNDS; i += 2) {
                VEC4_QUARTERROUND(0, 4, 8, 12);
                VEC4_QUARTERROUND(1, 5, 9, 13);
                VEC4_QUARTERROUND(2, 6, 10, 14);
                VEC4_QUARTERROUND(3, 7, 11, 15);
                VEC4_QUARTERROUND(0, 5, 10, 15);
                VEC4_QUARTERROUND(1, 6, 11, 12);
                VEC4_QUARTERROUND(2, 7, 8, 13);
                VEC4_QUARTERROUND(3, 4, 9, 14);
            }

#define ONEQUAD_TRANSPOSE(A, B, C, D)                                          \
        {                                                                          \
            simde_v128_t t0, t1, t2, t3;                                                \
                                                                                   \
            x_##A = simde_wasm_i32x4_add(x_##A, orig##A);                                 \
            x_##B = simde_wasm_i32x4_add(x_##B, orig##B);                                 \
            x_##C = simde_wasm_i32x4_add(x_##C, orig##C);                                 \
            x_##D = simde_wasm_i32x4_add(x_##D, orig##D);                                 \
            t_##A = DOLBEAU_UNPACKLO32(x_##A, x_##B);                              \
            t_##B = DOLBEAU_UNPACKLO32(x_##C, x_##D);                              \
            t_##C = DOLBEAU_UNPACKHI32(x_##A, x_##B);                              \
            t_##D = DOLBEAU_UNPACKHI32(x_##C, x_##D);                              \
            x_##A = DOLBEAU_UNPACKLO64(t_##A, t_##B);                              \
            x_##B = DOLBEAU_UNPACKHI64(t_##A, t_##B);                              \
            x_##C = DOLBEAU_UNPACKLO64(t_##C, t_##D);                              \
            x_##D = DOLBEAU_UNPACKHI64(t_##C, t_##D);                              \
                                                                                   \
            t0 = simde_wasm_v128_xor(x_##A, simde_wasm_v128_load((m + 0)));  \
            simde_wasm_v128_store((c + 0), t0);                              \
            t1 = simde_wasm_v128_xor(x_##B, simde_wasm_v128_load((m + 64))); \
            simde_wasm_v128_store((c + 64), t1);                             \
            t2 =                                                                   \
                simde_wasm_v128_xor(x_##C, simde_wasm_v128_load((m + 128))); \
            simde_wasm_v128_store((c + 128), t2);                            \
            t3 =                                                                   \
                simde_wasm_v128_xor(x_##D, simde_wasm_v128_load((m + 192))); \
            simde_wasm_v128_store((c + 192), t3);                            \
        }

#define ONEQUAD(A, B, C, D) ONEQUAD_TRANSPOSE(A, B, C, D)

            ONEQUAD(0, 1, 2, 3);
            m += 16;
            c += 16;
            ONEQUAD(4, 5, 6, 7);
            m += 16;
            c += 16;
            ONEQUAD(8, 9, 10, 11);
            m += 16;
            c += 16;
            ONEQUAD(12, 13, 14, 15);
            m -= 48;
            c -= 48;

#undef ONEQUAD
#undef ONEQUAD_TRANSPOSE

            bytes -= 256;
            c += 256;
            m += 256;
        }
    }
#undef VEC4_ROT
#undef VEC4_QUARTERROUND
#undef VEC4_QUARTERROUND_SHUFFLE

    while (bytes >= 64) {
        simde_v128_t       x_0, x_1, x_2, x_3;
        simde_v128_t       t_1;

        uint32_t in12;
        uint32_t in13;
        int      i;

        x_0 = simde_wasm_v128_load((x + 0));
        x_1 = simde_wasm_v128_load((x + 4));
        x_2 = simde_wasm_v128_load((x + 8));
        x_3 = simde_wasm_v128_load((x + 12));

        for (i = 0; i < DOLBEAU_ROUNDS; i += 2) {
            x_0 = simde_wasm_i32x4_add(x_0, x_1);
            x_3 = simde_wasm_v128_xor(x_3, x_0);
            x_3 = DOLBEAU_ROT16(x_3);

            x_2 = simde_wasm_i32x4_add(x_2, x_3);
            x_1 = simde_wasm_v128_xor(x_1, x_2);

            t_1 = x_1;
            x_1 = simde_wasm_i32x4_shl(x_1, 12);
            t_1 = simde_wasm_u32x4_shr(t_1, 20);
            x_1 = simde_wasm_v128_xor(x_1, t_1);

            x_0 = simde_wasm_i32x4_add(x_0, x_1);
            x_3 = simde_wasm_v128_xor(x_3, x_0);
            x_0 = DOLBEAU_SHUFFLE32(x_0, 0x93);
            x_3 = DOLBEAU_ROT8(x_3);

            x_2 = simde_wasm_i32x4_add(x_2, x_3);
            x_3 = DOLBEAU_SHUFFLE32(x_3, 0x4e);
            x_1 = simde_wasm_v128_xor(x_1, x_2);
            x_2 = DOLBEAU_SHUFFLE32(x_2, 0x39);

            t_1 = x_1;
            x_1 = simde_wasm_i32x4_shl(x_1, 7);
            t_1 = simde_wasm_u32x4_shr(t_1, 25);
            x_1 = simde_wasm_v128_xor(x_1, t_1);

            x_0 = simde_wasm_i32x4_add(x_0, x_1);
            x_3 = simde_wasm_v128_xor(x_3, x_0);
            x_3 = DOLBEAU_ROT16(x_3);

            x_2 = simde_wasm_i32x4_add(x_2, x_3);
            x_1 = simde_wasm_v128_xor(x_1, x_2);

            t_1 = x_1;
            x_1 = simde_wasm_i32x4_shl(x_1, 12);
            t_1 = simde_wasm_u32x4_shr(t_1, 20);
            x_1 = simde_wasm_v128_xor(x_1, t_1);

            x_0 = simde_wasm_i32x4_add(x_0, x_1);
            x_3 = simde_wasm_v128_xor(x_3, x_0);
            x_0 = DOLBEAU_SHUFFLE32(x_0, 0x39);
            x_3 = DOLBEAU_ROT8(x_3);

            x_2 = simde_wasm_i32x4_add(x_2, x_3);
            x_3 = DOLBEAU_SHUFFLE32(x_3, 0x4e);
            x_1 = simde_wasm_v128_xor(x_1, x_2);
            x_2 = DOLBEAU_SHUFFLE32(x_2, 0x93);

            t_1 = x_1;
            x_1 = simde_wasm_i32x4_shl(x_1, 7);
            t_1 = simde_wasm_u32x4_shr(t_1, 25);
            x_1 = simde_wasm_v128_xor(x_1, t_1);
        }
        x_0 = simde_wasm_i32x4_add(x_0, simde_wasm_v128_load((x + 0)));
        x_1 = simde_wasm_i32x4_add(x_1, simde_wasm_v128_load((x + 4)));
        x_2 = simde_wasm_i32x4_add(x_2, simde_wasm_v128_load((x + 8)));
        x_3 = simde_wasm_i32x4_add(x_3, simde_wasm_v128_load((x + 12)));
        x_0 = simde_wasm_v128_xor(x_0, simde_wasm_v128_load((m + 0)));
        x_1 = simde_wasm_v128_xor(x_1, simde_wasm_v128_load((m + 16)));
        x_2 = simde_wasm_v128_xor(x_2, simde_wasm_v128_load((m + 32)));
        x_3 = simde_wasm_v128_xor(x_3, simde_wasm_v128_load((m + 48)));
        simde_wasm_v128_store((c + 0), x_0);
        simde_wasm_v128_store((c + 16), x_1);
        simde_wasm_v128_store((c + 32), x_2);
        simde_wasm_v128_store((c + 48), x_3);

        in12 = x[12];
        in13 = x[13];
        in12++;
        if (in12 == 0) {
            in13++;
        }
        x[12] = in12;
        x[13] = in13;

        bytes -= 64;
        c += 64;
        m += 64;
    }

    if (bytes > 0) {
        simde_v128_t       x_0, x_1, x_2, x_3;
        simde_v128_t       t_1;
        uint8_t partialblock[64];

        unsigned int i;

        x_0 = simde_wasm_v128_load((x + 0));
        x_1 = simde_wasm_v128_load((x + 4));
        x_2 = simde_wasm_v128_load((x + 8));
        x_3 = simde_wasm_v128_load((x + 12));

        for (i = 0; i < DOLBEAU_ROUNDS; i += 2) {
            x_0 = simde_wasm_i32x4_add(x_0, x_1);
            x_3 = simde_wasm_v128_xor(x_3, x_0);
            x_3 = DOLBEAU_ROT16(x_3);

            x_2 = simde_wasm_i32x4_add(x_2, x_3);
            x_1 = simde_wasm_v128_xor(x_1, x_2);

            t_1 = x_1;
            x_1 = simde_wasm_i32x4_shl(x_1, 12);
            t_1 = simde_wasm_u32x4_shr(t_1, 20);
            x_1 = simde_wasm_v128_xor(x_1, t_1);

            x_0 = simde_wasm_i32x4_add(x_0, x_1);
            x_3 = simde_wasm_v128_xor(x_3, x_0);
            x_0 = DOLBEAU_SHUFFLE32(x_0, 0x93);
            x_3 = DOLBEAU_ROT8(x_3);

            x_2 = simde_wasm_i32x4_add(x_2, x_3);
            x_3 = DOLBEAU_SHUFFLE32(x_3, 0x4e);
            x_1 = simde_wasm_v128_xor(x_1, x_2);
            x_2 = DOLBEAU_SHUFFLE32(x_2, 0x39);

            t_1 = x_1;
            x_1 = simde_wasm_i32x4_shl(x_1, 7);
            t_1 = simde_wasm_u32x4_shr(t_1, 25);
            x_1 = simde_wasm_v128_xor(x_1, t_1);

            x_0 = simde_wasm_i32x4_add(x_0, x_1);
            x_3 = simde_wasm_v128_xor(x_3, x_0);
            x_3 = DOLBEAU_ROT16(x_3);

            x_2 = simde_wasm_i32x4_add(x_2, x_3);
            x_1 = simde_wasm_v128_xor(x_1, x_2);

            t_1 = x_1;
            x_1 = simde_wasm_i32x4_shl(x_1, 12);
            t_1 = simde_wasm_u32x4_shr(t_1, 20);
            x_1 = simde_wasm_v128_xor(x_1, t_1);

            x_0 = simde_wasm_i32x4_add(x_0, x_1);
            x_3 = simde_wasm_v128_xor(x_3, x_0);
            x_0 = DOLBEAU_SHUFFLE32(x_0, 0x39);
            x_3 = DOLBEAU_ROT8(x_3);

            x_2 = simde_wasm_i32x4_add(x_2, x_3);
            x_3 = DOLBEAU_SHUFFLE32(x_3, 0x4e);
            x_1 = simde_wasm_v128_xor(x_1, x_2);
            x_2 = DOLBEAU_SHUFFLE32(x_2, 0x93);

            t_1 = x_1;
            x_1 = simde_wasm_i32x4_shl(x_1, 7);
            t_1 = simde_wasm_u32x4_shr(t_1, 25);
            x_1 = simde_wasm_v128_xor(x_1, t_1);
        }
        x_0 = simde_wasm_i32x4_add(x_0, simde_wasm_v128_load((x + 0)));
        x_1 = simde_wasm_i32x4_add(x_1, simde_wasm_v128_load((x + 4)));
        x_2 = simde_wasm_i32x4_add(x_2, simde_wasm_v128_load((x + 8)));
        x_3 = simde_wasm_i32x4_add(x_3, simde_wasm_v128_load((x + 12)));
        simde_wasm_v128_store((partialblock + 0), x_0);
        simde_wasm_v128_store((partialblock + 16), x_1);
        simde_wasm_v128_store((partialblock + 32), x_2);
        simde_wasm_v128_store((partialblock + 48), x_3);

        for (i = 0; i < bytes; i++) {
            c[i] = m[i] ^ partialblock[i];
        }

    }

}

#undef DOLBEAU_ROT8
#undef DOLBEAU_ROT16
#undef DOLBEAU_UNPACKHI64
#undef DOLBEAU_UNPACKLO64
#undef DOLBEAU_UNPACKHI32
#undef DOLBEAU_UNPACKLO32
#undef DOLBEAU_SHUFFLE32
#undef DOLBEAU_ROUNDS

#endif
