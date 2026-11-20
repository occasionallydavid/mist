/* From libsodium 1.0.20, crypto_stream/chacha20/dolbeau. See LICENSE. */

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

        for (i = 0; i < ROUNDS; i += 2) {
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
