/* From libsodium 1.0.20, crypto_stream/chacha20/dolbeau. See LICENSE. */
if (bytes > 0) {
    simde_v128_t       x_0, x_1, x_2, x_3;
    simde_v128_t       t_1;
    uint8_t partialblock[64];

    unsigned int i;

    x_0 = simde_wasm_v128_load((x + 0));
    x_1 = simde_wasm_v128_load((x + 4));
    x_2 = simde_wasm_v128_load((x + 8));
    x_3 = simde_wasm_v128_load((x + 12));

    for (i = 0; i < ROUNDS; i += 2) {
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
