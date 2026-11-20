/* From libsodium 1.0.20, crypto_stream/chacha20/dolbeau. See LICENSE. */
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
