#ifndef MIST_CRYPTO_POLY1305_SIMD_H
#define MIST_CRYPTO_POLY1305_SIMD_H

/* Andrew Moon's public-domain Poly1305-donna SSE2 kernel.
 * https://github.com/floodyberry/poly1305-opt/blob/700d5cf167441f627d76c845f56b7ea72bdd91e8/sources/poly1305-donna-x64-sse2-incremental-source.c
 * Ported to the SIMDe 128-bit vector API.
 */

#include <stdint.h>
#include <simde/wasm/simd128.h>

/* The original kernel multiplies the low word of each 64-bit lane. */
static inline simde_v128_t poly1305_mul_even(simde_v128_t a, simde_v128_t b)
{
    return simde_wasm_u64x2_extmul_low_u32x4(
        simde_wasm_i32x4_shuffle(a, a, 0, 2, 0, 2),
        simde_wasm_i32x4_shuffle(b, b, 0, 2, 0, 2));
}

#define POLY_SHUFFLE(v, a, b, c, d) simde_wasm_i32x4_shuffle(v, v, a, b, c, d)
#define POLY_UPPER(v) simde_wasm_i64x2_shuffle(v, simde_wasm_i32x4_splat(0), 1, 2)
#define POLY_UNPACK_LO(a, b) simde_wasm_i32x4_shuffle(a, b, 0, 4, 1, 5)
#define POLY_UNPACK_HI(a, b) simde_wasm_i32x4_shuffle(a, b, 2, 6, 3, 7)
#define POLY_UNPACK_64(a, b) simde_wasm_i64x2_shuffle(a, b, 0, 2)

enum poly1305_state_flags_t {
	poly1305_started = 1,
	poly1305_final_shift8 = 4,
	poly1305_final_shift16 = 8,
	poly1305_final_r2_r = 16, /* use [r^2,r] for the final block */
	poly1305_final_r_1 = 32, /* use [r,1] for the final block */
};

typedef struct poly1305_state_internal_t {
	union {
		uint64_t h[3];
		uint32_t hh[10];
	};                       /*  40 bytes  */
	uint32_t R[5];           /*  20 bytes  */
	uint32_t R2[5];          /*  20 bytes  */
	uint32_t R4[5];          /*  20 bytes  */
	uint64_t pad[2];         /*  16 bytes  */
	uint64_t flags;          /*   8 bytes  */
} poly1305_state_internal;   /* 124 bytes total */

/* Square a five-limb value modulo 2^130 - 5. */
static void
poly1305_square(uint32_t out[5], const uint32_t r[5])
{
    uint64_t r0 = r[0], r1 = r[1], r2 = r[2], r3 = r[3], r4 = r[4];
    uint64_t d0 = r0*r0 + 10*(r1*r4 + r2*r3);
    uint64_t d1 = 2*r0*r1 + 10*r2*r4 + 5*r3*r3;
    uint64_t d2 = 2*r0*r2 + r1*r1 + 10*r3*r4;
    uint64_t d3 = 2*(r0*r3 + r1*r2) + 5*r4*r4;
    uint64_t d4 = 2*(r0*r4 + r1*r3) + r2*r2;
    const uint32_t mask = 0x3ffffff;

    d1 += d0 >> 26;
    d2 += d1 >> 26;
    d3 += d2 >> 26;
    d4 += d3 >> 26;
    d0 = (d0 & mask) + 5*(d4 >> 26);
    out[0] = (uint32_t)d0 & mask;
    out[1] = ((uint32_t)d1 & mask) + (uint32_t)(d0 >> 26);
    out[2] = (uint32_t)d2 & mask;
    out[3] = (uint32_t)d3 & mask;
    out[4] = (uint32_t)d4 & mask;
}

static void
poly1305_init_simd(poly1305_state_internal *st, const uint8_t key[32])
{
    st->R[0] = load32_le(key) & 0x3ffffff;
    st->R[1] = (load32_le(key + 3) >> 2) & 0x3ffff03;
    st->R[2] = (load32_le(key + 6) >> 4) & 0x3ffc0ff;
    st->R[3] = (load32_le(key + 9) >> 6) & 0x3f03fff;
    st->R[4] = (load32_le(key + 12) >> 8) & 0x00fffff;
    st->pad[0] = load64_le(key + 16);
    st->pad[1] = load64_le(key + 24);
    poly1305_square(st->R2, st->R);
    poly1305_square(st->R4, st->R2);
    st->flags = 0;
}

static void
poly1305_blocks_simd(poly1305_state_internal *st, const uint8_t *m, size_t bytes) {
	simde_v128_t HIBIT = simde_wasm_u64x2_make(1 << 24, 1 << 24);
	const simde_v128_t MMASK = simde_wasm_u64x2_make((1 << 26) - 1, (1 << 26) - 1);
	const simde_v128_t FIVE = simde_wasm_u64x2_make(5, 5);

	simde_v128_t H0,H1,H2,H3,H4;
	simde_v128_t T0,T1,T2,T3,T4,T5,T6,T7,T8;
	simde_v128_t M0,M1,M2,M3,M4;
	simde_v128_t M5,M6,M7,M8;
	simde_v128_t C1,C2;
	simde_v128_t R20,R21,R22,R23,R24,S21,S22,S23,S24;
	simde_v128_t R40,R41,R42,R43,R44,S41,S42,S43,S44;

	if (st->flags & poly1305_final_shift8) HIBIT = POLY_UPPER(HIBIT);
	if (st->flags & poly1305_final_shift16) HIBIT = simde_wasm_i32x4_splat(0);

	if (!(st->flags & poly1305_started)) {
		/* H = [Mx,My] */
		T5 = POLY_UNPACK_64(simde_wasm_v128_load64_zero(m + 0), simde_wasm_v128_load64_zero(m + 16));
		T6 = POLY_UNPACK_64(simde_wasm_v128_load64_zero(m + 8), simde_wasm_v128_load64_zero(m + 24));
		H0 = simde_wasm_v128_and(MMASK, T5);
		H1 = simde_wasm_v128_and(MMASK, simde_wasm_u64x2_shr(T5, 26));
		T5 = simde_wasm_v128_or(simde_wasm_u64x2_shr(T5, 52), simde_wasm_i64x2_shl(T6, 12));
		H2 = simde_wasm_v128_and(MMASK, T5);
		H3 = simde_wasm_v128_and(MMASK, simde_wasm_u64x2_shr(T5, 26));
		H4 = simde_wasm_u64x2_shr(T6, 40);
		H4 = simde_wasm_v128_or(H4, HIBIT);
		m += 32;
		bytes -= 32;
		st->flags |= poly1305_started;
	} else {
		T0 = simde_wasm_v128_load(&st->hh[0]);
		T1 = simde_wasm_v128_load(&st->hh[4]);
		T2 = simde_wasm_v128_load64_zero(&st->hh[8]);
		H0 = POLY_SHUFFLE(T0, 0, 0, 1, 1);
		H1 = POLY_SHUFFLE(T0, 2, 2, 3, 3);
		H2 = POLY_SHUFFLE(T1, 0, 0, 1, 1);
		H3 = POLY_SHUFFLE(T1, 2, 2, 3, 3);
		H4 = POLY_SHUFFLE(T2, 0, 0, 1, 1);
	}

	if (st->flags & (poly1305_final_r2_r|poly1305_final_r_1)) {
		if (st->flags & poly1305_final_r2_r) {
			/* use [r^2, r] */
			T2 = simde_wasm_v128_load(&st->R[0]);
			T3 = simde_wasm_u32x4_make(st->R[4], 0, 0, 0);
			T0 = simde_wasm_v128_load(&st->R2[0]);
			T1 = simde_wasm_u32x4_make(st->R2[4], 0, 0, 0);
			T4 = POLY_UNPACK_LO(T0, T2);
			T5 = POLY_UNPACK_HI(T0, T2);
			R24 = POLY_UNPACK_64(T1, T3);
		} else {
			/* use [r^1, 1] */
			T0 = simde_wasm_v128_load(&st->R[0]);
			T1 = simde_wasm_u32x4_make(st->R[4], 0, 0, 0);
			T2 = simde_wasm_u32x4_make(1, 0, 0, 0);
			T4 = POLY_UNPACK_LO(T0, T2);
			T5 = POLY_UNPACK_HI(T0, T2);
			R24 = T1;
		}

		R20 = POLY_SHUFFLE(T4, 0, 0, 1, 1);
		R21 = POLY_SHUFFLE(T4, 2, 2, 3, 3);
		R22 = POLY_SHUFFLE(T5, 0, 0, 1, 1);
		R23 = POLY_SHUFFLE(T5, 2, 2, 3, 3);
	} else {
		/* use [r^2, r^2] */
		T0 = simde_wasm_v128_load(&st->R2[0]);
		T1 = simde_wasm_u32x4_make(st->R2[4], 0, 0, 0);
		R20 = POLY_SHUFFLE(T0, 0, 0, 0, 0);
		R21 = POLY_SHUFFLE(T0, 1, 1, 1, 1);
		R22 = POLY_SHUFFLE(T0, 2, 2, 2, 2);
		R23 = POLY_SHUFFLE(T0, 3, 3, 3, 3);
		R24 = POLY_SHUFFLE(T1, 0, 0, 0, 0);
	}
	S21 = poly1305_mul_even(R21, FIVE);
	S22 = poly1305_mul_even(R22, FIVE);
	S23 = poly1305_mul_even(R23, FIVE);
	S24 = poly1305_mul_even(R24, FIVE);

	if (bytes >= 64) {
		T0 = simde_wasm_v128_load(&st->R4[0]);
		T1 = simde_wasm_u32x4_make(st->R4[4], 0, 0, 0);
		R40 = POLY_SHUFFLE(T0, 0, 0, 0, 0);
		R41 = POLY_SHUFFLE(T0, 1, 1, 1, 1);
		R42 = POLY_SHUFFLE(T0, 2, 2, 2, 2);
		R43 = POLY_SHUFFLE(T0, 3, 3, 3, 3);
		R44 = POLY_SHUFFLE(T1, 0, 0, 0, 0);
		S41 = poly1305_mul_even(R41, FIVE);
		S42 = poly1305_mul_even(R42, FIVE);
		S43 = poly1305_mul_even(R43, FIVE);
		S44 = poly1305_mul_even(R44, FIVE);

		while (bytes >= 64) {
			simde_v128_t v00,v01,v02,v03,v04;
			simde_v128_t v10,v11,v12,v13,v14;
			simde_v128_t v20,v21,v22,v23,v24;
			simde_v128_t v30,v31,v32,v33,v34;
			simde_v128_t v40,v41,v42,v43,v44;
			simde_v128_t T14,T15;

			/* H *= [r^4,r^4], preload [Mx,My] */
			T15 = S42;
			T0  = H4; T0  = poly1305_mul_even(T0, S41);
			v01 = H3; v01 = poly1305_mul_even(v01, T15);
			T14 = S43;
			T1  = H4; T1  = poly1305_mul_even(T1 , T15);
			v11 = H3; v11 = poly1305_mul_even(v11, T14);
			T2  = H4; T2  = poly1305_mul_even(T2 , T14); T0 = simde_wasm_i64x2_add(T0, v01);
			T15 = S44;
			v02 = H2; v02 = poly1305_mul_even(v02, T14);
			T3  = H4; T3  = poly1305_mul_even(T3 , T15); T1 = simde_wasm_i64x2_add(T1, v11);
			v03 = H1; v03 = poly1305_mul_even(v03, T15);
			v12 = H2; v12 = poly1305_mul_even(v12, T15); T0 = simde_wasm_i64x2_add(T0, v02);
			T14 = R40;
			v21 = H3; v21 = poly1305_mul_even(v21, T15);
			v31 = H3; v31 = poly1305_mul_even(v31, T14); T0 = simde_wasm_i64x2_add(T0, v03);
			T4  = H4; T4  = poly1305_mul_even(T4 , T14); T1 = simde_wasm_i64x2_add(T1, v12);
			v04 = H0; v04 = poly1305_mul_even(v04, T14); T2 = simde_wasm_i64x2_add(T2, v21);
			v13 = H1; v13 = poly1305_mul_even(v13, T14); T3 = simde_wasm_i64x2_add(T3, v31);
			T15 = R41;
			v22 = H2; v22 = poly1305_mul_even(v22, T14);
			v32 = H2; v32 = poly1305_mul_even(v32, T15); T0 = simde_wasm_i64x2_add(T0, v04);
			v41 = H3; v41 = poly1305_mul_even(v41, T15); T1 = simde_wasm_i64x2_add(T1, v13);
			v14 = H0; v14 = poly1305_mul_even(v14, T15); T2 = simde_wasm_i64x2_add(T2, v22);
			T14 = R42;
			T5 = POLY_UNPACK_64(simde_wasm_v128_load64_zero(m + 0), simde_wasm_v128_load64_zero(m + 16));
			v23 = H1; v23 = poly1305_mul_even(v23, T15); T3 = simde_wasm_i64x2_add(T3, v32);
			v33 = H1; v33 = poly1305_mul_even(v33, T14); T4 = simde_wasm_i64x2_add(T4, v41);
			v42 = H2; v42 = poly1305_mul_even(v42, T14); T1 = simde_wasm_i64x2_add(T1, v14);
			T15 = R43;
			T6 = POLY_UNPACK_64(simde_wasm_v128_load64_zero(m + 8), simde_wasm_v128_load64_zero(m + 24));
			v24 = H0; v24 = poly1305_mul_even(v24, T14); T2 = simde_wasm_i64x2_add(T2, v23);
			v34 = H0; v34 = poly1305_mul_even(v34, T15); T3 = simde_wasm_i64x2_add(T3, v33);
			M0 = simde_wasm_v128_and(MMASK, T5);
			v43 = H1; v43 = poly1305_mul_even(v43, T15); T4 = simde_wasm_i64x2_add(T4, v42);
			M1 = simde_wasm_v128_and(MMASK, simde_wasm_u64x2_shr(T5, 26));
			v44 = H0; v44 = poly1305_mul_even(v44, R44); T2 = simde_wasm_i64x2_add(T2, v24);
			T5 = simde_wasm_v128_or(simde_wasm_u64x2_shr(T5, 52), simde_wasm_i64x2_shl(T6, 12));
													 T3 = simde_wasm_i64x2_add(T3, v34);
			M3 = simde_wasm_v128_and(MMASK, simde_wasm_u64x2_shr(T6, 14));
													 T4 = simde_wasm_i64x2_add(T4, v43);
			M2 = simde_wasm_v128_and(MMASK, T5);
													 T4 = simde_wasm_i64x2_add(T4, v44);
			M4 = simde_wasm_v128_or(simde_wasm_u64x2_shr(T6, 40), HIBIT);

			/* H += [Mx',My'] */
			T5 = simde_wasm_v128_load((m + 32));
			T6 = simde_wasm_v128_load((m + 48));
			T7 = POLY_UNPACK_LO(T5, T6);
			T8 = POLY_UNPACK_HI(T5, T6);
			M5 = POLY_UNPACK_LO(T7, simde_wasm_i32x4_splat(0));
			M6 = POLY_UNPACK_HI(T7, simde_wasm_i32x4_splat(0));
			M7 = POLY_UNPACK_LO(T8, simde_wasm_i32x4_splat(0));
			M8 = POLY_UNPACK_HI(T8, simde_wasm_i32x4_splat(0));
			M6 = simde_wasm_i64x2_shl(M6, 6);
			M7 = simde_wasm_i64x2_shl(M7, 12);
			M8 = simde_wasm_i64x2_shl(M8, 18);
			T0 = simde_wasm_i64x2_add(T0, M5);
			T1 = simde_wasm_i64x2_add(T1, M6);
			T2 = simde_wasm_i64x2_add(T2, M7);
			T3 = simde_wasm_i64x2_add(T3, M8);
			T4 = simde_wasm_i64x2_add(T4, HIBIT);

			/* H += [Mx,My]*[r^2,r^2] */
			T15 = S22;
			v00 = M4; v00 = poly1305_mul_even(v00, S21);
			v01 = M3; v01 = poly1305_mul_even(v01, T15);
			T14 = S23;
			v10 = M4; v10 = poly1305_mul_even(v10, T15);
			v11 = M3; v11 = poly1305_mul_even(v11, T14); T0 = simde_wasm_i64x2_add(T0, v00);
			v20 = M4; v20 = poly1305_mul_even(v20, T14); T0 = simde_wasm_i64x2_add(T0, v01);
			T15 = S24;
			v02 = M2; v02 = poly1305_mul_even(v02, T14); T1 = simde_wasm_i64x2_add(T1, v10);
			v30 = M4; v30 = poly1305_mul_even(v30, T15); T1 = simde_wasm_i64x2_add(T1, v11);
			v03 = M1; v03 = poly1305_mul_even(v03, T15); T2 = simde_wasm_i64x2_add(T2, v20);
			v12 = M2; v12 = poly1305_mul_even(v12, T15); T0 = simde_wasm_i64x2_add(T0, v02);
			T14 = R20;
			v21 = M3; v21 = poly1305_mul_even(v21, T15); T3 = simde_wasm_i64x2_add(T3, v30);
			v31 = M3; v31 = poly1305_mul_even(v31, T14); T0 = simde_wasm_i64x2_add(T0, v03);
			v40 = M4; v40 = poly1305_mul_even(v40, T14); T1 = simde_wasm_i64x2_add(T1, v12);
			v04 = M0; v04 = poly1305_mul_even(v04, T14); T2 = simde_wasm_i64x2_add(T2, v21);
			v13 = M1; v13 = poly1305_mul_even(v13, T14); T3 = simde_wasm_i64x2_add(T3, v31);
			T15 = R21;
			v22 = M2; v22 = poly1305_mul_even(v22, T14); T4 = simde_wasm_i64x2_add(T4, v40);
			v32 = M2; v32 = poly1305_mul_even(v32, T15); T0 = simde_wasm_i64x2_add(T0, v04);
			v41 = M3; v41 = poly1305_mul_even(v41, T15); T1 = simde_wasm_i64x2_add(T1, v13);
			v14 = M0; v14 = poly1305_mul_even(v14, T15); T2 = simde_wasm_i64x2_add(T2, v22);
			T14 = R22;
			v23 = M1; v23 = poly1305_mul_even(v23, T15); T3 = simde_wasm_i64x2_add(T3, v32);
			v33 = M1; v33 = poly1305_mul_even(v33, T14); T4 = simde_wasm_i64x2_add(T4, v41);
			v42 = M2; v42 = poly1305_mul_even(v42, T14); T1 = simde_wasm_i64x2_add(T1, v14);
			T15 = R23;
			v24 = M0; v24 = poly1305_mul_even(v24, T14); T2 = simde_wasm_i64x2_add(T2, v23);
			v34 = M0; v34 = poly1305_mul_even(v34, T15); T3 = simde_wasm_i64x2_add(T3, v33);
			v43 = M1; v43 = poly1305_mul_even(v43, T15); T4 = simde_wasm_i64x2_add(T4, v42);
			v44 = M0; v44 = poly1305_mul_even(v44, R24); T2 = simde_wasm_i64x2_add(T2, v24);
													 T3 = simde_wasm_i64x2_add(T3, v34);
													 T4 = simde_wasm_i64x2_add(T4, v43);
													 T4 = simde_wasm_i64x2_add(T4, v44);

			/* reduce */
			C1 = simde_wasm_u64x2_shr(T0, 26); C2 = simde_wasm_u64x2_shr(T3, 26); T0 = simde_wasm_v128_and(T0, MMASK); T3 = simde_wasm_v128_and(T3, MMASK); T1 = simde_wasm_i64x2_add(T1, C1); T4 = simde_wasm_i64x2_add(T4, C2);
			C1 = simde_wasm_u64x2_shr(T1, 26); C2 = simde_wasm_u64x2_shr(T4, 26); T1 = simde_wasm_v128_and(T1, MMASK); T4 = simde_wasm_v128_and(T4, MMASK); T2 = simde_wasm_i64x2_add(T2, C1); T0 = simde_wasm_i64x2_add(T0, poly1305_mul_even(C2, FIVE));
			C1 = simde_wasm_u64x2_shr(T2, 26); C2 = simde_wasm_u64x2_shr(T0, 26); T2 = simde_wasm_v128_and(T2, MMASK); T0 = simde_wasm_v128_and(T0, MMASK); T3 = simde_wasm_i64x2_add(T3, C1); T1 = simde_wasm_i64x2_add(T1, C2);
			C1 = simde_wasm_u64x2_shr(T3, 26);                              T3 = simde_wasm_v128_and(T3, MMASK);                                T4 = simde_wasm_i64x2_add(T4, C1);

			/* Final: H = (H*[r^4,r^4] + [Mx,My]*[r^2,r^2] + [Mx',My']) */
			H0 = T0;
			H1 = T1;
			H2 = T2;
			H3 = T3;
			H4 = T4;

			m += 64;
			bytes -= 64;
		}
	}


	if (bytes >= 32) {
		simde_v128_t v01,v02,v03,v04;
		simde_v128_t v11,v12,v13,v14;
		simde_v128_t v21,v22,v23,v24;
		simde_v128_t v31,v32,v33,v34;
		simde_v128_t v41,v42,v43,v44;
		simde_v128_t T14,T15;

		/* H *= [r^2,r^2] */
		T15 = S22;
		T0  = H4; T0  = poly1305_mul_even(T0, S21);
		v01 = H3; v01 = poly1305_mul_even(v01, T15);
		T14 = S23;
		T1  = H4; T1  = poly1305_mul_even(T1 , T15);
		v11 = H3; v11 = poly1305_mul_even(v11, T14);
		T2  = H4; T2  = poly1305_mul_even(T2 , T14); T0 = simde_wasm_i64x2_add(T0, v01);
		T15 = S24;
		v02 = H2; v02 = poly1305_mul_even(v02, T14);
		T3  = H4; T3  = poly1305_mul_even(T3 , T15); T1 = simde_wasm_i64x2_add(T1, v11);
		v03 = H1; v03 = poly1305_mul_even(v03, T15);
		v12 = H2; v12 = poly1305_mul_even(v12, T15); T0 = simde_wasm_i64x2_add(T0, v02);
		T14 = R20;
		v21 = H3; v21 = poly1305_mul_even(v21, T15);
		v31 = H3; v31 = poly1305_mul_even(v31, T14); T0 = simde_wasm_i64x2_add(T0, v03);
		T4  = H4; T4  = poly1305_mul_even(T4 , T14); T1 = simde_wasm_i64x2_add(T1, v12);
		v04 = H0; v04 = poly1305_mul_even(v04, T14); T2 = simde_wasm_i64x2_add(T2, v21);
		v13 = H1; v13 = poly1305_mul_even(v13, T14); T3 = simde_wasm_i64x2_add(T3, v31);
		T15 = R21;
		v22 = H2; v22 = poly1305_mul_even(v22, T14);
		v32 = H2; v32 = poly1305_mul_even(v32, T15); T0 = simde_wasm_i64x2_add(T0, v04);
		v41 = H3; v41 = poly1305_mul_even(v41, T15); T1 = simde_wasm_i64x2_add(T1, v13);
		v14 = H0; v14 = poly1305_mul_even(v14, T15); T2 = simde_wasm_i64x2_add(T2, v22);
		T14 = R22;
		v23 = H1; v23 = poly1305_mul_even(v23, T15); T3 = simde_wasm_i64x2_add(T3, v32);
		v33 = H1; v33 = poly1305_mul_even(v33, T14); T4 = simde_wasm_i64x2_add(T4, v41);
		v42 = H2; v42 = poly1305_mul_even(v42, T14); T1 = simde_wasm_i64x2_add(T1, v14);
		T15 = R23;
		v24 = H0; v24 = poly1305_mul_even(v24, T14); T2 = simde_wasm_i64x2_add(T2, v23);
		v34 = H0; v34 = poly1305_mul_even(v34, T15); T3 = simde_wasm_i64x2_add(T3, v33);
		v43 = H1; v43 = poly1305_mul_even(v43, T15); T4 = simde_wasm_i64x2_add(T4, v42);
		v44 = H0; v44 = poly1305_mul_even(v44, R24); T2 = simde_wasm_i64x2_add(T2, v24);
		                                         T3 = simde_wasm_i64x2_add(T3, v34);
		                                         T4 = simde_wasm_i64x2_add(T4, v43);
		                                         T4 = simde_wasm_i64x2_add(T4, v44);

		/* H += [Mx,My] */
		if (m) {
			T5 = simde_wasm_v128_load((m + 0));
			T6 = simde_wasm_v128_load((m + 16));
			T7 = POLY_UNPACK_LO(T5, T6);
			T8 = POLY_UNPACK_HI(T5, T6);
			M0 = POLY_UNPACK_LO(T7, simde_wasm_i32x4_splat(0));
			M1 = POLY_UNPACK_HI(T7, simde_wasm_i32x4_splat(0));
			M2 = POLY_UNPACK_LO(T8, simde_wasm_i32x4_splat(0));
			M3 = POLY_UNPACK_HI(T8, simde_wasm_i32x4_splat(0));
			M1 = simde_wasm_i64x2_shl(M1, 6);
			M2 = simde_wasm_i64x2_shl(M2, 12);
			M3 = simde_wasm_i64x2_shl(M3, 18);
			T0 = simde_wasm_i64x2_add(T0, M0);
			T1 = simde_wasm_i64x2_add(T1, M1);
			T2 = simde_wasm_i64x2_add(T2, M2);
			T3 = simde_wasm_i64x2_add(T3, M3);
			T4 = simde_wasm_i64x2_add(T4, HIBIT);
		}

		/* reduce */
		C1 = simde_wasm_u64x2_shr(T0, 26); C2 = simde_wasm_u64x2_shr(T3, 26); T0 = simde_wasm_v128_and(T0, MMASK); T3 = simde_wasm_v128_and(T3, MMASK); T1 = simde_wasm_i64x2_add(T1, C1); T4 = simde_wasm_i64x2_add(T4, C2);
		C1 = simde_wasm_u64x2_shr(T1, 26); C2 = simde_wasm_u64x2_shr(T4, 26); T1 = simde_wasm_v128_and(T1, MMASK); T4 = simde_wasm_v128_and(T4, MMASK); T2 = simde_wasm_i64x2_add(T2, C1); T0 = simde_wasm_i64x2_add(T0, poly1305_mul_even(C2, FIVE));
		C1 = simde_wasm_u64x2_shr(T2, 26); C2 = simde_wasm_u64x2_shr(T0, 26); T2 = simde_wasm_v128_and(T2, MMASK); T0 = simde_wasm_v128_and(T0, MMASK); T3 = simde_wasm_i64x2_add(T3, C1); T1 = simde_wasm_i64x2_add(T1, C2);
		C1 = simde_wasm_u64x2_shr(T3, 26);                              T3 = simde_wasm_v128_and(T3, MMASK);                                T4 = simde_wasm_i64x2_add(T4, C1);

		/* H = (H*[r^2,r^2] + [Mx,My]) */
		H0 = T0;
		H1 = T1;
		H2 = T2;
		H3 = T3;
		H4 = T4;
	}

	if (m) {
		T0 = POLY_SHUFFLE(H0, 0, 2, 0, 0);
		T1 = POLY_SHUFFLE(H1, 0, 2, 0, 0);
		T2 = POLY_SHUFFLE(H2, 0, 2, 0, 0);
		T3 = POLY_SHUFFLE(H3, 0, 2, 0, 0);
		T4 = POLY_SHUFFLE(H4, 0, 2, 0, 0);
		T0 = POLY_UNPACK_64(T0, T1);
		T1 = POLY_UNPACK_64(T2, T3);
		simde_wasm_v128_store(&st->hh[0], T0);
		simde_wasm_v128_store(&st->hh[4], T1);
		simde_wasm_v128_store64_lane(&st->hh[8], T4, 0);
	} else {
		uint32_t t0,t1,t2,t3,t4,b;
		uint64_t h0,h1,h2,g0,g1,g2,c,nc;

		/* H = H[0]+H[1] */
		T0 = H0;
		T1 = H1;
		T2 = H2;
		T3 = H3;
		T4 = H4;

		T0 = simde_wasm_i64x2_add(T0, POLY_UPPER(T0));
		T1 = simde_wasm_i64x2_add(T1, POLY_UPPER(T1));
		T2 = simde_wasm_i64x2_add(T2, POLY_UPPER(T2));
		T3 = simde_wasm_i64x2_add(T3, POLY_UPPER(T3));
		T4 = simde_wasm_i64x2_add(T4, POLY_UPPER(T4));

		t0 = simde_wasm_u32x4_extract_lane(T0, 0)    ; b = (t0 >> 26); t0 &= 0x3ffffff;
		t1 = simde_wasm_u32x4_extract_lane(T1, 0) + b; b = (t1 >> 26); t1 &= 0x3ffffff;
		t2 = simde_wasm_u32x4_extract_lane(T2, 0) + b; b = (t2 >> 26); t2 &= 0x3ffffff;
		t3 = simde_wasm_u32x4_extract_lane(T3, 0) + b; b = (t3 >> 26); t3 &= 0x3ffffff;
		t4 = simde_wasm_u32x4_extract_lane(T4, 0) + b;

		/* everything except t4 is in range, so this is all safe */
		h0 =  (((uint64_t)t0      ) | ((uint64_t)t1 << 26)                       ) & 0xfffffffffffull;
		h1 =  (((uint64_t)t1 >> 18) | ((uint64_t)t2 <<  8) | ((uint64_t)t3 << 34)) & 0xfffffffffffull;
		h2 =  (((uint64_t)t3 >> 10) | ((uint64_t)t4 << 16)                       );

		             c = (h2 >> 42); h2 &= 0x3ffffffffff;
		h0 += c * 5; c = (h0 >> 44); h0 &= 0xfffffffffff;
		h1 += c;	 c = (h1 >> 44); h1 &= 0xfffffffffff;
		h2 += c;     c = (h2 >> 42); h2 &= 0x3ffffffffff;
		h0 += c * 5; c = (h0 >> 44); h0 &= 0xfffffffffff;
		h1 += c;

		g0 = h0 + 5; c = (g0 >> 44); g0 &= 0xfffffffffff;
		g1 = h1 + c; c = (g1 >> 44); g1 &= 0xfffffffffff;
		g2 = h2 + c - ((uint64_t)1 << 42);

		c = (g2 >> 63) - 1;
		nc = ~c;
		h0 = (h0 & nc) | (g0 & c);
		h1 = (h1 & nc) | (g1 & c);
		h2 = (h2 & nc) | (g2 & c);

		st->h[0] = h0;
		st->h[1] = h1;
		st->h[2] = h2;
	}
}

static void
poly1305_finish_ext_simd(poly1305_state_internal *st, const uint8_t *m, size_t leftover, unsigned char mac[16]) {
	uint64_t h0,h1,h2;

	if (leftover) {
		unsigned char final[32] = {0};
		memcpy(final, m, leftover);
		if (leftover != 16) final[leftover] = 1;
		st->flags |= (leftover >= 16) ? poly1305_final_shift8 : poly1305_final_shift16;
		poly1305_blocks_simd(st, final, 32);
	}

	if (st->flags & poly1305_started) {
		/* finalize, H *= [r^2,r], or H *= [r,1] */
		if (!leftover || (leftover > 16))
			st->flags |= poly1305_final_r2_r;
		else
			st->flags |= poly1305_final_r_1;
		poly1305_blocks_simd(st, NULL, 32);
	}

	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];

	/* pad */
	h0 = ((h0      ) | (h1 << 44));
	h1 = ((h1 >> 20) | (h2 << 24));

	uint64_t low = h0 + st->pad[0];
	store64_le(mac, low);
	store64_le(mac + 8, h1 + st->pad[1] + (low < h0));
}

#undef POLY_SHUFFLE
#undef POLY_UPPER
#undef POLY_UNPACK_LO
#undef POLY_UNPACK_HI
#undef POLY_UNPACK_64

#endif
