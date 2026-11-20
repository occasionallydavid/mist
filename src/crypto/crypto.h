#ifndef MIST_CRYPTO_H
#define MIST_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

void mist_wipe(void *p, size_t n);
int mist_equal(const uint8_t *a, const uint8_t *b, size_t n);
void mist_x25519_public(uint8_t out[32], const uint8_t secret[32]);
int mist_x25519(uint8_t out[32], const uint8_t secret[32], const uint8_t peer[32]);
void mist_aead_seal(uint8_t *out, const uint8_t *in, size_t n,
                    const uint8_t *ad, size_t ad_len,
                    const uint8_t key[32], const uint8_t nonce[12]);
int mist_aead_open(uint8_t *out, const uint8_t *in, size_t n,
                   const uint8_t *ad, size_t ad_len,
                   const uint8_t key[32], const uint8_t nonce[12]);
void mist_nonce(uint8_t nonce[12], uint64_t number);
void mist_blake2s(uint8_t out[32], const uint8_t *in, size_t n);

#define MIST_PARAMS_LEN 24
#define MIST_NOISE_INIT_LEN (32 + 48 + MIST_PARAMS_LEN + 16)
#define MIST_NOISE_RESP_LEN (32 + MIST_PARAMS_LEN + 16)

typedef struct {
    uint8_t chain[32], hash[32], key[32];
    uint8_t ephemeral[32], remote_ephemeral[32], remote_static[32];
    uint64_t nonce;
} mist_noise;

int mist_noise_write_init(mist_noise *s, uint8_t out[MIST_NOISE_INIT_LEN],
                          const uint8_t cid[16], const uint8_t local[32],
                          const uint8_t peer[32], const uint8_t eph[32],
                          const uint8_t params[MIST_PARAMS_LEN]);
int mist_noise_read_init(mist_noise *s, uint8_t params[MIST_PARAMS_LEN],
                         const uint8_t cid[16], const uint8_t local[32],
                         const uint8_t public_key[32],
                         const uint8_t in[MIST_NOISE_INIT_LEN]);
int mist_noise_write_resp(mist_noise *s, uint8_t out[MIST_NOISE_RESP_LEN],
                          const uint8_t eph[32], const uint8_t params[MIST_PARAMS_LEN],
                          uint8_t k1[32], uint8_t k2[32]);
int mist_noise_read_resp(mist_noise *s, uint8_t params[MIST_PARAMS_LEN],
                         const uint8_t local[32], const uint8_t in[MIST_NOISE_RESP_LEN],
                         uint8_t k1[32], uint8_t k2[32]);

#endif
