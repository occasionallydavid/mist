#include "crypto.h"

#include <string.h>

/* Noise IK only needs HMAC with a 32-byte key and inputs of at most 33 bytes. */
static void hmac(uint8_t out[32], const uint8_t key[32],
                 const uint8_t *input, size_t n)
{
    uint8_t inner[97], outer[96];
    memset(inner, 0x36, 64);
    memset(outer, 0x5c, 64);
    for (size_t i = 0; i < 32; ++i) {
        inner[i] ^= key[i];
        outer[i] ^= key[i];
    }
    if (n)
        memcpy(inner + 64, input, n);
    mist_blake2s(outer + 64, inner, 64 + n);
    mist_blake2s(out, outer, sizeof outer);
    mist_wipe(inner, sizeof inner);
    mist_wipe(outer, sizeof outer);
}

static void hkdf(uint8_t a[32], uint8_t b[32], const uint8_t chain[32],
                 const uint8_t *input, size_t n)
{
    uint8_t temp[32], block[33] = {1};
    hmac(temp, chain, input, n);
    hmac(block, temp, block, 1);
    memcpy(a, block, 32);
    block[32] = 2;
    hmac(b, temp, block, sizeof block);
    mist_wipe(temp, sizeof temp);
    mist_wipe(block, sizeof block);
}

static void mix_hash(mist_noise *s, const uint8_t *data, size_t n)
{
    uint8_t joined[32 + 48];
    memcpy(joined, s->hash, 32);
    memcpy(joined + 32, data, n);
    mist_blake2s(s->hash, joined, 32 + n);
    mist_wipe(joined, sizeof joined);
}

static void initialize(mist_noise *s, const uint8_t cid[16],
                       const uint8_t responder[32])
{
    static const uint8_t name[] = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
    uint8_t prologue[21] = {'M', 'S', 'T', '1', 1};
    memset(s, 0, sizeof *s);
    uint8_t protocol_hash[32];
    mist_blake2s(protocol_hash, name, sizeof name - 1);
    memcpy(s->hash, protocol_hash, sizeof protocol_hash);
    memcpy(s->chain, protocol_hash, sizeof protocol_hash);
    memcpy(prologue + 5, cid, 16);
    mix_hash(s, prologue, sizeof prologue);
    mix_hash(s, responder, 32);
}

static int mix_dh(mist_noise *s, const uint8_t secret[32], const uint8_t peer[32])
{
    uint8_t dh[32];
    int valid = mist_x25519(dh, secret, peer);
    if (valid) {
        hkdf(s->chain, s->key, s->chain, dh, sizeof dh);
        s->nonce = 0;
    }
    mist_wipe(dh, sizeof dh);
    return valid;
}

static void encrypt(mist_noise *s, uint8_t *out, const uint8_t *in, size_t n)
{
    uint8_t nonce[12];
    mist_nonce(nonce, s->nonce++);
    mist_aead_seal(out, in, n, s->hash, 32, s->key, nonce);
    mix_hash(s, out, n + 16);
}

static int decrypt(mist_noise *s, uint8_t *out, const uint8_t *in, size_t n)
{
    uint8_t nonce[12];
    mist_nonce(nonce, s->nonce++);
    if (!mist_aead_open(out, in, n, s->hash, 32, s->key, nonce))
        return 0;
    mix_hash(s, in, n + 16);
    return 1;
}

int mist_noise_write_init(mist_noise *s, uint8_t out[MIST_NOISE_INIT_LEN],
                          const uint8_t cid[16], const uint8_t local[32],
                          const uint8_t peer[32], const uint8_t eph[32],
                          const uint8_t params[MIST_PARAMS_LEN])
{
    uint8_t public_key[32];
    initialize(s, cid, peer);
    memcpy(s->ephemeral, eph, 32);
    mist_x25519_public(out, eph);
    mix_hash(s, out, 32);
    if (!mix_dh(s, eph, peer))
        return 0;
    mist_x25519_public(public_key, local);
    encrypt(s, out + 32, public_key, 32);
    if (!mix_dh(s, local, peer))
        return 0;
    encrypt(s, out + 80, params, MIST_PARAMS_LEN);
    return 1;
}

int mist_noise_read_init(mist_noise *s, uint8_t params[MIST_PARAMS_LEN],
                         const uint8_t cid[16], const uint8_t local[32],
                         const uint8_t public_key[32],
                         const uint8_t in[MIST_NOISE_INIT_LEN])
{
    initialize(s, cid, public_key);
    memcpy(s->remote_ephemeral, in, 32);
    mix_hash(s, in, 32);
    return mix_dh(s, local, in) &&
           decrypt(s, s->remote_static, in + 32, 32) &&
           mix_dh(s, local, s->remote_static) &&
           decrypt(s, params, in + 80, MIST_PARAMS_LEN);
}

int mist_noise_write_resp(mist_noise *s, uint8_t out[MIST_NOISE_RESP_LEN],
                          const uint8_t eph[32], const uint8_t params[MIST_PARAMS_LEN],
                          uint8_t k1[32], uint8_t k2[32])
{
    mist_x25519_public(out, eph);
    mix_hash(s, out, 32);
    if (!mix_dh(s, eph, s->remote_ephemeral) ||
        !mix_dh(s, eph, s->remote_static))
        return 0;
    encrypt(s, out + 32, params, MIST_PARAMS_LEN);
    hkdf(k1, k2, s->chain, NULL, 0);
    return 1;
}

int mist_noise_read_resp(mist_noise *s, uint8_t params[MIST_PARAMS_LEN],
                         const uint8_t local[32], const uint8_t in[MIST_NOISE_RESP_LEN],
                         uint8_t k1[32], uint8_t k2[32])
{
    mix_hash(s, in, 32);
    if (!mix_dh(s, s->ephemeral, in) || !mix_dh(s, local, in) ||
        !decrypt(s, params, in + 32, MIST_PARAMS_LEN))
        return 0;
    hkdf(k1, k2, s->chain, NULL, 0);
    return 1;
}
