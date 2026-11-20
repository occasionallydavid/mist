#include "crypto/crypto.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static unsigned nibble(char c)
{
    return c <= '9' ? (unsigned)(c - '0') : (unsigned)(c - 'a' + 10);
}

static size_t hex(uint8_t *out, const char *str)
{
    size_t n = strlen(str) / 2;
    for (size_t i = 0; i < n; ++i)
        out[i] = (uint8_t)((nibble(str[2 * i]) << 4) | nibble(str[2 * i + 1]));
    return n;
}

static void expect(const uint8_t *data, size_t n, const char *str)
{
    uint8_t expected[160];
    assert(hex(expected, str) == n);
    assert(memcmp(data, expected, n) == 0);
}

static void x25519(void)
{
    uint8_t alice[32], bob[32], a[32], b[32], shared[32];
    hex(alice, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    hex(bob, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    mist_x25519_public(a, alice);
    mist_x25519_public(b, bob);
    expect(a, 32, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    expect(b, 32, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    assert(mist_x25519(shared, alice, b));
    expect(shared, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert(mist_x25519(shared, bob, a));
    expect(shared, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    memset(a, 0, 32);
    assert(!mist_x25519(shared, alice, a));
    a[0] = 1;
    assert(!mist_x25519(shared, alice, a));

    uint8_t k[32] = {9}, u[32] = {9};
    for (unsigned i = 0; i < 1000; ++i) {
        assert(mist_x25519(shared, k, u));
        memcpy(u, k, 32);
        memcpy(k, shared, 32);
        if (i == 0)
            expect(k, 32, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
    }
    expect(k, 32, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
}

static void aead(void)
{
    static const uint8_t plaintext[] =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
        "for the future, sunscreen would be it.";
    uint8_t key[32], nonce[12], ad[12], box[sizeof plaintext - 1 + 16];
    uint8_t output[sizeof plaintext - 1];
    hex(key, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    hex(nonce, "070000004041424344454647");
    hex(ad, "50515253c0c1c2c3c4c5c6c7");
    mist_aead_seal(box, plaintext, sizeof output, ad, sizeof ad, key, nonce);
    expect(box, sizeof box,
           "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63"
           "dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
           "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
           "3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691");
    assert(mist_aead_open(output, box, sizeof output, ad, sizeof ad, key, nonce));
    assert(!memcmp(plaintext, output, sizeof output));
    memset(output, 0xab, sizeof output);
    box[sizeof box - 1] ^= 1;
    assert(!mist_aead_open(output, box, sizeof output, ad, sizeof ad, key, nonce));
    for (size_t i = 0; i < sizeof output; ++i)
        assert(output[i] == 0xab);
}

static void blake2s(void)
{
    uint8_t data[255], out[32];
    for (unsigned i = 0; i < sizeof data; ++i)
        data[i] = (uint8_t)i;
    mist_blake2s(out, NULL, 0);
    expect(out, 32, "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
    mist_blake2s(out, (const uint8_t *)"abc", 3);
    expect(out, 32, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    mist_blake2s(out, data, 64);
    expect(out, 32, "56f34e8b96557e90c1f24b52d0c89d51086acf1b00f634cf1dde9233b8eaaa3e");
    mist_blake2s(out, data, 65);
    expect(out, 32, "1b53ee94aaf34e4b159d48de352c7f0661d0a40edff95a0b1639b4090e974472");
    mist_blake2s(out, data, sizeof data);
    expect(out, 32, "f03f5789d3336b80d002d59fdf918bdb775b00956ed5528e86aa994acb38fe2d");
}

/* Cacophony's IK keys, with MIST's prologue and parameter payloads.
 * Expected bytes generated with Python cryptography and hashlib after
 * reproducing Cacophony's published handshake and first transport packets. */
static void noise(void)
{
    mist_noise initiator, responder;
    uint8_t si[32], sr[32], ei[32], er[32], pr[32], pi[32], cid[16];
    uint8_t k1[32], k2[32], peer_k1[32], peer_k2[32];
    uint8_t pa[MIST_PARAMS_LEN], pb[MIST_PARAMS_LEN], decoded[MIST_PARAMS_LEN];
    uint8_t init[MIST_NOISE_INIT_LEN], resp[MIST_NOISE_RESP_LEN];
    hex(si, "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1");
    hex(sr, "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893");
    hex(ei, "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a");
    hex(er, "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b");
    hex(cid, "000102030405060708090a0b0c0d0e0f");
    hex(pa, "000000000010000000000000000100000000001000000040");
    hex(pb, "000000000020000000000000000200000000002000000100");
    mist_x25519_public(pr, sr);
    mist_x25519_public(pi, si);
    assert(mist_noise_write_init(&initiator, init, cid, si, pr, ei, pa));
    expect(init, sizeof init,
           "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79440b"
           "03ddc7aac5123d06a1b23b71670e32e76c28239a7ca4ac8f784de7e44c1adbeb0"
           "4757fa0dd8be6e3ade72c4076770f3768736b8a1f02ea141b0a8f32fdca3d4aaf"
           "4811e860f2481ff1cab51faed6280f6a085f6af54505");
    assert(mist_noise_read_init(&responder, decoded, cid, sr, pr, init));
    assert(!memcmp(decoded, pa, sizeof pa) && !memcmp(responder.remote_static, pi, 32));
    assert(mist_noise_write_resp(&responder, resp, er, pb, k1, k2));
    expect(resp, sizeof resp,
           "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088439"
           "4c0dae01e53e93731830051dd0e31009393cc0f75beb6e82896d5314293db993a2"
           "0d741aa81b74d");
    expect(k1, 32, "5f098179a66cf7bcf05c827118632c5e8196e9b3180b19a79808f56c9aa21bbe");
    expect(k2, 32, "72b76a299926ffeddd2a4305781399ff17d3eedc9f809287d544d9115041d7d8");
    assert(mist_noise_read_resp(&initiator, decoded, si, resp, peer_k1, peer_k2));
    assert(!memcmp(decoded, pb, sizeof pb));
    assert(!memcmp(k1, peer_k1, 32) && !memcmp(k2, peer_k2, 32));
}

int main(void)
{
    x25519();
    aead();
    blake2s();
    noise();
    puts("crypto vectors passed");
}
