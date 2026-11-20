#include "internal.h"

typedef struct {
    uint64_t expires;
    uint8_t initiator[32], responder[32], ephemeral[32];
} replay_entry;

struct mist_replay_cache {
    size_t capacity, cursor;
    replay_entry entries[];
};

mist_replay_cache *mist_replay_cache_create(size_t capacity)
{
    if (!capacity || capacity > 4096)
        return NULL;
    mist_replay_cache *cache = calloc(1, sizeof *cache + capacity * sizeof(replay_entry));
    if (cache)
        cache->capacity = capacity;
    return cache;
}

void mist_replay_cache_destroy(mist_replay_cache *cache)
{
    free(cache);
}

static bool remember_init(mist_conn *c, const mist_noise *noise)
{
    mist_replay_cache *cache = c->config.replay_cache;
    if (!cache)
        return true;

    size_t slot = cache->cursor;
    bool found_expired = false;
    for (size_t i = 0; i < cache->capacity; ++i) {
        replay_entry *entry = &cache->entries[i];
        if (entry->expires <= c->now) {
            if (!found_expired) {
                slot = i;
                found_expired = true;
            }
            continue;
        }
        if (mist_equal(entry->initiator, noise->remote_static, 32) &&
            mist_equal(entry->responder, c->public_key, 32) &&
            mist_equal(entry->ephemeral, noise->remote_ephemeral, 32))
            return false;
    }
    replay_entry *entry = &cache->entries[slot];
    memcpy(entry->initiator, noise->remote_static, 32);
    memcpy(entry->responder, c->public_key, 32);
    memcpy(entry->ephemeral, noise->remote_ephemeral, 32);
    entry->expires = mist_add(c->now, SERVER_CACHE_TIME);
    cache->cursor = (slot + 1) % cache->capacity;
    return true;
}

static void write_params(const mist_config *cfg, uint8_t out[MIST_PARAMS_LEN])
{
    write_be(out, cfg->initial_max_data, 8);
    write_be(out + 8, cfg->initial_max_stream_data, 8);
    write_be(out + 16, cfg->max_streams_bidi, 4);
    write_be(out + 20, cfg->max_streams_uni, 4);
}

static bool read_params(const uint8_t in[MIST_PARAMS_LEN], params *p)
{
    p->max_data = read_be(in, 8);
    p->max_stream_data = read_be(in + 8, 8);
    p->max_bidi = (uint32_t)read_be(in + 16, 4);
    p->max_uni = (uint32_t)read_be(in + 20, 4);
    return p->max_data <= MIST_MAX_WINDOW &&
           p->max_stream_data <= MIST_MAX_WINDOW &&
           p->max_bidi <= MIST_MAX_INITIAL_STREAMS &&
           p->max_uni <= MIST_MAX_INITIAL_STREAMS;
}

static void install_peer(mist_conn *c, params peer)
{
    c->peer = peer;
    c->tx_limit = peer.max_data;
    c->classes[c->server].peer_limit = peer.max_bidi;
    c->classes[2u + c->server].peer_limit = peer.max_uni;
}

static void install_keys(mist_conn *c, const uint8_t send[32], const uint8_t recv[32])
{
    memcpy(c->send_key, send, 32);
    memcpy(c->recv_key, recv, 32);
    mist_wipe(c->local_key, sizeof c->local_key);
    mist_wipe(&c->noise, sizeof c->noise);
    c->last_rx = c->now;
    c->expire_at = mist_add(c->now, SESSION_TIME);
    c->reconnect_at = mist_add(c->now, RECONNECT_TIME);
}

void establish(mist_conn *c)
{
    c->state = ESTABLISHED;
    c->connected_event = true;
    c->handshake_pending = false;
}

static bool authorized(const mist_conn *c, const uint8_t peer[32])
{
    if (c->authorize)
        return c->authorize(c->authorize_context, peer) != 0;
    return mist_equal(c->peer_key, peer, 32) != 0;
}

static void accept_init(mist_conn *c, const uint8_t *packet)
{
    mist_noise noise;
    uint8_t payload[MIST_PARAMS_LEN];
    params peer;
    if (mist_noise_read_init(&noise, payload, packet + 6, c->local_key,
                            c->public_key, packet + COMMON_HEADER) &&
        read_params(payload, &peer) && authorized(c, noise.remote_static) &&
        remember_init(c, &noise)) {
        install_peer(c, peer);
        memcpy(c->cid, packet + 6, sizeof c->cid);
        memcpy(c->peer_key, noise.remote_static, sizeof c->peer_key);
        memcpy(c->init, packet, INIT_SIZE);
        c->noise = noise;
        c->state = WAIT_SERVER_RANDOM;
        c->random_event = true;
        c->handshake_at = mist_add(c->now, TENTATIVE_TIME);
    }
    mist_wipe(&noise, sizeof noise);
    mist_wipe(payload, sizeof payload);
}

static void accept_resp(mist_conn *c, const uint8_t *packet)
{
    mist_noise noise = c->noise;
    uint8_t payload[MIST_PARAMS_LEN], k1[32], k2[32];
    params peer;
    if (mist_noise_read_resp(&noise, payload, c->local_key,
                            packet + COMMON_HEADER, k1, k2) &&
        read_params(payload, &peer)) {
        install_peer(c, peer);
        install_keys(c, k1, k2);
        c->first_data = true;
        establish(c);
    }
    mist_wipe(&noise, sizeof noise);
    mist_wipe(k1, sizeof k1);
    mist_wipe(k2, sizeof k2);
    mist_wipe(payload, sizeof payload);
}

void handshake_input(mist_conn *c, const uint8_t *packet, size_t length)
{
    if (packet[5] == PACKET_INIT && length == INIT_SIZE && c->server) {
        if (c->state == WAIT_INIT)
            accept_init(c, packet);
        else if (c->state == WAIT_CONFIRM && memcmp(c->init, packet, length) == 0)
            c->handshake_pending = true;
    } else if (packet[5] == PACKET_RESP && length == RESP_SIZE &&
               c->state == WAIT_RESP && memcmp(c->cid, packet + 6, 16) == 0) {
        accept_resp(c, packet);
    }
}

static void emit_handshake(mist_conn *c, const uint8_t *packet, size_t n)
{
    memcpy(c->datagram, packet, n);
    c->datagram_len = n;
}

static void send_init(mist_conn *c)
{
    uint8_t payload[MIST_PARAMS_LEN];
    write_params(&c->config, payload);
    memcpy(c->cid, c->randomness, sizeof c->cid);
    packet_header(c->init, PACKET_INIT, c->cid);
    bool ok = mist_noise_write_init(&c->noise, c->init + COMMON_HEADER, c->cid,
                                   c->local_key, c->peer_key, c->randomness + 16, payload);
    mist_wipe(c->randomness, sizeof c->randomness);
    c->random_length = 0;
    if (!ok) {
        terminate(c, MIST_PROTOCOL_ERROR, false);
        return;
    }
    c->state = WAIT_RESP;
    c->handshake_at = mist_add(c->now, 1000000);
    emit_handshake(c, c->init, INIT_SIZE);
}

static void send_resp(mist_conn *c)
{
    uint8_t payload[MIST_PARAMS_LEN], k1[32], k2[32];
    write_params(&c->config, payload);
    packet_header(c->resp, PACKET_RESP, c->cid);
    bool ok = mist_noise_write_resp(&c->noise, c->resp + COMMON_HEADER,
                                   c->randomness, payload, k1, k2);
    mist_wipe(c->randomness, sizeof c->randomness);
    c->random_length = 0;
    if (ok) {
        install_keys(c, k2, k1);
        c->state = WAIT_CONFIRM;
        emit_handshake(c, c->resp, RESP_SIZE);
    } else {
        terminate(c, MIST_PROTOCOL_ERROR, false);
    }
    mist_wipe(k1, sizeof k1);
    mist_wipe(k2, sizeof k2);
}

void handshake_poll(mist_conn *c)
{
    switch (c->state) {
    case WAIT_CLIENT_RANDOM:
        if (c->random_length)
            send_init(c);
        break;
    case WAIT_SERVER_RANDOM:
        if (c->random_length)
            send_resp(c);
        break;
    case WAIT_RESP:
        if (c->now >= c->handshake_at) {
            ++c->handshake_retries;
            emit_handshake(c, c->init, INIT_SIZE);
            c->handshake_at = mist_add(c->now, UINT64_C(1000000) << c->handshake_retries);
        }
        break;
    case WAIT_CONFIRM:
        if (c->handshake_pending) {
            c->handshake_pending = false;
            emit_handshake(c, c->resp, RESP_SIZE);
        }
        break;
    default:
        break;
    }
}
