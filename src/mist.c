#include "internal.h"

void mist_config_default(mist_config *cfg)
{
    if (!cfg)
        return;
    *cfg = (mist_config){
        .max_send_buffer = 1024 * 1024,
        .max_recv_buffer = 1024 * 1024,
        .initial_max_data = 1024 * 1024,
        .initial_max_stream_data = 64 * 1024,
        .max_streams_bidi = 16,
        .max_streams_uni = 64
    };
}

void mist_public_key(uint8_t public_key[32], const uint8_t private_key[32])
{
    mist_x25519_public(public_key, private_key);
}

static mist_conn *create(const mist_config *cfg, const uint8_t local[32],
                         const uint8_t peer[32], bool server)
{
    mist_config defaults;
    if (!cfg) {
        mist_config_default(&defaults);
        cfg = &defaults;
    }
    if (!local || cfg->max_send_buffer > MIST_MAX_WINDOW ||
        cfg->max_recv_buffer > MIST_MAX_WINDOW ||
        cfg->initial_max_data > cfg->max_recv_buffer ||
        cfg->initial_max_stream_data > MIST_MAX_WINDOW ||
        cfg->max_streams_bidi > MIST_MAX_INITIAL_STREAMS ||
        cfg->max_streams_uni > MIST_MAX_INITIAL_STREAMS)
        return NULL;
    mist_conn *c = calloc(1, sizeof *c);
    if (!c)
        return NULL;
    c->server = server;
    c->state = server ? WAIT_INIT : WAIT_CLIENT_RANDOM;
    c->random_event = !server;
    c->config = *cfg;
    c->rx_credit.limit = c->rx_credit.sent = c->rx_credit.acked = cfg->initial_max_data;
    c->stats.cwnd = 10 * MIST_MAX_DATAGRAM;
    c->stats.ssthresh = UINT64_MAX;
    c->ack_at = c->pto_at = NEVER;
    for (unsigned i = 0; i < 4; ++i) {
        stream_class *sc = &c->classes[i];
        uint32_t count = is_message(i) ? cfg->max_streams_uni : cfg->max_streams_bidi;
        sc->capacity = is_local(c, i) ? MIST_MAX_INITIAL_STREAMS : count;
        if (!is_local(c, i))
            sc->rx_credit.limit = sc->rx_credit.sent = sc->rx_credit.acked = count;
        if (sc->capacity) {
            sc->slots = calloc(sc->capacity, sizeof *sc->slots);
            if (!sc->slots) {
                mist_destroy(c);
                return NULL;
            }
        }
    }
    memcpy(c->local_key, local, 32);
    if (peer)
        memcpy(c->peer_key, peer, 32);
    mist_x25519_public(c->public_key, local);
    return c;
}

mist_conn *mist_client_create(const mist_config *cfg, const uint8_t local[32],
                              const uint8_t responder[32])
{
    return responder ? create(cfg, local, responder, false) : NULL;
}

mist_conn *mist_server_create(const mist_config *cfg, const uint8_t local[32],
                              const uint8_t allowed_initiator[32])
{
    return allowed_initiator ? create(cfg, local, allowed_initiator, true) : NULL;
}

mist_conn *mist_server_create_with_policy(const mist_config *cfg,
                                          const uint8_t local[32],
                                          mist_authorize_fn authorize, void *context)
{
    if (!authorize)
        return NULL;
    mist_conn *c = create(cfg, local, NULL, true);
    if (c) {
        c->authorize = authorize;
        c->authorize_context = context;
    }
    return c;
}

void mist_destroy(mist_conn *c)
{
    if (!c)
        return;
    clean_streams(c);
    mist_wipe(c, sizeof *c);
    free(c);
}

int mist_supply_random(mist_conn *c, const uint8_t *bytes, size_t n)
{
    if (!c || !bytes || c->random_length ||
        !((c->state == WAIT_CLIENT_RANDOM && n == 48) ||
          (c->state == WAIT_SERVER_RANDOM && n == 32)))
        return MIST_INVALID;
    memcpy(c->randomness, bytes, n);
    c->random_length = n;
    c->random_event = false;
    return MIST_OK;
}

bool has_transport(const mist_conn *c)
{
    return c->state == WAIT_CONFIRM || c->state == ESTABLISHED || c->state == CLOSING;
}

static void discard_application_state(mist_conn *c)
{
    clean_streams(c);
    c->datagram_len = 0;
    c->send_used = 0;
    c->chunks = 0;
    c->stats.bytes_in_flight = 0;
    c->flight_packets = 0;
    c->pto_at = NEVER;
    memset(c->sent, 0, sizeof c->sent);
    c->sent_valid = c->sent_flight = (slot_set){0};
    c->connected_event = c->writable_event = c->random_event = false;
}

void terminate(mist_conn *c, uint16_t code, bool remote)
{
    discard_application_state(c);
    mist_wipe(c->local_key, sizeof c->local_key);
    mist_wipe(c->randomness, sizeof c->randomness);
    mist_wipe(c->send_key, sizeof c->send_key);
    mist_wipe(c->recv_key, sizeof c->recv_key);
    mist_wipe(&c->noise, sizeof c->noise);
    c->close_code = code;
    c->remote_close = remote;
    c->state = CLOSED;
    c->closed_event = true;
}

void fail_connection(mist_conn *c, uint16_t code)
{
    if (c->state == CLOSED || c->state == CLOSING)
        return;
    if (!has_transport(c) || c->tx_number >= PACKET_LIMIT || c->now >= c->expire_at) {
        terminate(c, code, false);
        return;
    }
    discard_application_state(c);
    c->state = CLOSING;
    c->close_code = code;
    c->close_at = c->now;
}

int mist_close(mist_conn *c, uint16_t code)
{
    if (!c || c->state == CLOSED || c->state == CLOSING)
        return MIST_INVALID;
    fail_connection(c, code);
    return MIST_OK;
}

static bool set_clock(mist_conn *c, uint64_t now)
{
    if (now == NEVER || (c->clock_set && now < c->now))
        return false;
    c->clock_set = true;
    c->now = now;
    if ((c->state == WAIT_SERVER_RANDOM || c->state == WAIT_CONFIRM) &&
        now >= c->handshake_at) {
        terminate(c, MIST_SESSION_EXPIRED, false);
    } else if (c->state == WAIT_RESP && c->handshake_retries == 5 &&
               now >= c->handshake_at) {
        terminate(c, MIST_SESSION_EXPIRED, false);
    } else if (has_transport(c)) {
        if (!c->reconnect_reported &&
            (now >= c->reconnect_at || c->tx_number >= PACKET_LIMIT - 1024)) {
            c->reconnect_reported = true;
            c->reconnect_event = true;
        }
        if (now >= c->expire_at || c->tx_number >= PACKET_LIMIT)
            terminate(c, MIST_SESSION_EXPIRED, false);
        else if (c->state == ESTABLISHED && now >= mist_add(c->last_rx, IDLE_TIME))
            terminate(c, MIST_SESSION_EXPIRED, false);
    }
    return true;
}

int mist_input(mist_conn *c, const uint8_t *packet, size_t length, uint64_t now)
{
    if (!c || (!packet && length) || !set_clock(c, now))
        return MIST_INVALID;
    if (c->state == CLOSED || length < COMMON_HEADER || length > MIST_MAX_DATAGRAM ||
        memcmp(packet, "MST1", 4) || packet[4] != 1)
        return MIST_OK;
    if (packet[5] == PACKET_INIT || packet[5] == PACKET_RESP) {
        handshake_input(c, packet, length);
    } else if (packet[5] == PACKET_DATA && has_transport(c) &&
               length >= DATA_HEADER + TAG_SIZE && !memcmp(packet + 6, c->cid, 16)) {
        data_input(c, packet, length);
    }
    return MIST_OK;
}

int mist_poll(mist_conn *c, uint64_t now)
{
    if (!c || !set_clock(c, now))
        return MIST_INVALID;
    if (!c->datagram_len) {
        if (c->state == ESTABLISHED || c->state == CLOSING)
            data_poll(c);
        else
            handshake_poll(c);
    }
    return MIST_OK;
}

int mist_next_event(mist_conn *c, mist_event *e)
{
    if (!c || !e)
        return MIST_INVALID;
    *e = (mist_event){0};
    if (c->datagram_len) {
        e->type = MIST_SEND_DATAGRAM;
        e->length = c->datagram_len;
        e->data = c->datagram;
        c->datagram_len = 0;
    } else if (c->random_event) {
        e->type = MIST_NEED_RANDOM;
        e->length = c->server ? 32 : 48;
        c->random_event = false;
    } else if (c->connected_event) {
        e->type = MIST_CONNECTED;
        e->data = c->peer_key;
        e->length = sizeof c->peer_key;
        c->connected_event = false;
    } else if (c->reconnect_event) {
        e->type = MIST_RECONNECT_REQUIRED;
        c->reconnect_event = false;
    } else if (c->closed_event) {
        e->type = MIST_CLOSED;
        e->close_code = c->close_code;
        e->remote = c->remote_close;
        c->closed_event = false;
    } else if (c->writable_event) {
        e->type = MIST_WRITABLE;
        c->writable_event = false;
    } else if (c->state != ESTABLISHED || !stream_event(c, e)) {
        return 0;
    }
    return 1;
}

uint64_t mist_next_deadline(const mist_conn *c)
{
    if (!c || c->state == CLOSED)
        return NEVER;
    if (c->datagram_len)
        return c->now;
    switch (c->state) {
    case WAIT_CLIENT_RANDOM:
        return c->random_length ? c->now : NEVER;
    case WAIT_INIT:
        return NEVER;
    case WAIT_SERVER_RANDOM:
        return c->random_length ? c->now : c->handshake_at;
    case WAIT_RESP:
        return c->handshake_at;
    case WAIT_CONFIRM:
        return c->handshake_pending ? c->now : c->handshake_at;
    case ESTABLISHED:
    case CLOSING: {
        uint64_t next = c->expire_at;
        if (!c->reconnect_reported) {
            next = mist_min(next, c->reconnect_at);
            if (c->tx_number >= PACKET_LIMIT - 1024)
                next = c->now;
        }
        if (c->tx_number >= PACKET_LIMIT)
            return c->now;
        if (c->state == CLOSING)
            return mist_max(c->now, mist_min(next, c->close_at));
        next = mist_min(next, mist_add(c->last_rx, IDLE_TIME));
        return mist_max(c->now, mist_min(next, data_deadline(c)));
    }
    default:
        return NEVER;
    }
}

int mist_get_stats(const mist_conn *c, mist_stats *stats)
{
    if (!c || !stats)
        return MIST_INVALID;
    *stats = c->stats;
    stats->next_packet_number = c->tx_number;
    return MIST_OK;
}
