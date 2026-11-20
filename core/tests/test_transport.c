#include "internal.h"

#include <assert.h>
#include <stdio.h>

typedef struct {
    mist_conn *client, *server;
    uint8_t entropy[48];
    uint64_t now;
} pair;

static pair endpoints(const mist_config *cfg)
{
    const uint8_t a[32] = {11, 21, 31}, b[32] = {34, 44, 54};
    uint8_t ap[32], bp[32];
    mist_public_key(ap, a);
    mist_public_key(bp, b);
    pair p = {mist_client_create(cfg, a, bp), mist_server_create(cfg, b, ap), {13, 23}, 0};
    assert(p.client && p.server);
    return p;
}

static void destroy(pair p)
{
    mist_destroy(p.client);
    mist_destroy(p.server);
}

static mist_event event(mist_conn *c, mist_event_type type)
{
    mist_event e;
    assert(mist_next_event(c, &e) == 1 && e.type == type);
    return e;
}

static void empty(mist_conn *c)
{
    mist_event e;
    assert(mist_next_event(c, &e) == 0);
}

static void feed(mist_conn *c, const uint8_t *data, size_t n, uint64_t now)
{
    assert(mist_input(c, data, n, now) == MIST_OK);
}

static void poll_at(mist_conn *c, uint64_t now)
{
    assert(mist_poll(c, now) == MIST_OK);
}

static size_t output(mist_conn *c, uint64_t now, uint8_t dst[MIST_MAX_DATAGRAM])
{
    poll_at(c, now);
    mist_event e = event(c, MIST_SEND_DATAGRAM);
    memcpy(dst, e.data, e.length);
    return e.length;
}

static size_t init(pair *p, uint8_t out[MIST_MAX_DATAGRAM])
{
    assert(event(p->client, MIST_NEED_RANDOM).length == 48);
    assert(mist_supply_random(p->client, p->entropy, 47) == MIST_INVALID);
    assert(mist_supply_random(p->client, p->entropy, 48) == MIST_OK);
    assert(mist_supply_random(p->client, p->entropy, 48) == MIST_INVALID);
    return output(p->client, p->now, out);
}

static void handshake(pair *p)
{
    uint8_t datagram[MIST_MAX_DATAGRAM];
    size_t n = init(p, datagram);
    feed(p->server, datagram, n, p->now += 10000);
    assert(event(p->server, MIST_NEED_RANDOM).length == 32);
    assert(mist_supply_random(p->server, p->entropy, 32) == MIST_OK);
    n = output(p->server, p->now, datagram);
    uint32_t id;
    assert(mist_open_stream(p->server, &id) == MIST_INVALID);
    feed(p->client, datagram, n, p->now += 10000);
    n = output(p->client, p->now, datagram);
    event(p->client, MIST_CONNECTED);
    feed(p->server, datagram, n, p->now += 10000);
    event(p->server, MIST_CONNECTED);
    n = output(p->server, p->now, datagram);
    feed(p->client, datagram, n, p->now += 10000);
    empty(p->client);
    empty(p->server);
}

static void handshake_rules(void)
{
    uint8_t packet[MIST_MAX_DATAGRAM], resp[MIST_MAX_DATAGRAM], copy[MIST_MAX_DATAGRAM];
    pair p = endpoints(NULL);
    size_t n = init(&p, packet);
    assert(n == INIT_SIZE);
    assert(mist_next_deadline(p.client) == 1000000);
    assert(output(p.client, 1000000, copy) == n && !memcmp(packet, copy, n));

    uint8_t different[32] = {117}, allowed[32] = {119};
    mist_conn *unauthorized = mist_server_create(NULL, different, allowed);
    assert(unauthorized);
    feed(unauthorized, packet, n, 1000000);
    empty(unauthorized);
    mist_destroy(unauthorized);

    /* Same responder static key, deliberately wrong allowlist. */
    const uint8_t b[32] = {34, 44, 54};
    unauthorized = mist_server_create(NULL, b, allowed);
    feed(unauthorized, packet, n, 1000000);
    empty(unauthorized);
    assert(unauthorized->state == WAIT_INIT);
    mist_destroy(unauthorized);

    packet[n - 1] ^= 1;
    feed(p.server, packet, n, 1000000);
    empty(p.server);
    packet[n - 1] ^= 1;
    feed(p.server, packet, n, 1000000);
    event(p.server, MIST_NEED_RANDOM);
    feed(p.server, packet, n, 1000000);
    empty(p.server);
    assert(mist_supply_random(p.server, p.entropy, 32) == MIST_OK);
    size_t rn = output(p.server, 1000000, resp);
    assert(rn == RESP_SIZE);
    packet[n - 1] ^= 1;
    feed(p.server, packet, n, 2000000);
    poll_at(p.server, 2000000);
    empty(p.server);
    packet[n - 1] ^= 1;
    feed(p.server, packet, n, 2000000);
    assert(output(p.server, 2000000, copy) == rn && !memcmp(resp, copy, rn));
    feed(p.client, resp, rn, 2000000);
    event(p.client, MIST_CONNECTED);
    poll_at(p.server, 41000000);
    assert(event(p.server, MIST_CLOSED).close_code == MIST_SESSION_EXPIRED);
    destroy(p);

    p = endpoints(NULL);
    n = init(&p, packet);
    for (uint64_t t = 1; t <= 31; t = t * 2 + 1)
        assert(output(p.client, t * 1000000, copy) == n && !memcmp(packet, copy, n));
    poll_at(p.client, 63000000);
    assert(event(p.client, MIST_CLOSED).close_code == MIST_SESSION_EXPIRED);
    destroy(p);
}

static void handshake_replay_cache(void)
{
    mist_config cfg;
    mist_config_default(&cfg);
    cfg.replay_cache = mist_replay_cache_create(4);
    assert(cfg.replay_cache);
    pair p = endpoints(&cfg), q = endpoints(&cfg);
    uint8_t packet[MIST_MAX_DATAGRAM];
    size_t n = init(&p, packet);
    feed(p.server, packet, n, 100);
    event(p.server, MIST_NEED_RANDOM);
    feed(q.server, packet, n, 1000);
    empty(q.server);
    feed(q.server, packet, n, 120001000);
    event(q.server, MIST_NEED_RANDOM);
    destroy(p);
    destroy(q);
    mist_replay_cache_destroy(cfg.replay_cache);
}

static size_t stream_frame(uint8_t *out, uint32_t id, uint64_t offset, bool fin,
                           const void *data, size_t n)
{
    out[0] = FRAME_STREAM;
    write_be(out + 1, id, 4);
    write_be(out + 5, offset, 8);
    out[13] = (uint8_t)fin;
    write_be(out + 14, n, 2);
    if (n)
        memcpy(out + STREAM_HEADER, data, n);
    return STREAM_HEADER + n;
}

static void inject(pair *p, uint64_t pn, const uint8_t *frames, size_t n, bool corrupt)
{
    uint8_t packet[MIST_MAX_DATAGRAM], nonce[12];
    assert(n <= MAX_PLAINTEXT);
    packet_header(packet, PACKET_DATA, p->client->cid);
    write_be(packet + COMMON_HEADER, pn, 8);
    mist_nonce(nonce, pn);
    mist_aead_seal(packet + DATA_HEADER, frames, n, packet, DATA_HEADER,
                   p->client->send_key, nonce);
    size_t length = DATA_HEADER + n + TAG_SIZE;
    if (corrupt)
        packet[length - 1] ^= 1;
    feed(p->server, packet, length, p->now += 10);
}

static void expect_closing(pair *p, uint16_t code)
{
    uint8_t packet[MIST_MAX_DATAGRAM], plaintext[3], nonce[12];
    size_t n = output(p->server, p->now, packet);
    assert(n == DATA_HEADER + 3 + TAG_SIZE);
    mist_nonce(nonce, read_be(packet + COMMON_HEADER, 8));
    assert(mist_aead_open(plaintext, packet + DATA_HEADER, sizeof plaintext,
                          packet, DATA_HEADER, p->client->recv_key, nonce));
    assert(plaintext[0] == FRAME_CLOSE && read_be(plaintext + 1, 2) == code);
    feed(p->client, packet, n, ++p->now);
    mist_event e = event(p->client, MIST_CLOSED);
    assert(e.remote && e.close_code == code);
    for (unsigned i = 0; i < 2; ++i)
        output(p->server, p->now += 1000000, packet);
    poll_at(p->server, p->now += 1000000);
    e = event(p->server, MIST_CLOSED);
    assert(!e.remote && e.close_code == code);
}

static void reordering_and_transaction(void)
{
    pair p = endpoints(NULL);
    handshake(&p);
    uint8_t f[MAX_PLAINTEXT];
    size_t n = stream_frame(f, 0, 3, true, "def", 3);
    inject(&p, 3, f, n, true);
    empty(p.server);
    inject(&p, 3, f, n, false);
    assert(event(p.server, MIST_STREAM_OPEN).stream_id == 0);
    assert(mist_next_deadline(p.server) == p.now);
    empty(p.server);
    n = stream_frame(f, 4, 0, true, "xyz", 3);
    inject(&p, 2, f, n, false);
    assert(event(p.server, MIST_STREAM_OPEN).stream_id == 4);
    mist_event e = event(p.server, MIST_STREAM_READABLE);
    assert(e.stream_id == 4 && e.length == 3 && !memcmp(e.data, "xyz", 3));
    assert(mist_stream_consume(p.server, 4, 4) == MIST_INVALID);
    assert(mist_stream_consume(p.server, 4, 1) == MIST_OK);
    e = event(p.server, MIST_STREAM_READABLE);
    assert(e.length == 2 && !memcmp(e.data, "yz", 2));
    assert(mist_stream_consume(p.server, 4, 2) == MIST_OK);
    assert(event(p.server, MIST_STREAM_FIN).stream_id == 4);
    n = stream_frame(f, 0, 0, false, "abcd", 4);
    inject(&p, 1, f, n, false);
    e = event(p.server, MIST_STREAM_READABLE);
    assert(e.stream_id == 0 && e.length == 6 && !memcmp(e.data, "abcdef", 6));
    assert(event(p.server, MIST_STREAM_FIN).stream_id == 0);
    inject(&p, 1, f, n, false);
    empty(p.server);

    n = stream_frame(f, 8, 0, false, "new", 3);
    n += stream_frame(f + n, 0, 1, false, "Q", 1);
    inject(&p, 4, f, n, false);
    assert(!replay_contains(p.server, 4) && p.server->rx_accounted == 9);
    empty(p.server);
    expect_closing(&p, MIST_PROTOCOL_ERROR);
    destroy(p);

    p = endpoints(NULL);
    handshake(&p);
    n = stream_frame(f, 0, 0, false, "a", 1);
    n += stream_frame(f + n, 0, 0, false, "b", 1);
    inject(&p, 1, f, n, false);
    assert(p.server->rx_accounted == 0);
    expect_closing(&p, MIST_PROTOCOL_ERROR);
    destroy(p);
}

static void receive_bitmap_boundaries(void)
{
    pair p = endpoints(NULL);
    handshake(&p);
    uint8_t data[PAGE_SIZE + 21], f[MAX_PLAINTEXT];
    for (size_t i = 0; i < sizeof data; ++i)
        data[i] = (uint8_t)(i * 37u);

    size_t n = stream_frame(f, 0, 63, false, data + 63, PAGE_SIZE + 4 - 63);
    n += stream_frame(f + n, 0, PAGE_SIZE + 8, true, data + PAGE_SIZE + 8, 13);
    inject(&p, 1, f, n, false);
    event(p.server, MIST_STREAM_OPEN);
    empty(p.server);

    n = stream_frame(f, 0, 0, false, data, PAGE_SIZE + 1);
    inject(&p, 2, f, n, false);
    mist_event e = event(p.server, MIST_STREAM_READABLE);
    assert(e.length == PAGE_SIZE && !memcmp(e.data, data, e.length));
    assert(mist_stream_consume(p.server, 0, e.length) == MIST_OK);
    e = event(p.server, MIST_STREAM_READABLE);
    assert(e.length == 4 && !memcmp(e.data, data + PAGE_SIZE, e.length));
    assert(mist_stream_consume(p.server, 0, e.length) == MIST_OK);
    empty(p.server);

    n = stream_frame(f, 0, PAGE_SIZE + 4, false, data + PAGE_SIZE + 4, 17);
    inject(&p, 3, f, n, false);
    e = event(p.server, MIST_STREAM_READABLE);
    assert(e.length == 17 && !memcmp(e.data, data + PAGE_SIZE + 4, e.length));
    assert(mist_stream_consume(p.server, 0, e.length) == MIST_OK);
    event(p.server, MIST_STREAM_FIN);

    data[65] ^= 1;
    n = stream_frame(f, 0, 0, false, data, 128);
    inject(&p, 4, f, n, false);
    assert(!replay_contains(p.server, 4));
    expect_closing(&p, MIST_PROTOCOL_ERROR);
    destroy(p);
}

static void flow_and_ack_violations(void)
{
    mist_config cfg;
    mist_config_default(&cfg);
    cfg.initial_max_data = 24;
    cfg.initial_max_stream_data = 16;
    cfg.max_streams_bidi = 1;
    uint8_t f[MAX_PLAINTEXT], bytes[16] = {0};
    for (unsigned test = 0; test < 9; ++test) {
        cfg.max_streams_bidi = test == 2 ? 2 : 1;
        pair p = endpoints(&cfg);
        handshake(&p);
        size_t n = 0;
        uint16_t error = MIST_PROTOCOL_ERROR;
        switch (test) {
        case 0:
            n = stream_frame(f, 4, 0, false, bytes, 1);
            error = MIST_FLOW_CONTROL;
            break;
        case 1:
            n = stream_frame(f, 0, 16, false, bytes, 1);
            error = MIST_FLOW_CONTROL;
            break;
        case 2:
            n = stream_frame(f, 0, 15, false, bytes, 1);
            n += stream_frame(f + n, 4, 8, false, bytes, 1);
            error = MIST_FLOW_CONTROL;
            break;
        case 3:
            n = stream_frame(f, 0, UINT64_MAX, false, bytes, 1);
            break;
        case 4:
            n = stream_frame(f, 3, 0, true, bytes, 1);
            break;
        case 5:
            n = stream_frame(f, 2, 0, false, bytes, 1);
            break;
        case 6:
            n = stream_frame(f, 0, 0, true, bytes, 2);
            n += stream_frame(f + n, 0, 0, true, bytes, 1);
            break;
        case 7:
            memset(f, 0, 30);
            f[0] = FRAME_ACK;
            f[13] = 1;
            write_be(f + 1, 1, 8); /* Only the server's PN 0 has been sent. */
            write_be(f + 22, 1, 8);
            n = 30;
            break;
        case 8:
            n = stream_frame(f, 0, 0, false, bytes, 1);
            f[n++] = 0xff;
            break;
        }
        inject(&p, 1, f, n, false);
        assert(p.server->rx_accounted == 0 && !replay_contains(p.server, 1));
        empty(p.server);
        expect_closing(&p, error);
        destroy(p);
    }
}

static void messages_and_replay_window(void)
{
    pair p = endpoints(NULL);
    handshake(&p);
    uint8_t f[MAX_PLAINTEXT];
    size_t n = stream_frame(f, 6, 0, true, "two", 3);
    inject(&p, 2, f, n, false);
    mist_event e = event(p.server, MIST_MESSAGE);
    assert(e.stream_id == 6 && e.length == 3 && !memcmp(e.data, "two", 3));
    assert(mist_message_consume(p.server, 6) == MIST_OK);
    inject(&p, 3, f, n, false);
    empty(p.server);
    assert(p.server->classes[2].retired == 0);
    n = stream_frame(f, 2, 0, true, NULL, 0);
    inject(&p, 1, f, n, false);
    e = event(p.server, MIST_MESSAGE);
    assert(e.stream_id == 2 && e.length == 0);
    assert(mist_message_consume(p.server, 2) == MIST_OK);
    assert(p.server->classes[2].retired == 2);
    inject(&p, 4, f, n, false);
    empty(p.server);

    f[0] = FRAME_PING;
    inject(&p, 2052, f, 1, false);
    assert(replay_seen_or_old(p.server, 4));
    assert(!replay_seen_or_old(p.server, 5));
    n = stream_frame(f, 10, 0, true, "late", 4);
    inject(&p, 4, f, n, false);
    empty(p.server);
    inject(&p, 5, f, n, false);
    assert(event(p.server, MIST_MESSAGE).stream_id == 10);
    destroy(p);
}

static void pto_and_pacing(void)
{
    pair p = endpoints(NULL);
    handshake(&p);
    uint8_t packet[MIST_MAX_DATAGRAM], retry[MIST_MAX_DATAGRAM];
    uint8_t body[1024] = {42};
    mist_stats initial, after;
    assert(mist_get_stats(p.client, &initial) == MIST_OK);
    assert(initial.cwnd > 12000 && initial.smoothed_rtt_us == 20000);
    assert(mist_send_message(p.client, body, sizeof body) == MIST_OK);
    size_t n = output(p.client, p.now, packet);
    assert(n == 1086);
    assert(mist_send_message(p.client, NULL, 0) == MIST_OK);
    uint64_t next = mist_next_deadline(p.client);
    assert(next > p.now && next < p.now + 20000);
    poll_at(p.client, next - 1);
    empty(p.client);
    output(p.client, next, retry); /* Drop the entire flight. */
    uint64_t pto = mist_next_deadline(p.client);
    assert(pto > next && pto < p.now + 1000000);
    assert(output(p.client, pto, retry) == n);
    assert(read_be(retry + COMMON_HEADER, 8) > read_be(packet + COMMON_HEADER, 8));
    assert(memcmp(retry + DATA_HEADER, packet + DATA_HEADER, n - DATA_HEADER));
    feed(p.server, retry, n, pto + 10000);
    mist_event e = event(p.server, MIST_MESSAGE);
    assert(e.length == sizeof body && !memcmp(e.data, body, sizeof body));
    assert(mist_message_consume(p.server, e.stream_id) == MIST_OK);
    n = output(p.server, pto + 10000, packet);
    feed(p.client, packet, n, pto + 20000);
    assert(mist_get_stats(p.client, &after) == MIST_OK);
    assert(after.probe_timeouts == 1 && after.packets_lost > 0);
    assert(after.cwnd < initial.cwnd && after.cwnd >= MIN_CWND);
    assert(after.min_rtt_us == 20000 && after.smoothed_rtt_us == 20000);
    destroy(p);
}

typedef struct {
    uint8_t expected[32];
    unsigned calls;
} authorization;

static int allow_peer(void *context, const uint8_t key[32])
{
    authorization *policy = context;
    ++policy->calls;
    return memcmp(policy->expected, key, sizeof policy->expected) == 0;
}

static void authorization_policy(void)
{
    pair p = endpoints(NULL);
    const uint8_t a[32] = {11, 21, 31}, b[32] = {34, 44, 54};
    authorization policy = {0};
    mist_public_key(policy.expected, a);
    mist_destroy(p.server);
    p.server = mist_server_create_with_policy(NULL, b, allow_peer, &policy);
    assert(p.server);

    uint8_t packet[MIST_MAX_DATAGRAM];
    size_t n = init(&p, packet);
    packet[n - 1] ^= 1;
    feed(p.server, packet, n, 0);
    assert(!policy.calls);
    packet[n - 1] ^= 1;
    feed(p.server, packet, n, 0);
    assert(policy.calls == 1);
    event(p.server, MIST_NEED_RANDOM);
    assert(mist_supply_random(p.server, p.entropy, 32) == MIST_OK);
    n = output(p.server, 0, packet);
    feed(p.client, packet, n, 0);
    n = output(p.client, 0, packet);
    assert(event(p.client, MIST_CONNECTED).length == 32);
    feed(p.server, packet, n, 0);
    mist_event e = event(p.server, MIST_CONNECTED);
    assert(e.length == 32 && !memcmp(e.data, policy.expected, 32));
    destroy(p);
}

static void atomic_flow_feedback(void)
{
    mist_config cfg;
    mist_config_default(&cfg);
    cfg.initial_max_data = cfg.initial_max_stream_data = 1024;
    cfg.max_recv_buffer = 1024;
    cfg.max_streams_uni = 1;
    pair p = endpoints(&cfg);
    handshake(&p);
    uint8_t data[800] = {47}, packet[MIST_MAX_DATAGRAM];
    assert(mist_send_message(p.client, data, 400) == MIST_OK);
    assert(mist_send_message(p.client, data, 800) == MIST_AGAIN);
    size_t n = output(p.client, p.now, packet);
    feed(p.server, packet, n, p.now += 10000);
    mist_event e = event(p.server, MIST_MESSAGE);
    assert(e.length == 400 && mist_message_consume(p.server, e.stream_id) == MIST_OK);
    uint64_t update = p.now + ACK_DELAY;
    n = output(p.server, p.now, packet);
    feed(p.client, packet, n, p.now += 10000);
    event(p.client, MIST_WRITABLE);
    assert(mist_send_message(p.client, data, 800) == MIST_OK);
    poll_at(p.client, update - 1);
    empty(p.client);
    assert(p.client->tx_accounted == 400 && p.client->tx_limit == 1024);
    assert(mist_next_deadline(p.server) == update);
    n = output(p.server, update, packet);
    feed(p.client, packet, n, update + 10000);
    n = output(p.client, update + 10000, packet);
    feed(p.server, packet, n, update + 20000);
    e = event(p.server, MIST_MESSAGE);
    assert(e.length == sizeof data && !memcmp(e.data, data, sizeof data));
    destroy(p);
}

static void ack_ranges_and_deadlines(void)
{
    pair p = endpoints(NULL);
    handshake(&p);
    uint8_t f = FRAME_PING, packet[MIST_MAX_DATAGRAM], plaintext[MAX_PLAINTEXT], nonce[12];
    inject(&p, 1, &f, 1, false);
    uint64_t deadline = p.now + ACK_DELAY;
    assert(mist_next_deadline(p.server) == deadline);
    poll_at(p.server, deadline - 1);
    empty(p.server);
    size_t n = output(p.server, deadline, packet);
    mist_nonce(nonce, read_be(packet + COMMON_HEADER, 8));
    assert(mist_aead_open(plaintext, packet + DATA_HEADER, n - DATA_HEADER - TAG_SIZE,
                          packet, DATA_HEADER, p.client->recv_key, nonce));
    assert(plaintext[0] == FRAME_ACK && read_be(plaintext + 9, 4) == ACK_DELAY);

    p.now = deadline;
    for (uint64_t pn = 3; pn < 43; pn += 2)
        inject(&p, pn, &f, 1, false);
    assert(mist_next_deadline(p.server) == p.now);
    n = output(p.server, p.now, packet);
    mist_nonce(nonce, read_be(packet + COMMON_HEADER, 8));
    assert(mist_aead_open(plaintext, packet + DATA_HEADER, n - DATA_HEADER - TAG_SIZE,
                          packet, DATA_HEADER, p.client->recv_key, nonce));
    assert(plaintext[0] == FRAME_ACK && plaintext[13] == ACK_RANGES);
    for (unsigned i = 0; i < ACK_RANGES; ++i) {
        assert(read_be(plaintext + 14 + i * 16, 8) == 41 - 2 * i);
        assert(read_be(plaintext + 22 + i * 16, 8) == 41 - 2 * i);
    }
    inject(&p, 43, &f, 1, true);
    uint64_t idle = p.server->last_rx + IDLE_TIME;
    poll_at(p.server, idle);
    assert(event(p.server, MIST_CLOSED).close_code == MIST_SESSION_EXPIRED);
    destroy(p);
}

static void ack_bitmap_wrap(void)
{
    pair p = endpoints(NULL);
    for (uint64_t n = 0; n <= 2100; ++n) {
        if (n != 2000 && n != 2001 && n != 2047 && n != 2048)
            replay_accept(p.server, n, false, false);
    }

    uint8_t encoded[14 + ACK_RANGES * 16];
    size_t size = encode_ack(p.server, encoded);
    p.client->tx_number = 2101;
    ack_frame ack;
    assert(decode_ack(p.client, encoded, size, &ack) && ack.count == 3);
    assert(ack.range[0].start == 2049 && ack.range[0].end == 2100);
    assert(ack.range[1].start == 2002 && ack.range[1].end == 2046);
    assert(ack.range[2].start == 53 && ack.range[2].end == 1999);
    destroy(p);
}

static void loss_history_wrap(void)
{
    pair p = endpoints(NULL);
    handshake(&p);
    mist_conn *c = p.client;
    assert(c->flight_packets == 0);
    c->sent_cursor = TX_HISTORY - 2;
    const frame_ref ping = {FRAME_PING, 0, 0};
    for (uint64_t n = 10; n <= 14; n += 2) {
        c->now += 500;
        c->tx_number = n;
        record_sent(c, 47, ping, false);
    }
    ++c->tx_number;
    assert(c->sent_cursor == 1);

    /* Packet 13 was ACK-only. Its ACK can still establish a loss threshold. */
    ack_frame ack = {.largest = 13, .count = 1, .range = {{13, 13}}};
    process_acks(c, &ack, 1);
    assert(c->flight_packets == 2 && c->stats.packets_lost == 1);
    uint64_t deadline = loss_deadline(c);
    assert(deadline > c->now && deadline != NEVER);
    c->now = deadline;
    detect_loss(c);
    assert(c->flight_packets == 1 && c->stats.packets_lost == 2);
    assert(loss_deadline(c) == NEVER);

    ack = (ack_frame){.largest = 12, .count = 1, .range = {{10, 12}}};
    process_acks(c, &ack, 1);
    assert(c->flight_packets == 1 && c->stats.bytes_in_flight == 47);
    assert(slot_at_or_after(&c->sent_valid, 1) == NO_SLOT);
    ack = (ack_frame){.largest = 14, .count = 1, .range = {{14, 14}}};
    process_acks(c, &ack, 1);
    assert(c->flight_packets == 0 && c->pto_at == NEVER);
    destroy(p);
}

static void session_limits(void)
{
    pair p = endpoints(NULL);
    handshake(&p);
    /* Jump close to the packet cap without sending four billion packets. */
    p.client->tx_number = PACKET_LIMIT - 1024;
    assert(mist_next_deadline(p.client) == p.now);
    poll_at(p.client, p.now);
    event(p.client, MIST_RECONNECT_REQUIRED);
    empty(p.client);
    p.client->tx_number = PACKET_LIMIT - 1;
    assert(mist_send_message(p.client, NULL, 0) == MIST_OK);
    uint8_t packet[MIST_MAX_DATAGRAM];
    output(p.client, p.now, packet);
    assert(read_be(packet + COMMON_HEADER, 8) == PACKET_LIMIT - 1);
    assert(mist_next_deadline(p.client) == p.now);
    poll_at(p.client, p.now);
    assert(event(p.client, MIST_CLOSED).close_code == MIST_SESSION_EXPIRED);
    destroy(p);

    p = endpoints(NULL);
    handshake(&p);
    uint64_t warn = p.client->reconnect_at, expire = p.client->expire_at;
    assert(expire - warn == IDLE_TIME);
    p.client->last_rx = warn - 1;
    assert(mist_next_deadline(p.client) == warn);
    poll_at(p.client, warn);
    event(p.client, MIST_RECONNECT_REQUIRED);
    p.client->last_rx = expire - 1;
    poll_at(p.client, expire);
    assert(event(p.client, MIST_CLOSED).close_code == MIST_SESSION_EXPIRED);
    destroy(p);
}

static void scheduler_sparse_slots(void)
{
    mist_config cfg;
    mist_config_default(&cfg);
    cfg.max_streams_bidi = MIST_MAX_INITIAL_STREAMS;
    cfg.initial_max_stream_data = 4;
    pair p = endpoints(&cfg);
    handshake(&p);

    /* Leave most scheduler slots empty, including whole bitmap words. */
    const uint32_t ids[] = {0, 4 * 64, 4 * (MIST_MAX_INITIAL_STREAMS - 1)};
    uint8_t frames[MAX_PLAINTEXT];
    size_t n = 0;
    for (unsigned i = 0; i < 3; ++i)
        n += stream_frame(frames + n, ids[i], 0, false, NULL, 0);
    inject(&p, 1, frames, n, false);
    for (unsigned i = 0; i < 3; ++i) {
        assert(event(p.server, MIST_STREAM_OPEN).stream_id == ids[i]);
        assert(mist_stream_write(p.server, ids[i], (const uint8_t *)"abcdefgh", 8) == 8);
    }

    size_t size;
    const size_t budget = STREAM_HEADER + 2;
    p.server->schedule_slot[0] = 64;
    frame_ref ref = choose_frame(p.server, budget, false, &size);
    assert(ref.type == FRAME_STREAM && ref.id == ids[1] && size == budget);
    encode_frame(p.server, ref, size, frames);

    frame_lost(p.server, ref, p.server->tx_number);
    frame_ref retry = choose_frame(p.server, budget, false, &size);
    assert(retry.type == FRAME_STREAM && retry.id == ref.id && retry.value == ref.value);
    frame_acked(p.server, ref);

    const uint32_t order[] = {ids[2], ids[0], ids[1]};
    for (unsigned i = 0; i < 3; ++i) {
        ref = choose_frame(p.server, budget, false, &size);
        assert(ref.type == FRAME_STREAM && ref.id == order[i] && size == budget);
        encode_frame(p.server, ref, size, frames);
        assert(read_be(frames + 5, 8) == (i == 2 ? 2u : 0u));
    }
    destroy(p);
}

#define STREAMS 3
#define MESSAGES 25
#define QUEUE 256

typedef struct {
    uint64_t at;
    unsigned to;
    size_t size;
    uint8_t data[MIST_MAX_DATAGRAM];
} transit;

typedef struct {
    bool connected, open[STREAMS], finished[STREAMS], fin[STREAMS];
    size_t sent[STREAMS], read[STREAMS];
    bool messages[MESSAGES];
    unsigned next_message, got_messages;
    uint64_t next_pn;
} app;

typedef struct {
    pair p;
    transit q[QUEUE];
    app side[2];
    uint32_t rng, seed;
    bool lost_init, lost_resp, lost_confirm, lost_data_credit, lost_stream_credit;
} simulation;

static const size_t stream_lengths[2][STREAMS] = {{18000, 600, 7100}, {4200, 150, 9300}};

static uint32_t random_step(simulation *s)
{
    uint32_t x = s->rng;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return s->rng = x;
}

static uint8_t pattern(unsigned side, unsigned stream_idx, size_t offset)
{
    return (uint8_t)(side * 71 + stream_idx * 29 + (offset * 129) + (offset >> 5));
}

static size_t message_size(unsigned index)
{
    return index ? (index * 211u) % (MIST_MAX_MESSAGE + 1) : 0;
}

static void schedule_datagram(simulation *s, unsigned from, const mist_event *e,
                              unsigned fault)
{
    unsigned i = 0;
    while (i < QUEUE && s->q[i].size)
        ++i;
    assert(i < QUEUE);
    transit *t = &s->q[i];
    t->at = s->p.now + 2000 + random_step(s) % 43000;
    t->to = !from;
    t->size = e->length;
    memcpy(t->data, e->data, e->length);
    if (fault == 1) {
        t->data[random_step(s) % t->size] ^= 1;
    } else if (fault == 2) {
        t->size -= 1 + random_step(s) % (t->size - 1);
    }
}

static void network(simulation *s, mist_conn *c, unsigned from, const mist_event *e)
{
    assert(e->length <= MIST_MAX_DATAGRAM);
    switch (e->data[5]) {
    case PACKET_INIT:
        if (!s->lost_init) {
            s->lost_init = true;
            return;
        }
        schedule_datagram(s, from, e, 0);
        return;
    case PACKET_RESP:
        if (!s->lost_resp) {
            s->lost_resp = true;
            return;
        }
        schedule_datagram(s, from, e, 0);
        return;
    case PACKET_DATA: {
        uint64_t pn = read_be(e->data + COMMON_HEADER, 8);
        assert(pn == s->side[from].next_pn++);
        if (from == 0 && pn == 0) {
            s->lost_confirm = true;
            return;
        }
        uint8_t plaintext[MAX_PLAINTEXT], nonce[12];
        size_t plen = e->length - DATA_HEADER - TAG_SIZE;
        mist_nonce(nonce, pn);
        assert(mist_aead_open(plaintext, e->data + DATA_HEADER, plen,
                              e->data, DATA_HEADER, c->send_key, nonce));
        if (plaintext[0] == FRAME_MAX_DATA && !s->lost_data_credit) {
            s->lost_data_credit = true;
            return;
        }
        if (plaintext[0] == FRAME_MAX_STREAMS && !s->lost_stream_credit) {
            s->lost_stream_credit = true;
            return;
        }
        break;
    }
    default:
        assert(0);
    }
    if (random_step(s) % 100 < 82)
        schedule_datagram(s, from, e, 0);
    if (random_step(s) % 100 < 19)
        schedule_datagram(s, from, e, random_step(s) % 3);
}

static void application_events(simulation *s, mist_conn *c, unsigned side)
{
    app *a = &s->side[side];
    mist_event e;
    while (mist_next_event(c, &e) == 1) {
        unsigned i = e.stream_id >> 2;
        switch (e.type) {
        case MIST_NEED_RANDOM: {
            uint8_t bytes[48];
            for (size_t j = 0; j < e.length; ++j)
                bytes[j] = (uint8_t)random_step(s);
            assert(mist_supply_random(c, bytes, e.length) == MIST_OK);
            break;
        }
        case MIST_SEND_DATAGRAM:
            network(s, c, side, &e);
            break;
        case MIST_CONNECTED:
            assert(!a->connected);
            a->connected = true;
            break;
        case MIST_STREAM_OPEN:
            assert(side == 1 && i < STREAMS && !a->open[i] && !(e.stream_id & 3));
            a->open[i] = true;
            break;
        case MIST_STREAM_READABLE: {
            assert(i < STREAMS && a->open[i] && e.length);
            assert(a->read[i] + e.length <= stream_lengths[!side][i]);
            for (size_t j = 0; j < e.length; ++j)
                assert(e.data[j] == pattern(!side, i, a->read[i] + j));
            size_t take = (e.length + 1) / 2;
            a->read[i] += take;
            assert(mist_stream_consume(c, e.stream_id, take) == MIST_OK);
            break;
        }
        case MIST_STREAM_FIN:
            assert(i < STREAMS && !a->fin[i] && a->read[i] == stream_lengths[!side][i]);
            a->fin[i] = true;
            break;
        case MIST_MESSAGE:
            assert(i < MESSAGES && !a->messages[i] && e.length == message_size(i));
            assert((e.stream_id & 3) == (2u | !side));
            for (size_t j = 0; j < e.length; ++j)
                assert(e.data[j] == pattern(!side, i, j));
            a->messages[i] = true;
            ++a->got_messages;
            assert(mist_message_consume(c, e.stream_id) == MIST_OK);
            break;
        case MIST_WRITABLE:
            break;
        default:
            fprintf(stderr, "seed %u: unexpected event %d (code %u), side %u, t=%llu, "
                            "client state %d, server state %d, client PN %llu, server PN %llu\n",
                    s->seed, e.type, e.close_code, side, (unsigned long long)s->p.now,
                    s->p.client->state, s->p.server->state,
                    (unsigned long long)s->p.client->tx_number,
                    (unsigned long long)s->p.server->tx_number);
            assert(0);
        }
    }
}

static void application_writes(simulation *s, mist_conn *c, unsigned side)
{
    app *a = &s->side[side];
    if (!a->connected)
        return;
    for (unsigned i = 0; i < STREAMS; ++i) {
        uint32_t id = 4 * i;
        if (!side && !a->open[i]) {
            uint32_t allocated;
            assert(mist_open_stream(c, &allocated) == MIST_OK && id == allocated);
            a->open[i] = true;
        }
        if (!a->open[i] || a->finished[i])
            continue;
        uint8_t bytes[18000];
        size_t size = stream_lengths[side][i] - a->sent[i];
        for (size_t j = 0; j < size; ++j)
            bytes[j] = pattern(side, i, a->sent[i] + j);
        a->sent[i] += mist_stream_write(c, id, bytes, size);
        if (a->sent[i] == stream_lengths[side][i]) {
            int r = mist_stream_finish(c, id);
            assert(r == MIST_OK || r == MIST_AGAIN);
            a->finished[i] = r == MIST_OK;
        }
    }
    while (a->next_message < MESSAGES) {
        unsigned i = a->next_message;
        size_t size = message_size(i);
        uint8_t bytes[MIST_MAX_MESSAGE];
        for (size_t j = 0; j < size; ++j)
            bytes[j] = pattern(side, i, j);
        int r = mist_send_message(c, bytes, size);
        if (r == MIST_AGAIN)
            break;
        assert(r == MIST_OK);
        ++a->next_message;
    }
}

static bool completed(const simulation *s)
{
    for (unsigned side = 0; side < 2; ++side) {
        const app *a = &s->side[side];
        if (a->got_messages != MESSAGES)
            return false;
        for (unsigned i = 0; i < STREAMS; ++i) {
            if (!a->fin[i])
                return false;
        }
    }
    return !s->p.client->chunks && !s->p.server->chunks;
}

static void simulated_network(uint32_t seed)
{
    mist_config cfg;
    mist_config_default(&cfg);
    cfg.max_send_buffer = 5000;
    cfg.max_recv_buffer = cfg.initial_max_data = 3500;
    cfg.initial_max_stream_data = 1300;
    cfg.max_streams_bidi = STREAMS;
    cfg.max_streams_uni = 4;
    simulation *s = calloc(1, sizeof *s);
    assert(s);
    s->p = endpoints(&cfg);
    s->rng = s->seed = seed;
    mist_conn *ends[2] = {s->p.client, s->p.server};
    for (unsigned steps = 0; !completed(s); ++steps) {
        assert(steps < 30000 && s->p.now < 55000000);
        for (unsigned i = 0; i < QUEUE; ++i) {
            transit *t = &s->q[i];
            if (t->size && t->at <= s->p.now) {
                feed(ends[t->to], t->data, t->size, s->p.now);
                t->size = 0;
            }
        }
        for (unsigned i = 0; i < 2; ++i) {
            application_events(s, ends[i], i);
            application_writes(s, ends[i], i);
            poll_at(ends[i], s->p.now);
            application_events(s, ends[i], i);
            assert(ends[i]->rx_accounted <= ends[i]->rx_credit.sent);
            assert(ends[i]->rx_accounted - ends[i]->rx_consumed <= cfg.max_recv_buffer);
            assert(ends[i]->send_used <= cfg.max_send_buffer);
        }
        uint64_t next = mist_min(mist_next_deadline(ends[0]), mist_next_deadline(ends[1]));
        for (unsigned i = 0; i < QUEUE; ++i)
            if (s->q[i].size)
                next = mist_min(next, s->q[i].at);
        assert(next != NEVER);
        s->p.now = mist_max(next, s->p.now);
    }
    assert(s->lost_init && s->lost_resp && s->lost_confirm);
    assert(s->lost_data_credit && s->lost_stream_credit);
    assert(s->p.client->stats.packets_lost && s->p.server->stats.packets_lost);
    destroy(s->p);
    free(s);
}

int main(void)
{
    handshake_rules();
    handshake_replay_cache();
    authorization_policy();
    reordering_and_transaction();
    receive_bitmap_boundaries();
    flow_and_ack_violations();
    messages_and_replay_window();
    pto_and_pacing();
    atomic_flow_feedback();
    ack_ranges_and_deadlines();
    ack_bitmap_wrap();
    loss_history_wrap();
    session_limits();
    scheduler_sparse_slots();
    for (unsigned i = 1; i <= 30; ++i)
        simulated_network(i * 109);
    puts("transport simulation passed");
}
