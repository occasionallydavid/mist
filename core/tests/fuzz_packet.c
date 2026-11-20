#include "internal.h"

#include <assert.h>

/* Each record is mode, time delta in milliseconds, length (uint16 BE), and
 * bytes. Mode 0 feeds raw UDP. Mode 1 seals the bytes as DATA frames. Mode 2
 * builds one STREAM from compact fields. Mode 3 mutates a genuine INIT. */
typedef struct {
    mist_conn endpoint;
    uint8_t init[INIT_SIZE];
    size_t init_size;
} fixture;

static fixture baseline;

static size_t emit(mist_conn *c, uint64_t now, uint8_t *out)
{
    mist_event e;
    assert(mist_poll(c, now) == MIST_OK);
    assert(mist_next_event(c, &e) == 1 && e.type == MIST_SEND_DATAGRAM);
    memcpy(out, e.data, e.length);
    return e.length;
}

static void initialize(void)
{
    const uint8_t ckey[32] = {7, 21}, skey[32] = {8, 31};
    const uint8_t crandom[48] = {9, 41}, srandom[32] = {10, 51};
    uint8_t cp[32], sp[32], packet[MIST_MAX_DATAGRAM];
    mist_public_key(cp, ckey);
    mist_public_key(sp, skey);
    mist_config config;
    mist_config_default(&config);
    config.max_recv_buffer = config.initial_max_data = 8192;
    config.initial_max_stream_data = 2048;
    mist_conn *client = mist_client_create(&config, ckey, sp);
    mist_conn *server = mist_server_create(&config, skey, cp);
    assert(client && server);
    assert(mist_supply_random(client, crandom, sizeof crandom) == MIST_OK);
    baseline.init_size = emit(client, 0, baseline.init);
    assert(mist_input(server, baseline.init, baseline.init_size, 0) == MIST_OK);
    assert(mist_supply_random(server, srandom, sizeof srandom) == MIST_OK);
    size_t n = emit(server, 0, packet);
    assert(mist_input(client, packet, n, 0) == MIST_OK);
    n = emit(client, 0, packet);
    assert(mist_input(server, packet, n, 0) == MIST_OK);
    emit(server, 0, packet);
    assert(server->state == ESTABLISHED);
    server->connected_event = false;
    baseline.endpoint = *server;
    for (unsigned i = 0; i < 4; ++i)
        baseline.endpoint.classes[i].slots = NULL;
    mist_destroy(client);
    mist_destroy(server);
}

static mist_conn *target(bool handshake)
{
    if (handshake) {
        const uint8_t skey[32] = {8, 31};
        return mist_server_create(&baseline.endpoint.config, skey, baseline.endpoint.peer_key);
    }
    mist_conn *c = malloc(sizeof *c);
    assert(c);
    *c = baseline.endpoint;
    for (unsigned i = 0; i < 4; ++i) {
        c->classes[i].slots = calloc(c->classes[i].capacity, sizeof(stream *));
        assert(c->classes[i].slots);
    }
    return c;
}

static void sealed(mist_conn *c, uint64_t pn, const uint8_t *frames, size_t n, uint64_t now)
{
    uint8_t packet[MIST_MAX_DATAGRAM], nonce[12];
    packet_header(packet, PACKET_DATA, c->cid);
    write_be(packet + COMMON_HEADER, pn, 8);
    mist_nonce(nonce, pn);
    mist_aead_seal(packet + DATA_HEADER, frames, n, packet, DATA_HEADER, c->recv_key, nonce);
    assert(mist_input(c, packet, DATA_HEADER + n + TAG_SIZE, now) == MIST_OK);
}

static void poll_and_drain(mist_conn *c, uint64_t now)
{
    mist_event e;
    assert(mist_poll(c, now) == MIST_OK);
    while (mist_next_event(c, &e) == 1) {
        switch (e.type) {
        case MIST_NEED_RANDOM: {
            const uint8_t randomness[32] = {93};
            assert(mist_supply_random(c, randomness, e.length) == MIST_OK);
            break;
        }
        case MIST_STREAM_OPEN:
            assert(mist_stream_finish(c, e.stream_id) == MIST_OK);
            break;
        case MIST_STREAM_READABLE:
            assert(mist_stream_consume(c, e.stream_id, e.length) == MIST_OK);
            break;
        case MIST_MESSAGE:
            assert(mist_message_consume(c, e.stream_id) == MIST_OK);
            break;
        default:
            break;
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len)
{
    if (!len)
        return 0;
    if (!baseline.init_size)
        initialize();
    mist_conn *c = target((data[0] & 1u) != 0);
    assert(c);
    uint64_t now = 0, pn = 1;
    size_t at = 1;
    while (len - at >= 4 && c->state != CLOSED) {
        unsigned mode = data[at] & 3u;
        now += (uint64_t)data[at + 1] * 1000;
        size_t n = (size_t)mist_min(read_be(data + at + 2, 2), len - at - 4);
        const uint8_t *bytes = data + at + 4;
        at += n + 4;
        if (mode == 0) {
            assert(mist_input(c, bytes, n, now) == MIST_OK);
        } else if (mode == 1 && has_transport(c)) {
            sealed(c, pn++, bytes, (size_t)mist_min(n, MAX_PLAINTEXT), now);
        } else if (mode == 2 && n >= 4 && has_transport(c)) {
            uint8_t frame[MAX_PLAINTEXT] = {FRAME_STREAM};
            uint64_t id = bytes[0] & 127u;
            uint64_t offset = read_be(bytes + 1, 2) & 4095u;
            size_t size = (size_t)mist_min(n - 4, MAX_FRAGMENT);
            write_be(frame + 1, id, 4);
            write_be(frame + 5, offset, 8);
            frame[13] = bytes[3] & 3u;
            write_be(frame + 14, size, 2);
            memcpy(frame + STREAM_HEADER, bytes + 4, size);
            sealed(c, pn++, frame, STREAM_HEADER + size, now);
        } else if (mode == 3) {
            uint8_t packet[INIT_SIZE];
            memcpy(packet, baseline.init, baseline.init_size);
            for (size_t i = 1; i < n; i += 2)
                packet[bytes[i - 1] % baseline.init_size] ^= bytes[i];
            assert(mist_input(c, packet, baseline.init_size, now) == MIST_OK);
        }
        poll_and_drain(c, now);
    }
    mist_destroy(c);
    return 0;
}
