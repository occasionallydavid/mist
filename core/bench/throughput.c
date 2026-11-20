#define _POSIX_C_SOURCE 200809L

#include "mist.h"

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MIB UINT64_C(1048576)

typedef struct {
    mist_conn *client, *server;
    uint64_t now, size, queued, received;
    uint64_t wire_bytes, datagrams;
    uint32_t stream;
    bool client_connected, server_connected, can_write, fin_queued, fin_received;
} benchmark;

static uint8_t payload[64 * 1024];

static void fail(const char *message)
{
    fprintf(stderr, "throughput benchmark: %s\n", message);
    exit(EXIT_FAILURE);
}

static struct timespec wall_time(void)
{
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC, &time) != 0)
        fail("monotonic clock unavailable");
    return time;
}

static void consume(benchmark *b, const mist_event *event)
{
    if (event->stream_id != b->stream || event->length > b->size - b->received)
        fail("unexpected stream data");

    size_t index = (size_t)(b->received % sizeof payload);
    size_t first = sizeof payload - index;
    if (first > event->length)
        first = event->length;
    if (event->length - first > sizeof payload ||
        memcmp(event->data, payload + index, first) ||
        memcmp(event->data + first, payload, event->length - first))
        fail("payload verification failed");

    if (mist_stream_consume(b->server, b->stream, event->length) != MIST_OK)
        fail("could not consume stream data");
    b->received += event->length;
}

static void drive(benchmark *b, bool client)
{
    mist_conn *local = client ? b->client : b->server;
    mist_conn *peer = client ? b->server : b->client;
    if (mist_poll(local, b->now) != MIST_OK)
        fail("poll failed");

    mist_event event;
    int result;
    while ((result = mist_next_event(local, &event)) == 1) {
        switch (event.type) {
        case MIST_NEED_RANDOM: {
            /* Fixed entropy for a reproducible local benchmark. */
            const uint8_t entropy[48] = {12, 34, 56, 78, [16] = 90};
            const uint8_t response_entropy[32] = {98, 76, 54, 32};
            size_t length = client ? sizeof entropy : sizeof response_entropy;
            if (event.length != length ||
                mist_supply_random(local, client ? entropy : response_entropy, length) != MIST_OK)
                fail("could not supply handshake entropy");
            break;
        }
        case MIST_SEND_DATAGRAM:
            ++b->datagrams;
            b->wire_bytes += event.length;
            if (mist_input(peer, event.data, event.length, b->now) != MIST_OK)
                fail("datagram input failed");
            break;
        case MIST_CONNECTED:
            if (client)
                b->client_connected = true;
            else
                b->server_connected = true;
            break;
        case MIST_STREAM_OPEN:
            if (client || event.stream_id != b->stream)
                fail("unexpected stream");
            break;
        case MIST_STREAM_READABLE:
            if (client)
                fail("unexpected reply data");
            consume(b, &event);
            break;
        case MIST_STREAM_FIN:
            if (client || event.stream_id != b->stream || b->received != b->size)
                fail("unexpected stream FIN");
            b->fin_received = true;
            break;
        case MIST_WRITABLE:
            if (client)
                b->can_write = true;
            break;
        case MIST_CLOSED:
            fprintf(stderr, "connection closed with code %u\n", (unsigned)event.close_code);
            fail("connection closed before the transfer finished");
            break;
        default:
            fail("unexpected event");
        }
    }
    if (result < 0)
        fail("could not read connection events");
}

static void advance(benchmark *b, unsigned *same_time)
{
    uint64_t next = mist_next_deadline(b->client);
    uint64_t server_next = mist_next_deadline(b->server);
    if (server_next < next)
        next = server_next;
    if (next == MIST_NO_DEADLINE || next < b->now)
        fail("transfer stalled");
    *same_time = next == b->now ? *same_time + 1 : 0;
    if (*same_time > 1000)
        fail("transfer stalled at the same virtual timestamp");
    b->now = next;
}

static void queue_payload(benchmark *b)
{
    if (!b->can_write || b->fin_queued)
        return;

    while (b->queued < b->size) {
        size_t index = (size_t)(b->queued % sizeof payload);
        size_t length = sizeof payload - index;
        if (length > b->size - b->queued)
            length = (size_t)(b->size - b->queued);
        size_t accepted = mist_stream_write(b->client, b->stream, payload + index, length);
        b->queued += accepted;
        if (accepted < length) {
            b->can_write = false;
            return;
        }
    }

    int result = mist_stream_finish(b->client, b->stream);
    if (result == MIST_AGAIN)
        b->can_write = false;
    else if (result == MIST_OK)
        b->fin_queued = true;
    else
        fail("could not finish the stream");
}

static uint64_t transfer_size(int argc, char **argv)
{
    if (argc == 1)
        return 64 * MIB;
    if (argc == 2 && argv[1][0] >= '0' && argv[1][0] <= '9') {
        char *end;
        errno = 0;
        uintmax_t mib = strtoumax(argv[1], &end, 10);
        if (!errno && !*end && mib > 0 && mib <= UINT64_MAX / MIB)
            return (uint64_t)mib * MIB;
    }
    fprintf(stderr, "Usage: %s [positive payload size in MiB]\n", argv[0]);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    benchmark b = {.size = transfer_size(argc, argv)};
    const uint8_t client_key[32] = {14}, server_key[32] = {27};
    uint8_t client_public[32], server_public[32];
    mist_public_key(client_public, client_key);
    mist_public_key(server_public, server_key);
    b.client = mist_client_create(NULL, client_key, server_public);
    b.server = mist_server_create(NULL, server_key, client_public);
    if (!b.client || !b.server)
        fail("could not create endpoints");

    uint32_t random = 42;
    for (size_t i = 0; i < sizeof payload; ++i) {
        random ^= random << 13;
        random ^= random >> 17;
        random ^= random << 5;
        payload[i] = (uint8_t)random;
    }

    unsigned same_time = 0;
    while (!b.client_connected || !b.server_connected) {
        drive(&b, true);
        drive(&b, false);
        if (!b.client_connected || !b.server_connected)
            advance(&b, &same_time);
    }
    b.datagrams = b.wire_bytes = 0;

    struct timespec start = wall_time();
    if (mist_open_stream(b.client, &b.stream) != MIST_OK)
        fail("could not open a stream");
    b.can_write = true;
    same_time = 0;
    queue_payload(&b);
    while (!b.fin_received) {
        drive(&b, true);
        drive(&b, false);
        if (!b.fin_received) {
            queue_payload(&b);
            advance(&b, &same_time);
        }
    }
    struct timespec end = wall_time();
    double seconds = (double)(end.tv_sec - start.tv_sec) +
                     (double)(end.tv_nsec - start.tv_nsec) / 1e9;
    if (seconds <= 0)
        fail("transfer finished below the wall clock resolution");

    printf("Transferred %" PRIu64 " MiB in %.3f s\n", b.received / MIB, seconds);
    printf("Stream goodput %.2f MiB/s (%.2f Gbit/s)\n",
           (double)b.received / (double)MIB / seconds, (double)b.received * 8e-9 / seconds);
    printf("MIST traffic %" PRIu64 " bytes across %" PRIu64 " datagrams (both directions)\n",
           b.wire_bytes, b.datagrams);

    mist_destroy(b.client);
    mist_destroy(b.server);
    return EXIT_SUCCESS;
}
