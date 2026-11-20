#ifndef MIST_H
#define MIST_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MIST_MAX_DATAGRAM 1200
#define MIST_MAX_MESSAGE 1024
#define MIST_NO_DEADLINE UINT64_MAX
#define MIST_MAX_WINDOW (UINT64_C(64) * 1024 * 1024)
#define MIST_MAX_INITIAL_STREAMS 1024

typedef struct mist_conn mist_conn;
typedef struct mist_replay_cache mist_replay_cache;
typedef int (*mist_authorize_fn)(void *context, const uint8_t public_key[32]);

typedef enum {
    MIST_OK = 0,
    MIST_AGAIN = 1,          /* A write, stream open or message is blocked. */
    MIST_INVALID = -1,       /* Invalid arguments or operation for this state. */
    MIST_NO_MEMORY = -2
} mist_result;

typedef enum {
    MIST_NORMAL_CLOSE = 0,
    MIST_PROTOCOL_ERROR = 1,
    MIST_FLOW_CONTROL = 2,
    MIST_RESOURCE_LIMIT = 3,
    MIST_INTERNAL_ERROR = 4,
    MIST_SESSION_EXPIRED = 5
} mist_close_code;

typedef struct {
    uint64_t max_send_buffer;
    uint64_t max_recv_buffer;
    uint64_t initial_max_data;
    uint64_t initial_max_stream_data;
    uint32_t max_streams_bidi;
    uint32_t max_streams_uni;
    /* Optional shared server-side INIT replay cache. See lifetime rules below. */
    mist_replay_cache *replay_cache;
} mist_config;

typedef enum {
    MIST_NEED_RANDOM,
    MIST_SEND_DATAGRAM,
    MIST_CONNECTED,
    MIST_STREAM_OPEN,
    MIST_STREAM_READABLE,
    MIST_STREAM_FIN,
    MIST_MESSAGE,
    MIST_WRITABLE,
    MIST_RECONNECT_REQUIRED,
    MIST_CLOSED
} mist_event_type;

typedef struct mist_event {
    mist_event_type type;
    uint32_t stream_id;
    const uint8_t *data;
    size_t length;          /* Bytes of data or exact entropy requested. */
    uint16_t close_code;
    int remote;             /* Set for a CLOSE received from the peer. */
} mist_event;

typedef struct {
    uint64_t next_packet_number;
    uint64_t latest_rtt_us, min_rtt_us, smoothed_rtt_us, rtt_variance_us;
    uint64_t cwnd, ssthresh, bytes_in_flight;
    uint64_t packets_lost, probe_timeouts;
} mist_stats;

void mist_config_default(mist_config *config);
void mist_public_key(uint8_t public_key[32], const uint8_t private_key[32]);

/* Share across fresh server objects for the same identity. The cache must
 * outlive those objects, which must use one monotonic time domain and
 * synchronize cache access. Capacity is 1..4096 authenticated entries. */
mist_replay_cache *mist_replay_cache_create(size_t capacity);
void mist_replay_cache_destroy(mist_replay_cache *cache);

/* Constructors copy keys and configuration, and accept NULL for defaults.
 * A server represents one connection slot. Route active CIDs to their
 * existing slots and bound the number of slots at the dispatcher. */
mist_conn *mist_client_create(const mist_config *config, const uint8_t local[32],
                              const uint8_t responder[32]);
mist_conn *mist_server_create(const mist_config *config, const uint8_t local[32],
                              const uint8_t allowed_initiator[32]);
/* The callback returns nonzero for an authorized key. The key is already
 * authenticated, is borrowed for the call, and may be copied by the policy.
 * The caller owns context and must avoid reentering the same connection. */
mist_conn *mist_server_create_with_policy(const mist_config *config,
                                          const uint8_t local[32],
                                          mist_authorize_fn authorize, void *context);
void mist_destroy(mist_conn *conn);
int mist_supply_random(mist_conn *conn, const uint8_t *bytes, size_t length);

/* Input silently drops invalid or unauthenticated headers and handshakes.
 * Authenticated frame violations close with their wire code in MIST_CLOSED.
 * Both calls require nondecreasing microseconds below MIST_NO_DEADLINE. */
int mist_input(mist_conn *conn, const uint8_t *packet, size_t length, uint64_t now_us);
int mist_poll(mist_conn *conn, uint64_t now_us);

/* Returns one for an event, zero when drained, or a negative mist_result.
 * Poll produces at most one datagram. Call next_event until drained, then
 * poll again when the next deadline is due. Datagram data is valid until the
 * next mutating API call. Stream/message data stays valid until consumed,
 * local or remote closure, or destruction. Readable events expose one slice
 * at a time and can be followed by another slice after any positive consume.
 * Consume may release only bytes exposed by the latest readable event.
 * CONNECTED exposes the authenticated 32-byte peer key until destruction. */
int mist_next_event(mist_conn *conn, mist_event *event);

int mist_open_stream(mist_conn *conn, uint32_t *stream_id);
size_t mist_stream_write(mist_conn *conn, uint32_t stream_id,
                         const uint8_t *data, size_t length);
int mist_stream_finish(mist_conn *conn, uint32_t stream_id);
int mist_send_message(mist_conn *conn, const uint8_t *data, size_t length);
int mist_stream_consume(mist_conn *conn, uint32_t stream_id, size_t length);
int mist_message_consume(mist_conn *conn, uint32_t message_stream_id);
int mist_close(mist_conn *conn, uint16_t code);
uint64_t mist_next_deadline(const mist_conn *conn);
int mist_get_stats(const mist_conn *conn, mist_stats *stats);

#ifdef __cplusplus
}
#endif
#endif
