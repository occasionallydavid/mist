#ifndef MIST_INTERNAL_H
#define MIST_INTERNAL_H

#include "mist.h"
#include "crypto/crypto.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define COMMON_HEADER 22
#define DATA_HEADER 30
#define TAG_SIZE 16
#define MAX_PLAINTEXT (MIST_MAX_DATAGRAM - DATA_HEADER - TAG_SIZE)
#define STREAM_HEADER 16
#define MAX_FRAGMENT (MAX_PLAINTEXT - STREAM_HEADER)
#define INIT_SIZE (COMMON_HEADER + MIST_NOISE_INIT_LEN)
#define RESP_SIZE (COMMON_HEADER + MIST_NOISE_RESP_LEN)
#define IDLE_TIME UINT64_C(60000000)
#define TENTATIVE_TIME UINT64_C(40000000)
#define SESSION_TIME UINT64_C(86400000000)
#define RECONNECT_TIME (SESSION_TIME - IDLE_TIME)
#define PACKET_LIMIT (UINT64_C(1) << 32)
#define STREAM_LIMIT (UINT32_C(1) << 30)
#define SERVER_CACHE_TIME UINT64_C(120000000)
#define NEVER UINT64_MAX

#define PAGE_SIZE 256u
#define REPLAY_BITS 2048u
#define ACK_RANGES 16u
#define ACK_MIN_SIZE 30u
#define ACK_DELAY UINT64_C(25000)
#define TX_HISTORY 1024u
#define MAX_FLIGHT_PACKETS 512u
#define MAX_CHUNKS 16384u
#define RECENT_COMPLETIONS 64u
#define MIN_CWND (2u * MIST_MAX_DATAGRAM)
#define SLOT_WORDS ((MIST_MAX_INITIAL_STREAMS + 63u) / 64u)
#define NO_SLOT (SLOT_WORDS * 64u)

_Static_assert(SLOT_WORDS <= 64, "slot sets use a single word of occupancy bits");
_Static_assert(TX_HISTORY <= NO_SLOT, "packet history fits in a slot set");

enum packet_type { PACKET_INIT = 1, PACKET_RESP, PACKET_DATA };
enum frame_type {
    FRAME_PING = 1, FRAME_ACK, FRAME_STREAM, FRAME_MAX_DATA,
    FRAME_MAX_STREAM_DATA, FRAME_MAX_STREAMS, FRAME_CLOSE
};
enum conn_state {
    WAIT_CLIENT_RANDOM, WAIT_INIT, WAIT_RESP, WAIT_SERVER_RANDOM,
    WAIT_CONFIRM, ESTABLISHED, CLOSING, CLOSED
};
enum chunk_state { CHUNK_NEW, CHUNK_IN_FLIGHT, CHUNK_LOST };

typedef struct {
    uint64_t limit, sent, acked, packet, update_at;
    bool lost;
} credit;

typedef struct page {
    struct page *next;     /* Used only by packet transactions. */
    struct page *left, *right;
    unsigned height;
    uint64_t index;
    uint64_t present[PAGE_SIZE / 64];
    uint8_t data[PAGE_SIZE];
} page;

typedef struct chunk {
    struct chunk *next;
    uint64_t offset, token, packet;
    uint16_t length, used, sent_length;
    bool fin;
    enum chunk_state state;
    uint8_t data[];
} chunk;

typedef struct stream {
    uint32_t id;
    bool retired, saw_stream, open_event, final_known, fin_event, readable_issued;
    bool tx_finished, tx_fin_acked, tx_announced, message_event, message_issued;
    uint64_t rx_next, rx_high, rx_final, rx_read, tx_high, tx_offset, tx_limit;
    size_t exposed;
    credit rx_credit;
    page *pages;
    uint8_t *message;
    uint8_t message_digest[32];
    chunk *head, *tail, *next_new;
    unsigned lost_chunks;
} stream;

typedef struct {
    uint64_t final;
    uint32_t id;
    bool valid;
    uint8_t message_digest[32];
} completion;

typedef struct {
    uint64_t words[SLOT_WORDS], occupied;
} slot_set;

typedef struct {
    stream **slots;
    uint32_t capacity, next, retired, peer_limit;
    slot_set active, tx_new, tx_lost;
    credit rx_credit;
    completion recent[RECENT_COMPLETIONS];
} stream_class;

typedef struct {
    uint8_t type;
    uint32_t id;
    uint64_t value;
} frame_ref;

typedef struct {
    uint64_t number, time;
    frame_ref ref;
    uint16_t size;
    bool outstanding;
} sent_packet;

typedef struct {
    uint64_t start, end;
} ack_range;

typedef struct {
    uint64_t largest, delay;
    unsigned count;
    ack_range range[ACK_RANGES];
} ack_frame;

typedef struct {
    uint64_t max_data, max_stream_data;
    uint32_t max_bidi, max_uni;
} params;

struct mist_conn {
    enum conn_state state;
    bool server, clock_set, random_event, connected_event, closed_event;
    bool reconnect_event, reconnect_reported, first_data, remote_close;
    bool writable_event, write_blocked, finish_blocked, open_blocked, message_blocked;
    bool handshake_pending, ack_pending, rx_any, largest_acked_valid;
    bool recovery, rtt_valid;
    uint8_t cid[16], local_key[32], public_key[32], peer_key[32];
    uint8_t send_key[32], recv_key[32], randomness[48];
    size_t random_length;
    uint8_t init[INIT_SIZE], resp[RESP_SIZE];
    mist_noise noise;
    mist_config config;
    mist_authorize_fn authorize;
    void *authorize_context;
    params peer;
    uint64_t now, last_rx, handshake_at, ack_at, pace_at, close_at;
    uint64_t reconnect_at, expire_at;
    unsigned handshake_retries, ack_eliciting, close_attempts;
    uint16_t close_code;
    uint8_t datagram[MIST_MAX_DATAGRAM];
    size_t datagram_len;
    stream_class classes[4];
    uint64_t send_used, tx_accounted, rx_accounted, rx_consumed, token_next;
    unsigned chunks, schedule_class;
    size_t blocked_message_size;
    uint32_t schedule_slot[4];
    credit rx_credit;
    uint64_t tx_limit;
    uint64_t tx_number, rx_largest, rx_largest_time;
    uint64_t replay[REPLAY_BITS / 64];
    sent_packet sent[TX_HISTORY];
    slot_set sent_valid, sent_flight;
    unsigned sent_cursor, flight_packets;
    uint64_t largest_acked, recovery_number, ca_credit, pto_at;
    unsigned pto_backoff;
    mist_stats stats;
};

static inline uint64_t mist_min(uint64_t a, uint64_t b) { return a < b ? a : b; }
static inline uint64_t mist_max(uint64_t a, uint64_t b) { return a > b ? a : b; }
static inline uint64_t mist_add(uint64_t a, uint64_t b)
{
    return a > UINT64_MAX - b ? UINT64_MAX : a + b;
}
static inline bool is_local(const mist_conn *c, uint32_t id)
{
    return (id & 1u) == (unsigned)c->server;
}
static inline bool is_message(uint32_t id) { return (id & 2u) != 0; }

static inline unsigned stream_slot(const stream_class *sc, uint32_t id)
{
    return (id >> 2) % sc->capacity;
}

static inline void slot_set_update(slot_set *set, unsigned slot, bool present)
{
    unsigned word = slot / 64u;
    uint64_t bit = UINT64_C(1) << (slot % 64u);
    uint64_t word_bit = UINT64_C(1) << word;
    if (present) {
        set->words[word] |= bit;
        set->occupied |= word_bit;
    } else {
        set->words[word] &= ~bit;
        if (!set->words[word])
            set->occupied &= ~word_bit;
    }
}

static inline unsigned first_bit(uint64_t bits)
{
#if defined(__GNUC__) || defined(__clang__)
    return (unsigned)__builtin_ctzll(bits);
#else
    unsigned bit = 0;
    while (!(bits & 1u)) {
        ++bit;
        bits >>= 1;
    }
    return bit;
#endif
}

/* Find the first member at or after start without walking empty words. */
static inline unsigned slot_at_or_after(const slot_set *set, unsigned start)
{
    if (start >= NO_SLOT)
        return NO_SLOT;
    unsigned word = start / 64u;
    uint64_t words = set->occupied & (UINT64_MAX << word);
    if (!words)
        return NO_SLOT;
    uint64_t bits = set->words[word] & (UINT64_MAX << (start % 64u));
    if (bits)
        return word * 64u + first_bit(bits);
    words &= ~(UINT64_C(1) << word);
    if (!words)
        return NO_SLOT;
    word = first_bit(words);
    return word * 64u + first_bit(set->words[word]);
}

static inline unsigned flight_slot_at_or_after(const mist_conn *c, unsigned start)
{
    unsigned slot = slot_at_or_after(&c->sent_flight, start);
    return slot == NO_SLOT ? slot_at_or_after(&c->sent_flight, 0) : slot;
}

uint64_t read_be(const uint8_t *p, unsigned n);
void write_be(uint8_t *p, uint64_t v, unsigned n);
void packet_header(uint8_t *out, enum packet_type type, const uint8_t cid[16]);

void handshake_poll(mist_conn *c);
void handshake_input(mist_conn *c, const uint8_t *packet, size_t length);
void establish(mist_conn *c);
bool has_transport(const mist_conn *c);
void fail_connection(mist_conn *c, uint16_t code);
void terminate(mist_conn *c, uint16_t code, bool remote);

stream *find_stream(const mist_conn *c, uint32_t id);
stream *new_stream(const mist_conn *c, uint32_t id);
void insert_stream(mist_conn *c, stream *s);
void free_stream(stream *s);
void release_streams(mist_conn *c);
void clean_streams(mist_conn *c);
void writable_changed(mist_conn *c);
bool stream_event(mist_conn *c, mist_event *e);
page *find_page(page *head, uint64_t index);
bool page_matches(const page *p, unsigned offset, const uint8_t *data, unsigned length);
void commit_page(stream *s, page *p);
void store_stream_bytes(stream *s, uint64_t offset, const uint8_t *data, size_t length);
void advance_stream(stream *s);
uint64_t window_deadline(const mist_conn *c);
void refresh_windows(mist_conn *c);
frame_ref choose_frame(const mist_conn *c, size_t budget, bool probe, size_t *size);
size_t encode_frame(mist_conn *c, frame_ref ref, size_t size, uint8_t *data);
void frame_acked(mist_conn *c, frame_ref ref);
void frame_lost(mist_conn *c, frame_ref ref, uint64_t number);

void data_input(mist_conn *c, const uint8_t *packet, size_t length);
bool replay_contains(const mist_conn *c, uint64_t number);
bool replay_seen_or_old(const mist_conn *c, uint64_t number);
void replay_accept(mist_conn *c, uint64_t number, bool eliciting, bool confirm);
size_t encode_ack(const mist_conn *c, uint8_t *out);
bool decode_ack(const mist_conn *c, const uint8_t *in, size_t n, ack_frame *ack);
void process_acks(mist_conn *c, const ack_frame *acks, size_t count);
void record_sent(mist_conn *c, size_t size, frame_ref ref, bool probe);
void detect_loss(mist_conn *c);
void make_probe_room(mist_conn *c);
uint64_t loss_deadline(const mist_conn *c);
uint64_t data_deadline(const mist_conn *c);
void data_poll(mist_conn *c);

#endif
