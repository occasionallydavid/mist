#include "internal.h"

#define MAX_PACKET_STREAMS (MAX_PLAINTEXT / 13)
#define MAX_PACKET_FRAGMENTS (MAX_PLAINTEXT / STREAM_HEADER)
#define MAX_PACKET_ACKS (MAX_PLAINTEXT / ACK_MIN_SIZE)

uint64_t read_be(const uint8_t *p, unsigned n)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < n; ++i)
        value = (value << 8) | p[i];
    return value;
}

void write_be(uint8_t *p, uint64_t value, unsigned n)
{
    while (n) {
        p[--n] = (uint8_t)value;
        value >>= 8;
    }
}

void packet_header(uint8_t *out, enum packet_type type, const uint8_t cid[16])
{
    memcpy(out, "MST1", 4);
    out[4] = 1;
    out[5] = (uint8_t)type;
    memcpy(out + 6, cid, 16);
}

typedef struct {
    stream *s;
    bool is_new, saw_stream, final_known, new_message;
    uint64_t high, final, tx_limit;
    page *reserved;
    uint8_t *message;
} stream_update;

typedef struct {
    stream_update *update;
    const uint8_t *data;
    uint64_t start, end;
} fragment;

typedef struct {
    size_t stream_count, fragment_count, ack_count;
    stream_update streams[MAX_PACKET_STREAMS];
    fragment fragments[MAX_PACKET_FRAGMENTS];
    ack_frame acks[MAX_PACKET_ACKS];
    uint64_t rx_accounted, tx_limit;
    uint32_t stream_limits[2];
    bool eliciting, close;
    uint16_t close_code;
} transaction;

static void discard(transaction *tx)
{
    for (size_t i = 0; i < tx->stream_count; ++i) {
        stream_update *u = &tx->streams[i];
        while (u->reserved) {
            page *p = u->reserved;
            u->reserved = p->next;
            free(p);
        }
        free(u->message);
        if (u->is_new)
            free_stream(u->s);
    }
}

static stream_update *stage_stream(mist_conn *c, transaction *tx, uint32_t id)
{
    for (size_t i = 0; i < tx->stream_count; ++i) {
        if (tx->streams[i].s->id == id)
            return &tx->streams[i];
    }
    stream *s = find_stream(c, id);
    bool is_new = !s;
    if (is_new)
        s = new_stream(c, id);
    if (!s)
        return NULL;

    stream_update *u = &tx->streams[tx->stream_count++];
    *u = (stream_update){
        .s = s, .is_new = is_new, .saw_stream = s->saw_stream,
        .final_known = s->final_known, .high = s->rx_high, .final = s->rx_final,
        .tx_limit = s->tx_limit
    };
    return u;
}

/* A compacted ordinal can never allocate a new record or deliver again. */
static int check_stream(const mist_conn *c, uint32_t id, bool data, bool *gone)
{
    const stream_class *sc = &c->classes[id & 3u];
    uint32_t ord = id >> 2;
    bool local = is_local(c, id);
    if (is_message(id) && local == data)
        return MIST_PROTOCOL_ERROR;
    *gone = ord < sc->retired;
    if (*gone)
        return 0;
    if (!local)
        return ord >= sc->rx_credit.sent ? MIST_FLOW_CONTROL : 0;
    stream *s = find_stream(c, id);
    return s && s->tx_announced ? 0 : MIST_PROTOCOL_ERROR;
}

static bool reserve_page(stream_update *u, uint64_t index)
{
    page **link = &u->reserved;
    while (*link && (*link)->index < index)
        link = &(*link)->next;
    if (*link && (*link)->index == index)
        return true;
    page *p = calloc(1, sizeof *p);
    if (!p)
        return false;
    p->index = index;
    p->next = *link;
    *link = p;
    return true;
}

static int stage_bytes(transaction *tx, stream_update *u, uint64_t offset,
                       uint64_t end, const uint8_t *data)
{
    for (size_t i = 0; i < tx->fragment_count; ++i) {
        const fragment *old = &tx->fragments[i];
        uint64_t lo = mist_max(offset, old->start), hi = mist_min(end, old->end);
        if (u == old->update && lo < hi &&
            memcmp(data + (size_t)(lo - offset),
                   old->data + (size_t)(lo - old->start), (size_t)(hi - lo)))
            return MIST_PROTOCOL_ERROR;
    }

    stream *s = u->s;
    for (uint64_t cur = offset; cur < end;) {
        uint64_t index = cur / PAGE_SIZE;
        const page *p = find_page(s->pages, index);
        unsigned at = (unsigned)(cur % PAGE_SIZE);
        unsigned count = (unsigned)mist_min(end - cur, PAGE_SIZE - at);
        if (p) {
            if (cur < s->rx_high &&
                !page_matches(p, at, data + (size_t)(cur - offset),
                              (unsigned)mist_min(count, s->rx_high - cur)))
                return MIST_PROTOCOL_ERROR;
        } else if (!s->retired && cur + count > s->rx_read && !reserve_page(u, index)) {
            return MIST_RESOURCE_LIMIT;
        }
        cur += count;
    }
    if (offset < end && !s->retired)
        tx->fragments[tx->fragment_count++] = (fragment){u, data, offset, end};
    return 0;
}

static int compare_message_digest(const uint8_t digest[32],
                                  const uint8_t *data, size_t n)
{
    uint8_t hash[32];
    mist_blake2s(hash, data, n);
    bool equal = mist_equal(digest, hash, sizeof hash) != 0;
    return equal ? 0 : MIST_PROTOCOL_ERROR;
}

static int check_completion(const mist_conn *c, uint32_t id, uint64_t end, bool fin,
                            const uint8_t *data, size_t n)
{
    const completion *entry = &c->classes[id & 3u].recent[(id >> 2) % RECENT_COMPLETIONS];
    if (!entry->valid || entry->id != id)
        return 0;
    if (end > entry->final || (fin && end != entry->final))
        return MIST_PROTOCOL_ERROR;
    return is_message(id) ? compare_message_digest(entry->message_digest, data, n) : 0;
}

static int stage_message(stream_update *u, const uint8_t *data, size_t n)
{
    stream *s = u->s;
    if (s->retired)
        return compare_message_digest(s->message_digest, data, n);
    if (s->saw_stream || u->new_message) {
        const uint8_t *previous = u->new_message ? u->message : s->message;
        return previous && memcmp(previous, data, n) ? MIST_PROTOCOL_ERROR : 0;
    }
    if (n) {
        u->message = malloc(n);
        if (!u->message)
            return MIST_RESOURCE_LIMIT;
        memcpy(u->message, data, n);
    }
    u->new_message = true;
    return 0;
}

static int parse_stream(mist_conn *c, transaction *tx, const uint8_t *in, size_t n)
{
    uint32_t id = (uint32_t)read_be(in + 1, 4);
    uint64_t offset = read_be(in + 5, 8);
    bool fin = (in[13] & 1u) != 0;
    if ((in[13] & ~1u) || n > UINT64_MAX - offset)
        return MIST_PROTOCOL_ERROR;
    bool message = is_message(id);
    if (message && (!fin || offset || n > MIST_MAX_MESSAGE))
        return MIST_PROTOCOL_ERROR;

    bool gone;
    int error = check_stream(c, id, true, &gone);
    if (error)
        return error;
    uint64_t end = offset + n;
    if (gone)
        return check_completion(c, id, end, fin, in + STREAM_HEADER, n);
    stream_update *u = stage_stream(c, tx, id);
    if (!u)
        return MIST_RESOURCE_LIMIT;
    if ((u->final_known && (end > u->final || (fin && end != u->final))) ||
        (fin && end < u->high))
        return MIST_PROTOCOL_ERROR;
    if (end > u->s->rx_credit.sent)
        return MIST_FLOW_CONTROL;
    if (end > u->high) {
        uint64_t delta = end - u->high;
        if (delta > c->rx_credit.sent - tx->rx_accounted)
            return MIST_FLOW_CONTROL;
        tx->rx_accounted += delta;
        u->high = end;
    }
    if (fin) {
        u->final_known = true;
        u->final = end;
    }
    u->saw_stream = true;
    return message ? stage_message(u, in + STREAM_HEADER, n) :
                     stage_bytes(tx, u, offset, end, in + STREAM_HEADER);
}

static int parse_max_stream_data(mist_conn *c, transaction *tx, const uint8_t *in)
{
    uint32_t id = (uint32_t)read_be(in + 1, 4);
    bool gone;
    int error = check_stream(c, id, false, &gone);
    if (error || gone)
        return error;
    stream_update *u = stage_stream(c, tx, id);
    if (!u)
        return MIST_RESOURCE_LIMIT;
    u->tx_limit = mist_max(u->tx_limit, read_be(in + 5, 8));
    return 0;
}

static int parse_frames(mist_conn *c, transaction *tx, const uint8_t *in, size_t n)
{
    if (!n)
        return MIST_PROTOCOL_ERROR;
    while (n) {
        size_t size;
        int error = 0;
        if (in[0] != FRAME_ACK)
            tx->eliciting = true;
        switch (in[0]) {
        case FRAME_PING:
            size = 1;
            break;
        case FRAME_ACK: {
            if (n < ACK_MIN_SIZE)
                return MIST_PROTOCOL_ERROR;
            ack_frame *ack = &tx->acks[tx->ack_count];
            if (!decode_ack(c, in, n, ack))
                return MIST_PROTOCOL_ERROR;
            size = 14 + ack->count * 16;
            ++tx->ack_count;
            break;
        }
        case FRAME_STREAM: {
            if (n < STREAM_HEADER)
                return MIST_PROTOCOL_ERROR;
            size_t payload = (size_t)read_be(in + 14, 2);
            if (payload > n - STREAM_HEADER)
                return MIST_PROTOCOL_ERROR;
            size = STREAM_HEADER + payload;
            if (c->state != CLOSING)
                error = parse_stream(c, tx, in, payload);
            break;
        }
        case FRAME_MAX_DATA:
            size = 9;
            if (n < size)
                return MIST_PROTOCOL_ERROR;
            tx->tx_limit = mist_max(tx->tx_limit, read_be(in + 1, 8));
            break;
        case FRAME_MAX_STREAM_DATA:
            size = 13;
            if (n < size)
                return MIST_PROTOCOL_ERROR;
            if (c->state != CLOSING)
                error = parse_max_stream_data(c, tx, in);
            break;
        case FRAME_MAX_STREAMS: {
            size = 6;
            if (n < size || in[1] > 1)
                return MIST_PROTOCOL_ERROR;
            uint64_t limit = read_be(in + 2, 4);
            if (limit > STREAM_LIMIT)
                return MIST_PROTOCOL_ERROR;
            tx->stream_limits[in[1]] = (uint32_t)mist_max(tx->stream_limits[in[1]], limit);
            break;
        }
        case FRAME_CLOSE: {
            size = 3;
            if (n < size)
                return MIST_PROTOCOL_ERROR;
            uint16_t code = (uint16_t)read_be(in + 1, 2);
            if (tx->close && tx->close_code != code)
                return MIST_PROTOCOL_ERROR;
            tx->close = true;
            tx->close_code = code;
            break;
        }
        default:
            return MIST_PROTOCOL_ERROR;
        }
        if (error)
            return error;
        in += size;
        n -= size;
    }
    return 0;
}

static void commit_frames(mist_conn *c, transaction *tx)
{
    c->rx_accounted = tx->rx_accounted;
    c->tx_limit = tx->tx_limit;
    c->classes[c->server].peer_limit = tx->stream_limits[0];
    c->classes[2u + c->server].peer_limit = tx->stream_limits[1];
    for (size_t i = 0; i < tx->stream_count; ++i) {
        stream_update *u = &tx->streams[i];
        stream *s = u->s;
        if (u->is_new)
            insert_stream(c, s);
        if (u->saw_stream && !s->saw_stream && !is_message(s->id) && !is_local(c, s->id))
            s->open_event = true;
        s->saw_stream = u->saw_stream;
        s->rx_high = u->high;
        s->rx_final = u->final;
        s->final_known = u->final_known;
        s->tx_limit = u->tx_limit;
        if (u->new_message) {
            s->message = u->message;
            s->message_event = true;
        }
        while (u->reserved) {
            page *p = u->reserved;
            u->reserved = p->next;
            commit_page(s, p);
        }
    }
    for (size_t i = 0; i < tx->fragment_count; ++i) {
        fragment *f = &tx->fragments[i];
        store_stream_bytes(f->update->s, f->start, f->data, (size_t)(f->end - f->start));
    }
    for (size_t i = 0; i < tx->stream_count; ++i) {
        stream *s = tx->streams[i].s;
        if (!is_message(s->id))
            advance_stream(s);
    }
    process_acks(c, tx->acks, tx->ack_count);
    release_streams(c);
}

static void accept_plaintext(mist_conn *c, uint64_t number, const uint8_t *in, size_t n)
{
    if (number >= PACKET_LIMIT) {
        fail_connection(c, MIST_PROTOCOL_ERROR);
        return;
    }
    transaction tx;
    tx.stream_count = tx.fragment_count = tx.ack_count = 0;
    tx.rx_accounted = c->rx_accounted;
    tx.tx_limit = c->tx_limit;
    tx.stream_limits[0] = c->classes[c->server].peer_limit;
    tx.stream_limits[1] = c->classes[2u + c->server].peer_limit;
    tx.eliciting = tx.close = false;
    int error = parse_frames(c, &tx, in, n);
    if (error || tx.close) {
        discard(&tx);
        if (error)
            fail_connection(c, (uint16_t)error);
        else
            terminate(c, tx.close_code, true);
        return;
    }
    if (c->state == CLOSING) {
        process_acks(c, tx.acks, tx.ack_count);
        if (c->close_attempts && !c->flight_packets)
            terminate(c, c->close_code, false);
        return;
    }
    commit_frames(c, &tx);
    bool confirm = c->state == WAIT_CONFIRM;
    if (confirm)
        establish(c);
    replay_accept(c, number, tx.eliciting, confirm);
}

void data_input(mist_conn *c, const uint8_t *packet, size_t n)
{
    uint64_t number = read_be(packet + COMMON_HEADER, 8);
    if (replay_seen_or_old(c, number))
        return;
    uint8_t nonce[12], plaintext[MAX_PLAINTEXT];
    size_t length = n - DATA_HEADER - TAG_SIZE;
    mist_nonce(nonce, number);
    if (mist_aead_open(plaintext, packet + DATA_HEADER, length, packet,
                       DATA_HEADER, c->recv_key, nonce)) {
        c->last_rx = c->now;
        accept_plaintext(c, number, plaintext, length);
    }
}

static void emit_data(mist_conn *c, const uint8_t *plaintext, size_t n,
                      frame_ref ref, bool probe)
{
    uint8_t nonce[12];
    packet_header(c->datagram, PACKET_DATA, c->cid);
    write_be(c->datagram + COMMON_HEADER, c->tx_number, 8);
    mist_nonce(nonce, c->tx_number);
    mist_aead_seal(c->datagram + DATA_HEADER, plaintext, n, c->datagram,
                   DATA_HEADER, c->send_key, nonce);
    c->datagram_len = DATA_HEADER + n + TAG_SIZE;
    if (ref.type)
        record_sent(c, c->datagram_len, ref, probe);
    ++c->tx_number;
}

static void poll_close(mist_conn *c)
{
    if (c->now < c->close_at)
        return;
    if (c->close_attempts == 3) {
        terminate(c, c->close_code, false);
        return;
    }
    uint8_t frame[3] = {FRAME_CLOSE};
    write_be(frame + 1, c->close_code, 2);
    emit_data(c, frame, sizeof frame, (frame_ref){FRAME_CLOSE, 0, 0}, false);
    ++c->close_attempts;
    c->close_at = mist_add(c->now, 1000000);
}

static size_t normal_budget(const mist_conn *c)
{
    uint64_t overhead = DATA_HEADER + TAG_SIZE;
    if (c->flight_packets >= MAX_FLIGHT_PACKETS ||
        c->stats.cwnd <= c->stats.bytes_in_flight + overhead)
        return 0;
    return (size_t)mist_min(MAX_PLAINTEXT, c->stats.cwnd - c->stats.bytes_in_flight - overhead);
}

uint64_t data_deadline(const mist_conn *c)
{
    uint64_t next = mist_min(window_deadline(c), mist_min(c->pto_at, loss_deadline(c)));
    if (c->ack_pending)
        next = mist_min(next, c->ack_at);
    size_t size;
    if (choose_frame(c, normal_budget(c), false, &size).type)
        next = mist_min(next, mist_max(c->now, c->pace_at));
    return next;
}

void data_poll(mist_conn *c)
{
    if (c->state == CLOSING) {
        poll_close(c);
        return;
    }

    refresh_windows(c);
    detect_loss(c);
    bool probe = c->pto_at != NEVER && c->now >= c->pto_at;
    if (probe)
        make_probe_room(c);
    size_t budget = probe ? MAX_PLAINTEXT : normal_budget(c);
    frame_ref ref = {0};
    size_t size = 0;
    if (probe || c->now >= c->pace_at)
        ref = choose_frame(c, budget, probe, &size);

    uint8_t plaintext[MAX_PLAINTEXT];
    size_t length = 0;
    if (ref.type) {
        length = encode_frame(c, ref, size, plaintext);
        c->first_data = false;
    }
    if (c->ack_pending && (ref.type ? budget - length >= ACK_MIN_SIZE : c->now >= c->ack_at)) {
        uint8_t ack[14 + ACK_RANGES * 16];
        size_t ack_size = encode_ack(c, ack);
        if (!ref.type || (length + ack_size <= budget)) {
            memcpy(plaintext + length, ack, ack_size);
            length += ack_size;
            c->ack_pending = false;
            c->ack_eliciting = 0;
            c->ack_at = NEVER;
        }
    }
    if (length)
        emit_data(c, plaintext, length, ref, probe);
}
