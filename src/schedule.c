#include "internal.h"

static const frame_ref nothing = {0};

static bool pending(const credit *cr, bool probe)
{
    return probe ? cr->acked < cr->sent && cr->sent == cr->limit :
                   cr->limit > cr->sent || cr->lost;
}

static credit *get_credit(mist_conn *c, frame_ref ref)
{
    switch (ref.type) {
    case FRAME_MAX_DATA:
        return &c->rx_credit;
    case FRAME_MAX_STREAMS:
        return &c->classes[(unsigned)!c->server + ref.id * 2u].rx_credit;
    case FRAME_MAX_STREAM_DATA: {
        stream *s = find_stream(c, ref.id);
        return s && !s->retired ? &s->rx_credit : NULL;
    }
    default:
        return NULL;
    }
}

static chunk **find_chunk(stream *s, uint64_t token)
{
    if (!s)
        return NULL;
    chunk **link = &s->head;
    while (*link && (*link)->token != token)
        link = &(*link)->next;
    return *link ? link : NULL;
}

static frame_ref choose_control(const mist_conn *c, size_t budget, bool probe, size_t *size)
{
    if (budget >= 9 && pending(&c->rx_credit, probe)) {
        *size = 9;
        return (frame_ref){FRAME_MAX_DATA, 0, c->rx_credit.limit};
    }
    for (unsigned kind = 0; kind < 2 && budget >= 6; ++kind) {
        const credit *cr = &c->classes[(unsigned)!c->server + kind * 2u].rx_credit;
        if (pending(cr, probe)) {
            *size = 6;
            return (frame_ref){FRAME_MAX_STREAMS, kind, cr->limit};
        }
    }
    for (unsigned k = 0; k < 2 && budget >= 13; ++k) {
        const stream_class *sc = &c->classes[k];
        for (uint32_t i = 0; i < sc->capacity; ++i) {
            const stream *s = sc->slots[i];
            if (s && !s->retired && pending(&s->rx_credit, probe)) {
                *size = 13;
                return (frame_ref){FRAME_MAX_STREAM_DATA, s->id, s->rx_credit.limit};
            }
        }
    }
    return nothing;
}

static frame_ref choose_stream(const mist_conn *c, size_t budget, bool lost,
                               size_t *size)
{
    if (budget < STREAM_HEADER)
        return nothing;
    for (unsigned n = 0; n < 4; ++n) {
        unsigned k = (c->schedule_class + n) % 4;
        const stream_class *sc = &c->classes[k];
        for (uint32_t i = 0; i < sc->capacity; ++i) {
            const stream *s = sc->slots[(c->schedule_slot[k] + i) % sc->capacity];
            if (!s || s->retired)
                continue;
            for (const chunk *item = s->head; item; item = item->next) {
                if (lost) {
                    if (item->state == CHUNK_LOST &&
                        item->sent_length <= budget - STREAM_HEADER) {
                        *size = STREAM_HEADER + item->sent_length;
                        return (frame_ref){FRAME_STREAM, s->id, item->token};
                    }
                    continue;
                }
                if (item->state != CHUNK_NEW)
                    continue;
                uint64_t offset = item->offset + item->used;
                if (offset > s->tx_high || offset > s->tx_limit)
                    break;
                uint64_t limit = mist_min(s->tx_limit, mist_add(s->tx_high,
                                                          c->tx_limit - c->tx_accounted));
                size_t remaining = item->length - item->used;
                size_t length = (size_t)mist_min(remaining, limit - offset);
                length = (size_t)mist_min(length, budget - STREAM_HEADER);
                if ((remaining && !length) || (is_message(s->id) && length < remaining))
                    break;
                *size = STREAM_HEADER + length;
                return (frame_ref){FRAME_STREAM, s->id, item->token};
            }
        }
    }
    return nothing;
}

static frame_ref choose_probe(const mist_conn *c, size_t budget, size_t *size)
{
    const sent_packet *oldest = NULL;
    for (unsigned i = 0; i < TX_HISTORY; ++i) {
        const sent_packet *p = &c->sent[i];
        if (!p->outstanding || (oldest && oldest->number < p->number) ||
            p->ref.type != FRAME_STREAM)
            continue;
        stream *s = find_stream(c, p->ref.id);
        chunk **item = find_chunk(s, p->ref.value);
        if (item && (size_t)(*item)->sent_length + STREAM_HEADER <= budget) {
            oldest = p;
            *size = (*item)->sent_length + STREAM_HEADER;
        }
    }
    if (oldest)
        return oldest->ref;
    *size = 1;
    return (frame_ref){FRAME_PING, 0, 0};
}

frame_ref choose_frame(const mist_conn *c, size_t budget, bool probe, size_t *size)
{
    *size = 0;
    if (!budget)
        return nothing;
    frame_ref ref = choose_control(c, budget, false, size);
    if (!ref.type)
        ref = choose_stream(c, budget, true, size);
    if (!ref.type)
        ref = choose_stream(c, budget, false, size);
    if (!ref.type && probe)
        ref = choose_control(c, budget, true, size);
    if (!ref.type && probe)
        ref = choose_probe(c, budget, size);
    if (!ref.type && c->first_data) {
        *size = 1;
        ref = (frame_ref){FRAME_PING, 0, 0};
    }
    return ref;
}

size_t encode_frame(mist_conn *c, frame_ref ref, size_t size, uint8_t *out)
{
    out[0] = ref.type;
    switch (ref.type) {
    case FRAME_PING:
        return 1;
    case FRAME_STREAM: {
        stream *s = find_stream(c, ref.id);
        chunk *item = *find_chunk(s, ref.value);
        uint64_t offset = item->offset + item->used;
        size_t length = size - STREAM_HEADER;
        write_be(out + 1, s->id, 4);
        write_be(out + 5, offset, 8);
        out[13] = item->fin;
        write_be(out + 14, length, 2);
        memcpy(out + STREAM_HEADER, item->data + item->used, length);
        uint64_t end = offset + length;
        if (end > s->tx_high) {
            c->tx_accounted += end - s->tx_high;
            s->tx_high = end;
        }
        s->tx_announced = true;
        item->sent_length = (uint16_t)length;
        item->packet = c->tx_number;
        item->state = CHUNK_IN_FLIGHT;
        unsigned kind = s->id & 3u;
        c->schedule_slot[kind] = ((s->id >> 2) + 1) % c->classes[kind].capacity;
        c->schedule_class = (kind + 1) % 4;
        return size;
    }
    case FRAME_MAX_DATA:
        write_be(out + 1, ref.value, 8);
        break;
    case FRAME_MAX_STREAM_DATA:
        write_be(out + 1, ref.id, 4);
        write_be(out + 5, ref.value, 8);
        break;
    case FRAME_MAX_STREAMS:
        out[1] = (uint8_t)ref.id;
        write_be(out + 2, ref.value, 4);
        break;
    default:
        return 0;
    }
    credit *cr = get_credit(c, ref);
    cr->sent = ref.value;
    cr->packet = c->tx_number;
    cr->lost = false;
    return size;
}

void frame_acked(mist_conn *c, frame_ref ref)
{
    if (ref.type == FRAME_STREAM) {
        stream *s = find_stream(c, ref.id);
        chunk **link = find_chunk(s, ref.value);
        if (!link)
            return;
        chunk *item = *link;
        item->used += item->sent_length;
        if (item->used != item->length) {
            item->token = ++c->token_next;
            item->state = CHUNK_NEW;
            return;
        }
        if (item->fin)
            s->tx_fin_acked = true;
        *link = item->next;
        if (s->tail == item) {
            s->tail = NULL;
            for (chunk *last = s->head; last; last = last->next)
                s->tail = last;
        }
        c->send_used -= item->length;
        --c->chunks;
        mist_wipe(item->data, item->length);
        free(item);
    } else {
        credit *cr = get_credit(c, ref);
        if (cr) {
            cr->acked = mist_max(cr->acked, ref.value);
            if (cr->acked == cr->sent)
                cr->lost = false;
        }
    }
}

void frame_lost(mist_conn *c, frame_ref ref, uint64_t number)
{
    if (ref.type == FRAME_STREAM) {
        chunk **item = find_chunk(find_stream(c, ref.id), ref.value);
        if (item && (*item)->packet == number)
            (*item)->state = CHUNK_LOST;
    } else {
        credit *cr = get_credit(c, ref);
        if (cr && cr->packet == number && cr->acked < cr->sent)
            cr->lost = true;
    }
}
