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
        for (unsigned i = slot_at_or_after(&sc->active, 0); i != NO_SLOT;
             i = slot_at_or_after(&sc->active, i + 1)) {
            const stream *s = sc->slots[i];
            if (pending(&s->rx_credit, probe)) {
                *size = 13;
                return (frame_ref){FRAME_MAX_STREAM_DATA, s->id, s->rx_credit.limit};
            }
        }
    }
    return nothing;
}

static const chunk *choose_chunk(const mist_conn *c, const stream *s, size_t budget,
                                 bool lost, size_t *length)
{
    if (lost) {
        for (const chunk *item = s->head; item; item = item->next) {
            if (item->state == CHUNK_LOST && item->sent_length <= budget) {
                *length = item->sent_length;
                return item;
            }
            if (item == s->next_new)
                break;
        }
        return NULL;
    }

    const chunk *item = s->next_new;
    uint64_t offset = item->offset + item->used;
    if (offset > s->tx_high || offset > s->tx_limit)
        return NULL;
    uint64_t limit = mist_min(s->tx_limit, mist_add(s->tx_high, c->tx_limit - c->tx_accounted));
    size_t remaining = item->length - item->used;
    *length = (size_t)mist_min(remaining, mist_min(limit - offset, budget));
    if ((remaining && !*length) || (is_message(s->id) && *length < remaining))
        return NULL;
    return item;
}

static frame_ref choose_stream(const mist_conn *c, size_t budget, bool lost, size_t *size)
{
    if (budget < STREAM_HEADER)
        return nothing;
    for (unsigned n = 0; n < 4; ++n) {
        unsigned k = (c->schedule_class + n) % 4;
        const stream_class *sc = &c->classes[k];
        const slot_set *ready = lost ? &sc->tx_lost : &sc->tx_new;
        if (!ready->occupied)
            continue;
        unsigned i = slot_at_or_after(ready, c->schedule_slot[k]);
        if (i == NO_SLOT)
            i = slot_at_or_after(ready, 0);
        unsigned first = i;
        do {
            const stream *s = sc->slots[i];
            size_t length;
            const chunk *item = choose_chunk(c, s, budget - STREAM_HEADER, lost, &length);
            if (item) {
                *size = STREAM_HEADER + length;
                return (frame_ref){FRAME_STREAM, s->id, item->token};
            }
            i = slot_at_or_after(ready, i + 1);
            if (i == NO_SLOT)
                i = slot_at_or_after(ready, 0);
        } while (i != first);
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

static void remove_lost(stream_class *sc, stream *s, const chunk *item)
{
    if (item->state == CHUNK_LOST && !--s->lost_chunks)
        slot_set_update(&sc->tx_lost, stream_slot(sc, s->id), false);
}

size_t encode_frame(mist_conn *c, frame_ref ref, size_t size, uint8_t *out)
{
    out[0] = ref.type;
    switch (ref.type) {
    case FRAME_PING:
        return 1;
    case FRAME_STREAM: {
        stream *s = find_stream(c, ref.id);
        unsigned kind = s->id & 3u;
        stream_class *sc = &c->classes[kind];
        unsigned slot = stream_slot(sc, s->id);
        chunk *item = s->next_new;
        if (!item || item->token != ref.value) {
            item = *find_chunk(s, ref.value);
            remove_lost(sc, s, item);
        } else {
            s->next_new = item->next;
            if (!s->next_new)
                slot_set_update(&sc->tx_new, slot, false);
        }
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
        c->schedule_slot[kind] = slot + 1 == sc->capacity ? 0 : slot + 1;
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
        stream_class *sc = &c->classes[s->id & 3u];
        remove_lost(sc, s, item);
        item->used += item->sent_length;
        if (item->used != item->length) {
            item->token = ++c->token_next;
            item->state = CHUNK_NEW;
            /* Later offsets are blocked until the remainder is sent. */
            s->next_new = item;
            slot_set_update(&sc->tx_new, stream_slot(sc, s->id), true);
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
        stream *s = find_stream(c, ref.id);
        chunk **link = find_chunk(s, ref.value);
        if (link && (*link)->packet == number && (*link)->state == CHUNK_IN_FLIGHT) {
            (*link)->state = CHUNK_LOST;
            if (++s->lost_chunks == 1) {
                stream_class *sc = &c->classes[s->id & 3u];
                slot_set_update(&sc->tx_lost, stream_slot(sc, s->id), true);
            }
        }
    } else {
        credit *cr = get_credit(c, ref);
        if (cr && cr->packet == number && cr->acked < cr->sent)
            cr->lost = true;
    }
}
