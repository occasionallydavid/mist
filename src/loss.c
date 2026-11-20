#include "internal.h"

static uint64_t pto_interval(const mist_conn *c)
{
    uint64_t interval = 1000000;
    if (c->rtt_valid)
        interval = c->stats.smoothed_rtt_us +
                   mist_max(4 * c->stats.rtt_variance_us, 1000) + ACK_DELAY;
    interval = mist_min(interval, IDLE_TIME);
    for (unsigned i = 0; i < c->pto_backoff && interval < IDLE_TIME; ++i)
        interval = mist_min(interval * 2, IDLE_TIME);
    return interval;
}

static void remove_flight(mist_conn *c, sent_packet *p)
{
    p->outstanding = false;
    slot_set_update(&c->sent_flight, (unsigned)(p - c->sent), false);
    --c->flight_packets;
    c->stats.bytes_in_flight -= p->size;
    if (!c->flight_packets)
        c->pto_at = NEVER;
}

static void congestion_loss(mist_conn *c, const sent_packet *p)
{
    if (c->recovery && p->number <= c->recovery_number)
        return;
    c->recovery = true;
    c->recovery_number = c->tx_number - 1;
    c->stats.ssthresh = mist_max(c->stats.cwnd / 2, MIN_CWND);
    c->stats.cwnd = c->stats.ssthresh;
    c->ca_credit = 0;
}

static void mark_lost(mist_conn *c, sent_packet *p)
{
    remove_flight(c, p);
    congestion_loss(c, p);
    frame_lost(c, p->ref, p->number);
    ++c->stats.packets_lost;
}

static void congestion_ack(mist_conn *c, const sent_packet *p)
{
    if (c->recovery && p->number <= c->recovery_number)
        return;
    if (c->stats.cwnd < c->stats.ssthresh) {
        c->stats.cwnd += p->size;
    } else {
        c->ca_credit += (uint64_t)MIST_MAX_DATAGRAM * p->size;
        uint64_t increase = c->ca_credit / c->stats.cwnd;
        c->ca_credit %= c->stats.cwnd;
        c->stats.cwnd += increase;
    }
}

static void note_rtt(mist_conn *c, uint64_t rtt, uint64_t delay)
{
    mist_stats *s = &c->stats;
    s->latest_rtt_us = rtt;
    if (!c->rtt_valid) {
        c->rtt_valid = true;
        s->min_rtt_us = s->smoothed_rtt_us = rtt;
        s->rtt_variance_us = rtt / 2;
        return;
    }
    s->min_rtt_us = mist_min(s->min_rtt_us, rtt);
    delay = mist_min(delay, ACK_DELAY);
    rtt -= mist_min(delay, rtt - s->min_rtt_us);
    uint64_t diff = mist_max(s->smoothed_rtt_us, rtt) -
                    mist_min(s->smoothed_rtt_us, rtt);
    s->rtt_variance_us = (3 * s->rtt_variance_us + diff) / 4;
    s->smoothed_rtt_us = (7 * s->smoothed_rtt_us + rtt) / 8;
}

static const ack_frame *matching_ack(const ack_frame *acks, size_t count, uint64_t pn)
{
    for (size_t a = 0; a < count; ++a) {
        for (unsigned i = 0; i < acks[a].count; ++i) {
            if (pn > acks[a].range[i].end)
                break;
            if (pn >= acks[a].range[i].start)
                return &acks[a];
        }
    }
    return NULL;
}

void process_acks(mist_conn *c, const ack_frame *acks, size_t count)
{
    if (!count)
        return;
    for (size_t i = 0; i < count; ++i) {
        if (!c->largest_acked_valid || acks[i].largest > c->largest_acked) {
            c->largest_acked = acks[i].largest;
            c->largest_acked_valid = true;
        }
    }
    bool progress = false, sample = false;
    uint64_t sample_number = 0, rtt = 0, delay = 0;
    for (unsigned i = slot_at_or_after(&c->sent_valid, 0); i != NO_SLOT;
         i = slot_at_or_after(&c->sent_valid, i + 1)) {
        sent_packet *p = &c->sent[i];
        const ack_frame *ack = matching_ack(acks, count, p->number);
        if (!ack)
            continue;
        if (p->outstanding) {
            remove_flight(c, p);
            congestion_ack(c, p);
        }
        if (!sample || p->number > sample_number) {
            sample = true;
            sample_number = p->number;
            rtt = c->now - p->time;
            delay = p->number == ack->largest ? ack->delay : 0;
        }
        progress = true;
        frame_acked(c, p->ref);
        slot_set_update(&c->sent_valid, i, false);
    }
    if (sample)
        note_rtt(c, rtt, delay);
    if (progress) {
        c->pto_backoff = 0;
        c->pto_at = c->flight_packets ? mist_add(c->now, pto_interval(c)) : NEVER;
    }
    detect_loss(c);
}

static uint64_t loss_delay(const mist_conn *c)
{
    uint64_t rtt = c->rtt_valid ?
                   mist_max(c->stats.latest_rtt_us, c->stats.smoothed_rtt_us) : 100000;
    return mist_max(1000, rtt + rtt / 8);
}

/* The ring is written in increasing packet-number and timestamp order. */
static unsigned oldest_before_ack(const mist_conn *c)
{
    if (c->largest_acked_valid && c->flight_packets) {
        unsigned slot = flight_slot_at_or_after(c, c->sent_cursor);
        if (c->sent[slot].number < c->largest_acked)
            return slot;
    }
    return NO_SLOT;
}

uint64_t loss_deadline(const mist_conn *c)
{
    unsigned slot = oldest_before_ack(c);
    return slot == NO_SLOT ? NEVER : mist_add(c->sent[slot].time, loss_delay(c));
}

void detect_loss(mist_conn *c)
{
    unsigned slot = oldest_before_ack(c);
    if (slot == NO_SLOT)
        return;
    uint64_t delay = loss_delay(c);
    do {
        sent_packet *p = &c->sent[slot];
        if (c->largest_acked - p->number < 3 && c->now - p->time < delay)
            break;
        mark_lost(c, p);
        slot = oldest_before_ack(c);
    } while (slot != NO_SLOT);
}

void make_probe_room(mist_conn *c)
{
    if (c->flight_packets >= MAX_FLIGHT_PACKETS) {
        unsigned slot = flight_slot_at_or_after(c, c->sent_cursor);
        mark_lost(c, &c->sent[slot]);
    }
}

void record_sent(mist_conn *c, size_t size, frame_ref ref, bool probe)
{
    unsigned slot = c->sent_cursor;
    sent_packet *p = &c->sent[slot];
    if (p->outstanding)
        mark_lost(c, p);
    c->sent_cursor = (slot + 1) % TX_HISTORY;
    *p = (sent_packet){c->tx_number, c->now, ref, (uint16_t)size, true};
    slot_set_update(&c->sent_valid, slot, true);
    slot_set_update(&c->sent_flight, slot, true);
    ++c->flight_packets;
    c->stats.bytes_in_flight += size;
    if (probe) {
        ++c->stats.probe_timeouts;
        if (c->pto_backoff < 32)
            ++c->pto_backoff;
    }
    if (probe || c->flight_packets == 1)
        c->pto_at = mist_add(c->now, pto_interval(c));
    uint64_t rtt = c->rtt_valid ? c->stats.smoothed_rtt_us : 100000;
    uint64_t spacing = size * rtt / c->stats.cwnd;
    c->pace_at = mist_add(c->now, mist_max(1, spacing));
}
