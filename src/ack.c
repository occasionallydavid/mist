#include "internal.h"

bool replay_contains(const mist_conn *c, uint64_t number)
{
    unsigned bit = (unsigned)(number % REPLAY_BITS);
    return (c->replay[bit / 64] >> (bit % 64)) & 1u;
}

bool replay_seen_or_old(const mist_conn *c, uint64_t number)
{
    return c->rx_any && number <= c->rx_largest &&
           (c->rx_largest - number >= REPLAY_BITS || replay_contains(c, number));
}

void replay_accept(mist_conn *c, uint64_t number, bool eliciting, bool confirm)
{
    bool gap = c->rx_any ? number != c->rx_largest + 1 : number != 0;
    if (!c->rx_any || number > c->rx_largest) {
        if (c->rx_any && number - c->rx_largest < REPLAY_BITS) {
            for (uint64_t n = c->rx_largest + 1; n <= number; ++n) {
                unsigned bit = (unsigned)(n % REPLAY_BITS);
                c->replay[bit / 64] &= ~(UINT64_C(1) << (bit % 64));
            }
        } else {
            memset(c->replay, 0, sizeof c->replay);
        }
        c->rx_any = true;
        c->rx_largest = number;
        c->rx_largest_time = c->now;
    }
    unsigned bit = (unsigned)(number % REPLAY_BITS);
    c->replay[bit / 64] |= UINT64_C(1) << (bit % 64);
    if (eliciting || confirm) {
        if (++c->ack_eliciting == 1)
            c->ack_at = mist_add(c->now, ACK_DELAY);
        if (gap || confirm || c->ack_eliciting >= 2)
            c->ack_at = c->now;
        c->ack_pending = true;
    }
}

size_t encode_ack(const mist_conn *c, uint8_t *out)
{
    out[0] = FRAME_ACK;
    write_be(out + 1, c->rx_largest, 8);
    write_be(out + 9, mist_min(c->now - c->rx_largest_time, UINT32_MAX), 4);
    unsigned count = 0;
    uint64_t lower = c->rx_largest - mist_min(c->rx_largest, REPLAY_BITS - 1);
    uint64_t number = c->rx_largest;
    for (;;) {
        if (replay_contains(c, number)) {
            uint64_t end = number;
            while (number > lower && replay_contains(c, number - 1))
                --number;
            write_be(out + 14 + count * 16, number, 8);
            write_be(out + 22 + count * 16, end, 8);
            if (++count == ACK_RANGES)
                break;
        }
        if (number == lower)
            break;
        --number;
    }
    out[13] = (uint8_t)count;
    return 14 + count * 16;
}

bool decode_ack(const mist_conn *c, const uint8_t *in, size_t n, ack_frame *ack)
{
    if (n < 14)
        return false;
    ack->largest = read_be(in + 1, 8);
    ack->delay = read_be(in + 9, 4);
    ack->count = in[13];
    if (!ack->count || ack->count > ACK_RANGES || ack->largest >= c->tx_number ||
        n < 14 + ack->count * 16)
        return false;
    for (unsigned i = 0; i < ack->count; ++i) {
        uint64_t start = read_be(in + 14 + i * 16, 8);
        uint64_t end = read_be(in + 22 + i * 16, 8);
        if (start > end || (i == 0 && end != ack->largest) ||
            (i && end >= ack->range[i - 1].start))
            return false;
        ack->range[i] = (ack_range){start, end};
    }
    return true;
}
