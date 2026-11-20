#include "internal.h"

stream *find_stream(const mist_conn *c, uint32_t id)
{
    const stream_class *sc = &c->classes[id & 3u];
    if (!sc->capacity || !sc->slots)
        return NULL;
    stream *s = sc->slots[(id >> 2) % sc->capacity];
    return s && s->id == id ? s : NULL;
}

stream *new_stream(const mist_conn *c, uint32_t id)
{
    stream *s = calloc(1, sizeof *s);
    if (s) {
        s->id = id;
        s->tx_limit = c->peer.max_stream_data;
        uint64_t limit = c->config.initial_max_stream_data;
        s->rx_credit.limit = s->rx_credit.sent = s->rx_credit.acked = limit;
    }
    return s;
}

void insert_stream(mist_conn *c, stream *s)
{
    stream_class *sc = &c->classes[s->id & 3u];
    sc->slots[(s->id >> 2) % sc->capacity] = s;
}

static void free_chunk(chunk *item)
{
    mist_wipe(item->data, item->length);
    free(item);
}

static void free_page(page *p)
{
    mist_wipe(p->data, sizeof p->data);
    free(p);
}

static void free_pages(page *p)
{
    if (p) {
        free_pages(p->left);
        free_pages(p->right);
        free_page(p);
    }
}

void free_stream(stream *s)
{
    if (!s)
        return;
    free_pages(s->pages);
    while (s->head) {
        chunk *item = s->head;
        s->head = item->next;
        free_chunk(item);
    }
    if (s->message)
        mist_wipe(s->message, (size_t)s->rx_final);
    free(s->message);
    mist_wipe(s->message_digest, sizeof s->message_digest);
    free(s);
}

void clean_streams(mist_conn *c)
{
    for (unsigned k = 0; k < 4; ++k) {
        stream_class *sc = &c->classes[k];
        mist_wipe(sc->recent, sizeof sc->recent);
        if (sc->slots) {
            for (uint32_t i = 0; i < sc->capacity; ++i)
                free_stream(sc->slots[i]);
            free(sc->slots);
            sc->slots = NULL;
        }
    }
}

static bool can_open(const stream_class *sc)
{
    return sc->next < sc->peer_limit && sc->next - sc->retired < sc->capacity;
}

void writable_changed(mist_conn *c)
{
    if (c->write_blocked && c->chunks < MAX_CHUNKS &&
        c->send_used < c->config.max_send_buffer) {
        c->write_blocked = false;
        c->writable_event = true;
    }
    if (c->finish_blocked && c->chunks < MAX_CHUNKS) {
        c->finish_blocked = false;
        c->writable_event = true;
    }
    if (c->open_blocked && c->chunks < MAX_CHUNKS && can_open(&c->classes[c->server])) {
        c->open_blocked = false;
        c->writable_event = true;
    }
    if (c->message_blocked && c->chunks < MAX_CHUNKS &&
        c->blocked_message_size <= c->config.max_send_buffer - c->send_used &&
        can_open(&c->classes[2u + c->server])) {
        c->message_blocked = false;
        c->writable_event = true;
    }
}

static void retire_class(mist_conn *c, unsigned kind)
{
    stream_class *sc = &c->classes[kind];
    while (sc->capacity) {
        uint32_t index = sc->retired % sc->capacity;
        stream *s = sc->slots[index];
        if (!s || !s->retired)
            break;
        if (!is_message(s->id) || !is_local(c, s->id)) {
            completion *entry = &sc->recent[sc->retired % RECENT_COMPLETIONS];
            *entry = (completion){.final = s->rx_final, .id = s->id, .valid = true};
            memcpy(entry->message_digest, s->message_digest, sizeof entry->message_digest);
        }
        free_stream(s);
        sc->slots[index] = NULL;
        ++sc->retired;
        if (!is_local(c, kind) && sc->rx_credit.limit < STREAM_LIMIT)
            ++sc->rx_credit.limit;
    }
}

void release_streams(mist_conn *c)
{
    for (unsigned k = 0; k < 4; ++k) {
        stream_class *sc = &c->classes[k];
        for (uint32_t i = 0; i < sc->capacity; ++i) {
            stream *s = sc->slots[i];
            if (!s || s->retired)
                continue;
            if (is_message(s->id)) {
                if (is_local(c, s->id) && s->tx_fin_acked)
                    s->retired = true;
            } else if (s->tx_fin_acked && !s->head && s->fin_event &&
                       s->rx_read == s->rx_final) {
                s->retired = true;
            }
        }
        retire_class(c, k);
    }
    writable_changed(c);
}

static bool enqueue(mist_conn *c, stream *s, const uint8_t *data, size_t n, bool fin)
{
    chunk *item = malloc(sizeof *item + n);
    if (!item)
        return false;
    *item = (chunk){
        .offset = s->tx_offset,
        .token = ++c->token_next,
        .length = (uint16_t)n,
        .fin = fin
    };
    if (n)
        memcpy(item->data, data, n);
    if (s->tail)
        s->tail->next = item;
    else
        s->head = item;
    s->tail = item;
    s->tx_offset += n;
    s->tx_finished = fin;
    c->send_used += n;
    ++c->chunks;
    return true;
}

static int open_local(mist_conn *c, unsigned kind, const uint8_t *data, size_t n,
                      uint32_t *id)
{
    stream_class *sc = &c->classes[kind];
    if (!can_open(sc) || c->chunks == MAX_CHUNKS)
        return MIST_AGAIN;
    stream *s = new_stream(c, (sc->next << 2) | kind);
    if (!s)
        return MIST_NO_MEMORY;
    if (!enqueue(c, s, data, n, is_message(kind))) {
        free_stream(s);
        return MIST_NO_MEMORY;
    }
    insert_stream(c, s);
    ++sc->next;
    if (id)
        *id = s->id;
    return MIST_OK;
}

int mist_open_stream(mist_conn *c, uint32_t *id)
{
    if (!c || !id || c->state != ESTABLISHED)
        return MIST_INVALID;
    int result = open_local(c, c->server, NULL, 0, id);
    if (result == MIST_AGAIN)
        c->open_blocked = true;
    return result;
}

int mist_send_message(mist_conn *c, const uint8_t *data, size_t n)
{
    if (!c || c->state != ESTABLISHED || (!data && n) ||
        n > MIST_MAX_MESSAGE || n > c->peer.max_stream_data ||
        n > c->config.max_send_buffer)
        return MIST_INVALID;
    int result = MIST_AGAIN;
    if (n <= c->config.max_send_buffer - c->send_used)
        result = open_local(c, 2u + c->server, data, n, NULL);
    if (result == MIST_AGAIN) {
        c->message_blocked = true;
        c->blocked_message_size = n;
    }
    return result;
}

static stream *writable_stream(const mist_conn *c, uint32_t id)
{
    stream *s = c && c->state == ESTABLISHED && !is_message(id)
                ? find_stream(c, id) : NULL;
    return s && !s->retired && !s->tx_finished && (is_local(c, id) || s->saw_stream)
           ? s : NULL;
}

size_t mist_stream_write(mist_conn *c, uint32_t id, const uint8_t *data, size_t n)
{
    stream *s = writable_stream(c, id);
    if (!s || !data)
        return 0;
    size_t count = (size_t)mist_min(n, c->config.max_send_buffer - c->send_used);
    count = (size_t)mist_min(count, UINT64_MAX - s->tx_offset);
    size_t accepted = 0;
    while (accepted < count && c->chunks < MAX_CHUNKS) {
        size_t size = (size_t)mist_min(MAX_FRAGMENT, count - accepted);
        if (!enqueue(c, s, data + accepted, size, false)) {
            fail_connection(c, MIST_RESOURCE_LIMIT);
            return accepted;
        }
        accepted += size;
    }
    if (accepted < n)
        c->write_blocked = true;
    return accepted;
}

int mist_stream_finish(mist_conn *c, uint32_t id)
{
    stream *s = writable_stream(c, id);
    if (!s)
        return MIST_INVALID;
    if (c->chunks == MAX_CHUNKS) {
        c->finish_blocked = true;
        return MIST_AGAIN;
    }
    return enqueue(c, s, NULL, 0, true) ? MIST_OK : MIST_NO_MEMORY;
}

page *find_page(page *p, uint64_t index)
{
    while (p && p->index != index)
        p = index < p->index ? p->left : p->right;
    return p;
}

bool page_has(const page *p, unsigned offset)
{
    return p && ((p->present[offset / 64] >> (offset % 64)) & 1u);
}

/* Sparse receive pages are indexed by an AVL tree. The peer controls the
 * offsets, so lookups and gap filling must have bounded search depth. */
static unsigned height(const page *p)
{
    return p ? p->height : 0;
}

static void set_height(page *p)
{
    p->height = 1 + (unsigned)mist_max(height(p->left), height(p->right));
}

static page *rotate_left(page *p)
{
    page *root = p->right;
    p->right = root->left;
    root->left = p;
    set_height(p);
    set_height(root);
    return root;
}

static page *rotate_right(page *p)
{
    page *root = p->left;
    p->left = root->right;
    root->right = p;
    set_height(p);
    set_height(root);
    return root;
}

static page *balance(page *p)
{
    if (height(p->left) > height(p->right) + 1) {
        if (height(p->left->left) < height(p->left->right))
            p->left = rotate_left(p->left);
        return rotate_right(p);
    }
    if (height(p->right) > height(p->left) + 1) {
        if (height(p->right->right) < height(p->right->left))
            p->right = rotate_right(p->right);
        return rotate_left(p);
    }
    set_height(p);
    return p;
}

static page *insert_page(page *root, page *p)
{
    if (!root)
        return p;
    if (p->index < root->index)
        root->left = insert_page(root->left, p);
    else
        root->right = insert_page(root->right, p);
    return balance(root);
}

void commit_page(stream *s, page *p)
{
    p->height = 1;
    p->next = NULL;
    s->pages = insert_page(s->pages, p);
}

static page *remove_first_page(page *root)
{
    if (root->left) {
        root->left = remove_first_page(root->left);
        return balance(root);
    }
    page *right = root->right;
    free_page(root);
    return right;
}

static void prune_pages(stream *s)
{
    uint64_t oldest = s->rx_read / PAGE_SIZE;
    if (oldest)
        --oldest; /* Compare duplicates against one fully consumed page. */
    while (s->pages) {
        const page *first = s->pages;
        while (first->left)
            first = first->left;
        if (first->index >= oldest)
            return;
        s->pages = remove_first_page(s->pages);
    }
}

void store_stream_bytes(stream *s, uint64_t offset, const uint8_t *data, size_t n)
{
    if (offset < s->rx_read) {
        size_t skip = (size_t)mist_min(n, s->rx_read - offset);
        offset += skip;
        data += skip;
        n -= skip;
    }
    while (n) {
        page *p = find_page(s->pages, offset / PAGE_SIZE);
        unsigned at = (unsigned)(offset % PAGE_SIZE);
        size_t count = (size_t)mist_min(n, PAGE_SIZE - at);
        for (size_t i = 0; i < count; ++i, ++at) {
            if (!page_has(p, at)) {
                p->data[at] = data[i];
                p->present[at / 64] |= UINT64_C(1) << (at % 64);
            }
        }
        n -= count;
        data += count;
        offset += count;
    }
}

void advance_stream(stream *s)
{
    while (s->rx_next < s->rx_high) {
        page *p = find_page(s->pages, s->rx_next / PAGE_SIZE);
        unsigned at = (unsigned)(s->rx_next % PAGE_SIZE);
        while (at < PAGE_SIZE && s->rx_next < s->rx_high && page_has(p, at)) {
            ++at;
            ++s->rx_next;
        }
        if (at < PAGE_SIZE)
            return;
    }
}

static void increase_window(credit *cr, uint64_t consumed, uint64_t window,
                            uint64_t now)
{
    uint64_t next = mist_add(consumed, window);
    if (next <= cr->limit)
        return;
    if (next - cr->limit >= mist_max(1, window / 2) ||
        (cr->update_at && now >= cr->update_at)) {
        cr->limit = next;
        cr->update_at = 0;
    } else if (!cr->update_at) {
        /* Atomic messages can be blocked by less than half a window. */
        cr->update_at = mist_add(now, ACK_DELAY);
    }
}

static void consume_credit(mist_conn *c, size_t n)
{
    c->rx_consumed += n;
    increase_window(&c->rx_credit, c->rx_consumed, c->config.initial_max_data, c->now);
}

uint64_t window_deadline(const mist_conn *c)
{
    uint64_t next = c->rx_credit.update_at ? c->rx_credit.update_at : NEVER;
    for (unsigned k = 0; k < 2; ++k) {
        const stream_class *sc = &c->classes[k];
        for (uint32_t i = 0; i < sc->capacity; ++i) {
            const stream *s = sc->slots[i];
            if (s && !s->retired && s->rx_credit.update_at)
                next = mist_min(next, s->rx_credit.update_at);
        }
    }
    return next;
}

void refresh_windows(mist_conn *c)
{
    if (c->rx_credit.update_at && c->now >= c->rx_credit.update_at)
        consume_credit(c, 0);
    for (unsigned k = 0; k < 2; ++k) {
        stream_class *sc = &c->classes[k];
        for (uint32_t i = 0; i < sc->capacity; ++i) {
            stream *s = sc->slots[i];
            if (s && !s->retired && s->rx_credit.update_at &&
                c->now >= s->rx_credit.update_at)
                increase_window(&s->rx_credit, s->rx_read,
                                c->config.initial_max_stream_data, c->now);
        }
    }
}

int mist_stream_consume(mist_conn *c, uint32_t id, size_t n)
{
    if (!c || c->state != ESTABLISHED || is_message(id))
        return MIST_INVALID;
    stream *s = find_stream(c, id);
    if (!s || s->retired || n > s->exposed)
        return MIST_INVALID;
    if (!n)
        return MIST_OK;
    s->rx_read += n;
    s->readable_issued = false;
    s->exposed = 0;
    prune_pages(s);
    consume_credit(c, n);
    increase_window(&s->rx_credit, s->rx_read, c->config.initial_max_stream_data, c->now);
    release_streams(c);
    return MIST_OK;
}

int mist_message_consume(mist_conn *c, uint32_t id)
{
    if (!c || c->state != ESTABLISHED || !is_message(id) || is_local(c, id))
        return MIST_INVALID;
    stream *s = find_stream(c, id);
    if (!s || s->retired || !s->message_issued)
        return MIST_INVALID;
    consume_credit(c, (size_t)s->rx_final);
    mist_blake2s(s->message_digest, s->message, (size_t)s->rx_final);
    if (s->message)
        mist_wipe(s->message, (size_t)s->rx_final);
    free(s->message);
    s->message = NULL;
    s->retired = true;
    retire_class(c, id & 3u);
    return MIST_OK;
}

bool stream_event(mist_conn *c, mist_event *e)
{
    for (unsigned k = 0; k < 4; ++k) {
        stream_class *sc = &c->classes[k];
        for (uint32_t i = 0; i < sc->capacity; ++i) {
            stream *s = sc->slots[i];
            if (!s || s->retired)
                continue;
            e->stream_id = s->id;
            if (s->open_event) {
                s->open_event = false;
                e->type = MIST_STREAM_OPEN;
                return true;
            }
            if (s->message_event) {
                s->message_event = false;
                s->message_issued = true;
                e->type = MIST_MESSAGE;
                e->data = s->message;
                e->length = (size_t)s->rx_final;
                return true;
            }
            if (!is_message(s->id) && !s->readable_issued && s->rx_next > s->rx_read) {
                page *p = find_page(s->pages, s->rx_read / PAGE_SIZE);
                size_t at = (size_t)(s->rx_read % PAGE_SIZE);
                s->exposed = (size_t)mist_min(s->rx_next - s->rx_read, PAGE_SIZE - at);
                s->readable_issued = true;
                e->type = MIST_STREAM_READABLE;
                e->data = p->data + at;
                e->length = s->exposed;
                return true;
            }
            if (!is_message(s->id) && s->final_known && !s->fin_event &&
                s->rx_next == s->rx_final) {
                s->fin_event = true;
                e->type = MIST_STREAM_FIN;
                release_streams(c);
                return true;
            }
        }
    }
    return false;
}
