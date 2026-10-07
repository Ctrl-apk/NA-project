/*
 * frame.c  —  BinHTTP frame encode / decode implementation
 */

#include "frame.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
   /* winsock2.h already included via frame.h / bh_sock_t */
#else
#  include <unistd.h>
#  include <arpa/inet.h>
#endif

/* ── internal helpers ──────────────────────────────────────────────────── */

static void put_u8(bh_buf_t *b, uint8_t v)
{
    if (b->len + 1 > b->cap) {
        b->cap = (b->cap == 0) ? 256 : b->cap * 2;
        b->data = realloc(b->data, b->cap);
    }
    b->data[b->len++] = v;
}

static void put_u16be(bh_buf_t *b, uint16_t v)
{
    put_u8(b, (v >> 8) & 0xFF);
    put_u8(b, v & 0xFF);
}

static void put_u32be(bh_buf_t *b, uint32_t v)
{
    put_u8(b, (v >> 24) & 0xFF);
    put_u8(b, (v >> 16) & 0xFF);
    put_u8(b, (v >>  8) & 0xFF);
    put_u8(b, v & 0xFF);
}

static void put_bytes(bh_buf_t *b, const void *src, size_t n)
{
    while (b->len + n > b->cap) {
        b->cap = (b->cap == 0) ? 256 : b->cap * 2;
        b->data = realloc(b->data, b->cap);
    }
    memcpy(b->data + b->len, src, n);
    b->len += n;
}

/* Encode a length-prefixed string (1-byte length) */
static void put_lstr(bh_buf_t *b, const char *s)
{
    uint8_t l = (uint8_t)(strlen(s) & 0xFF);
    put_u8(b, l);
    put_bytes(b, s, l);
}

/* Build the header block into a temporary buffer, return its byte length */
static bh_buf_t encode_headers(const bh_header_t *headers, int count)
{
    bh_buf_t hb;
    bh_buf_init(&hb);
    for (int i = 0; i < count; i++) {
        put_lstr(&hb, headers[i].name);
        put_lstr(&hb, headers[i].value);
    }
    return hb;
}

/* ── public API ────────────────────────────────────────────────────────── */

void bh_buf_init(bh_buf_t *b)
{
    b->data = NULL;
    b->len  = 0;
    b->cap  = 0;
}

void bh_buf_free(bh_buf_t *b)
{
    free(b->data);
    b->data = NULL;
    b->len  = 0;
    b->cap  = 0;
}

/*
 * Frame wire layout reminder:
 *   [0]      VER
 *   [1]      TYPE
 *   [2]      FLAGS
 *   [3..6]   PAYLOAD_LENGTH  (uint32_t BE) — bytes after this field (i.e. byte 7 onward)
 *   [7..8]   HDR_BLOCK_LEN   (uint16_t BE)
 *   [9]      METHOD / STATUS_CLASS
 *   [10]     PATH_LEN / REASON_LEN
 *   [11..]   PATH / REASON
 *   [...]    HEADER BLOCK
 *   [...]    BODY
 */

int bh_encode_request(bh_buf_t *out,
                      uint8_t   method,
                      const char *path,
                      const bh_header_t *headers, int hdr_count,
                      const uint8_t *body, uint32_t body_len)
{
    if (!path || strlen(path) > BH_MAX_PATH) return -1;

    bh_buf_t hb = encode_headers(headers, hdr_count);

    uint8_t  path_len  = (uint8_t)strlen(path);
    uint16_t hdr_blen  = (uint16_t)(hb.len & 0xFFFF);

    /* payload = hdr_block_len(2) + method(1) + path_len(1) + path + hdr_block + body */
    uint32_t payload = 2 + 1 + 1 + path_len + hdr_blen + body_len;

    put_u8(out, BH_VERSION);
    put_u8(out, BH_TYPE_REQUEST);
    put_u8(out, BH_FLAG_END_STREAM);
    put_u32be(out, payload);
    put_u16be(out, hdr_blen);
    put_u8(out, method);
    put_u8(out, path_len);
    put_bytes(out, path, path_len);
    if (hb.len > 0) put_bytes(out, hb.data, hb.len);
    if (body_len > 0) put_bytes(out, body, body_len);

    bh_buf_free(&hb);
    return 0;
}

int bh_encode_response(bh_buf_t *out,
                       uint8_t   status_class,
                       const char *reason,
                       const bh_header_t *headers, int hdr_count,
                       const uint8_t *body, uint32_t body_len)
{
    if (!reason || strlen(reason) > BH_MAX_REASON) return -1;

    bh_buf_t hb = encode_headers(headers, hdr_count);

    uint8_t  reason_len = (uint8_t)strlen(reason);
    uint16_t hdr_blen   = (uint16_t)(hb.len & 0xFFFF);

    /* payload = hdr_block_len(2) + status(1) + reason_len(1) + reason + hdr_block + body */
    uint32_t payload = 2 + 1 + 1 + reason_len + hdr_blen + body_len;

    put_u8(out, BH_VERSION);
    put_u8(out, BH_TYPE_RESPONSE);
    put_u8(out, BH_FLAG_END_STREAM);
    put_u32be(out, payload);
    put_u16be(out, hdr_blen);
    put_u8(out, status_class);
    put_u8(out, reason_len);
    put_bytes(out, reason, reason_len);
    if (hb.len > 0) put_bytes(out, hb.data, hb.len);
    if (body_len > 0) put_bytes(out, body, body_len);

    bh_buf_free(&hb);
    return 0;
}

/* ── decoder ───────────────────────────────────────────────────────────── */

int bh_decode_frame(const uint8_t *data, size_t len, bh_frame_t *frame)
{
    if (len < BH_FIXED_HDR_LEN) return -1;

    memset(frame, 0, sizeof(*frame));

    frame->version = data[0];
    frame->type    = data[1];
    frame->flags   = data[2];

    uint32_t payload_len = ((uint32_t)data[3] << 24) |
                           ((uint32_t)data[4] << 16) |
                           ((uint32_t)data[5] <<  8) |
                            (uint32_t)data[6];

    if (payload_len > (uint32_t)BH_MAX_PAYLOAD) return -1;
    if (len < (size_t)(BH_FIXED_HDR_LEN + payload_len)) return -1;

    uint16_t hdr_blen = ((uint16_t)data[7] << 8) | (uint16_t)data[8];

    const uint8_t *p   = data + BH_FIXED_HDR_LEN;   /* pointer into payload  */
    const uint8_t *end = p + payload_len;            /* one past payload      */

    /* validate minimum variable header: status/method(1) + len(1) */
    if ((size_t)(end - p) < 2) return -1;

    if (frame->type == BH_TYPE_REQUEST) {
        frame->method = *p++;
        uint8_t plen  = *p++;
        if ((size_t)(end - p) < plen) return -1;
        memcpy(frame->path, p, plen);
        frame->path[plen] = '\0';
        p += plen;
    } else if (frame->type == BH_TYPE_RESPONSE) {
        frame->status_class = *p++;
        uint8_t rlen = *p++;
        if ((size_t)(end - p) < rlen) return -1;
        memcpy(frame->reason, p, rlen);
        frame->reason[rlen] = '\0';
        p += rlen;
    } else {
        /*
         * Unknown frame type — skip cleanly (§4 of spec).
         * We return the total consumed bytes so the caller can advance.
         */
        return (int)(BH_FIXED_HDR_LEN + payload_len);
    }

    /* decode header block */
    const uint8_t *hb_end = p + hdr_blen;
    if (hb_end > end) return -1;

    frame->header_count = 0;
    while (p < hb_end && frame->header_count < BH_MAX_HEADERS) {
        if (p >= hb_end) break;
        uint8_t nlen = *p++;
        if (p + nlen > hb_end) return -1;
        memcpy(frame->headers[frame->header_count].name, p, nlen);
        frame->headers[frame->header_count].name[nlen] = '\0';
        p += nlen;

        if (p >= hb_end) return -1;
        uint8_t vlen = *p++;
        if (p + vlen > hb_end) return -1;
        memcpy(frame->headers[frame->header_count].value, p, vlen);
        frame->headers[frame->header_count].value[vlen] = '\0';
        p += vlen;

        frame->header_count++;
    }
    p = hb_end;   /* skip any padding inside the header block */

    /* body is whatever remains */
    frame->body_len = (uint32_t)(end - p);
    if (frame->body_len > 0) {
        frame->body = malloc(frame->body_len);
        if (!frame->body) return -1;
        memcpy(frame->body, p, frame->body_len);
    } else {
        frame->body = NULL;
    }

    return (int)(BH_FIXED_HDR_LEN + payload_len);
}

void bh_free_frame(bh_frame_t *frame)
{
    free(frame->body);
    frame->body = NULL;
}

/* ── socket helpers ────────────────────────────────────────────────────── */

/* Read exactly n bytes from sock, blocking until done or error */
static int read_exact(bh_sock_t sock, uint8_t *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
#ifdef _WIN32
        int r = recv(sock, (char *)(buf + got), (int)(n - got), 0);
#else
        ssize_t r = read(sock, buf + got, n - got);
#endif
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

int bh_recv_frame(bh_sock_t sock, bh_frame_t *frame)
{
    uint8_t fixed[BH_FIXED_HDR_LEN];
    if (read_exact(sock, fixed, BH_FIXED_HDR_LEN) != 0) return -1;

    uint32_t payload_len = ((uint32_t)fixed[3] << 24) |
                           ((uint32_t)fixed[4] << 16) |
                           ((uint32_t)fixed[5] <<  8) |
                            (uint32_t)fixed[6];

    if (payload_len > (uint32_t)BH_MAX_PAYLOAD) return -1;

    /* allocate full frame buffer */
    size_t total = BH_FIXED_HDR_LEN + payload_len;
    uint8_t *buf = malloc(total);
    if (!buf) return -1;

    memcpy(buf, fixed, BH_FIXED_HDR_LEN);
    if (payload_len > 0) {
        if (read_exact(sock, buf + BH_FIXED_HDR_LEN, payload_len) != 0) {
            free(buf);
            return -1;
        }
    }

    int rc = bh_decode_frame(buf, total, frame);
    free(buf);
    return (rc < 0) ? -1 : 0;
}

int bh_send_buf(bh_sock_t sock, const bh_buf_t *buf)
{
    size_t sent = 0;
    while (sent < buf->len) {
#ifdef _WIN32
        int w = send(sock, (const char *)(buf->data + sent), (int)(buf->len - sent), 0);
#else
        ssize_t w = write(sock, buf->data + sent, buf->len - sent);
#endif
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}
