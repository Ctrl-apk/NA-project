#ifndef FRAME_H
#define FRAME_H

/*
 * frame.h  —  BinHTTP frame encode / decode
 *
 * Binary layout (big-endian throughout):
 *
 *   Byte  0      : VER            (0x01)
 *   Byte  1      : FRAME_TYPE     (0x01=REQUEST, 0x02=RESPONSE)
 *   Byte  2      : FLAGS          (0x01=END_STREAM)
 *   Bytes 3-6    : PAYLOAD_LENGTH (uint32_t) — bytes after byte 6
 *   Bytes 7-8    : HDR_BLOCK_LEN  (uint16_t) — bytes in header block
 *
 *   For REQUEST  (type 0x01):
 *     Byte  9    : METHOD         (0x01=GET 0x02=POST 0x03=HEAD)
 *     Byte  10   : PATH_LEN       (uint8_t)
 *     Bytes 11.. : PATH           (PATH_LEN bytes)
 *     …          : HEADER BLOCK   (HDR_BLOCK_LEN bytes)
 *     …          : BODY           (remainder)
 *
 *   For RESPONSE (type 0x02):
 *     Byte  9    : STATUS_CLASS   (0x02=2xx 0x04=4xx 0x05=5xx)
 *     Byte  10   : REASON_LEN     (uint8_t)
 *     Bytes 11.. : REASON         (REASON_LEN bytes)
 *     …          : HEADER BLOCK   (HDR_BLOCK_LEN bytes)
 *     …          : BODY           (remainder)
 *
 *   Header block: sequence of (name_len 1B)(name)(val_len 1B)(val) pairs.
 */

#include <stdint.h>
#include <stddef.h>

/* ── platform socket type ───────────────────────────────────────────────
 * On 64-bit Windows, SOCKET is UINT_PTR (8 bytes).  Using plain 'int'
 * truncates the handle.  We define bh_sock_t to be the correct type on
 * each platform.
 */
#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
   typedef SOCKET bh_sock_t;
#  define BH_INVALID_SOCK INVALID_SOCKET
#else
   typedef int bh_sock_t;
#  define BH_INVALID_SOCK (-1)
#endif

/* ── constants ─────────────────────────────────────────────────────────── */

#define BH_VERSION        0x01

#define BH_TYPE_REQUEST   0x01
#define BH_TYPE_RESPONSE  0x02

#define BH_FLAG_END_STREAM 0x01

#define BH_METHOD_GET     0x01
#define BH_METHOD_POST    0x02
#define BH_METHOD_HEAD    0x03

#define BH_STATUS_2XX     0x02   /* 200 OK          */
#define BH_STATUS_4XX     0x04   /* 400 / 404       */
#define BH_STATUS_5XX     0x05   /* 500             */

#define BH_FIXED_HDR_LEN  9      /* bytes before payload */
#define BH_MAX_PAYLOAD    (10 * 1024 * 1024)   /* 10 MB sanity cap */
#define BH_MAX_PATH       255
#define BH_MAX_REASON     255
#define BH_MAX_HEADERS    32

/* ── header pair ───────────────────────────────────────────────────────── */

typedef struct {
    char name[256];
    char value[256];
} bh_header_t;

/* ── decoded frame ─────────────────────────────────────────────────────── */

typedef struct {
    uint8_t  version;
    uint8_t  type;          /* BH_TYPE_REQUEST or BH_TYPE_RESPONSE        */
    uint8_t  flags;

    /* REQUEST fields */
    uint8_t  method;        /* BH_METHOD_*                                 */
    char     path[256];     /* null-terminated                             */

    /* RESPONSE fields */
    uint8_t  status_class;  /* BH_STATUS_*                                 */
    char     reason[256];   /* null-terminated                             */

    /* headers */
    bh_header_t headers[BH_MAX_HEADERS];
    int          header_count;

    /* body */
    uint8_t *body;          /* malloc'd; caller must free                  */
    uint32_t body_len;
} bh_frame_t;

/* ── wire buffer ───────────────────────────────────────────────────────── */

typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} bh_buf_t;

/* ── API ───────────────────────────────────────────────────────────────── */

/*
 * bh_buf_init / bh_buf_free
 *   Manage a growable byte buffer used as the encode target.
 */
void bh_buf_init(bh_buf_t *b);
void bh_buf_free(bh_buf_t *b);

/*
 * bh_encode_request
 *   Serialise a REQUEST frame into *out*.
 *   Returns 0 on success, -1 on error.
 */
int bh_encode_request(bh_buf_t *out,
                      uint8_t   method,
                      const char *path,
                      const bh_header_t *headers, int hdr_count,
                      const uint8_t *body, uint32_t body_len);

/*
 * bh_encode_response
 *   Serialise a RESPONSE frame into *out*.
 *   Returns 0 on success, -1 on error.
 */
int bh_encode_response(bh_buf_t *out,
                       uint8_t   status_class,
                       const char *reason,
                       const bh_header_t *headers, int hdr_count,
                       const uint8_t *body, uint32_t body_len);

/*
 * bh_decode_frame
 *   Parse a frame from *data* (len bytes).
 *   Fills *frame*; allocates frame->body with malloc (caller frees).
 *   Returns number of bytes consumed, or -1 on error.
 */
int bh_decode_frame(const uint8_t *data, size_t len, bh_frame_t *frame);

/*
 * bh_free_frame
 *   Free resources owned by a decoded frame.
 */
void bh_free_frame(bh_frame_t *frame);

/*
 * bh_recv_frame
 *   Read exactly one complete frame from socket sock.
 *   Internally reads the 9-byte fixed header first, then the payload.
 *   Returns 0 on success, -1 on error / EOF.
 */
int bh_recv_frame(bh_sock_t sock, bh_frame_t *frame);

/*
 * bh_send_buf
 *   Write all bytes in buf to sock (handles partial writes).
 *   Returns 0 on success, -1 on error.
 */
int bh_send_buf(bh_sock_t sock, const bh_buf_t *buf);

#endif /* FRAME_H */
