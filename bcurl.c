/*
 * bcurl.c  —  BinHTTP client
 *
 * Usage:  ./bcurl [-v] <host>:<port>/<path>
 *
 *   -v   verbose: hexdump every frame to stderr
 *
 * Behaviour:
 *   • Builds one REQUEST frame (GET method)
 *   • Sends it over a single TCP connection
 *   • Reads the RESPONSE frame
 *   • Writes the body to stdout
 *   • Exits non-zero on 4xx or 5xx status
 *   • Never opens a second connection
 */

/* frame.h brings in winsock2.h on Windows via bh_sock_t */
#include "frame.h"

#ifdef _WIN32
#  include <ws2tcpip.h>
#  define cli_close(s) closesocket(s)
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <unistd.h>
#  define cli_close(s) close(s)
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

/* ── hexdump ──────────────────────────────────────────────────────────── */

static void hexdump(const char *label, const uint8_t *data, size_t len)
{
    fprintf(stderr, "\n── %s  (%zu bytes) ──\n", label, len);
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) fprintf(stderr, "  %04zx  ", i);
        fprintf(stderr, "%02x ", data[i]);
        if (i % 16 == 15 || i == len - 1) {
            /* pad short last line */
            size_t col = i % 16;
            for (size_t pad = col; pad < 15; pad++) fprintf(stderr, "   ");
            fprintf(stderr, " |");
            size_t row_start = i - (i % 16);
            for (size_t j = row_start; j <= i; j++) {
                fprintf(stderr, "%c", isprint(data[j]) ? (char)data[j] : '.');
            }
            fprintf(stderr, "|\n");
        }
    }
    fprintf(stderr, "\n");
}

/* ── annotated hexdump (verbose mode) ────────────────────────────────── */

static void annotate_request(const uint8_t *data, size_t len)
{
    fprintf(stderr, "\n╔══════════════════════════════════════════════════════╗\n");
    fprintf(stderr,   "║         REQUEST FRAME — annotated hexdump           ║\n");
    fprintf(stderr,   "╚══════════════════════════════════════════════════════╝\n");

    if (len < 9) { hexdump("REQUEST (raw)", data, len); return; }

    uint32_t payload_len = ((uint32_t)data[3] << 24) | ((uint32_t)data[4] << 16) |
                           ((uint32_t)data[5] <<  8) |  (uint32_t)data[6];
    uint16_t hdr_blen    = ((uint16_t)data[7] <<  8) |  (uint16_t)data[8];
    uint8_t  path_len    = (len > 10) ? data[10] : 0;

    fprintf(stderr, "  Byte  0      : VER           = 0x%02x  (version %u)\n", data[0], data[0]);
    fprintf(stderr, "  Byte  1      : FRAME_TYPE    = 0x%02x  (%s)\n",
            data[1], data[1] == BH_TYPE_REQUEST ? "REQUEST" : "?");
    fprintf(stderr, "  Byte  2      : FLAGS         = 0x%02x  (%s)\n",
            data[2], (data[2] & BH_FLAG_END_STREAM) ? "END_STREAM" : "none");
    fprintf(stderr, "  Bytes 3-6    : PAYLOAD_LEN   = %u bytes\n", payload_len);
    fprintf(stderr, "  Bytes 7-8    : HDR_BLOCK_LEN = %u bytes\n", hdr_blen);

    if (len > 9) {
        const char *method = data[9] == BH_METHOD_GET  ? "GET"  :
                             data[9] == BH_METHOD_POST ? "POST" :
                             data[9] == BH_METHOD_HEAD ? "HEAD" : "?";
        fprintf(stderr, "  Byte  9      : METHOD        = 0x%02x  (%s)\n", data[9], method);
    }
    if (len > 10) fprintf(stderr, "  Byte  10     : PATH_LEN      = %u\n", path_len);
    if (len > 11 && path_len > 0) {
        char path_buf[256] = {0};
        size_t copy = path_len < 255 ? path_len : 255;
        if (11 + copy <= len) memcpy(path_buf, data + 11, copy);
        fprintf(stderr, "  Bytes 11-%-3zu : PATH          = \"%s\"\n",
                (size_t)(10 + path_len), path_buf);
    }
    fprintf(stderr, "\n");
    hexdump("REQUEST (raw bytes)", data, len);
}

static void annotate_response(const uint8_t *data, size_t len,
                               const bh_frame_t *frame)
{
    fprintf(stderr, "\n╔══════════════════════════════════════════════════════╗\n");
    fprintf(stderr,   "║        RESPONSE FRAME — annotated hexdump           ║\n");
    fprintf(stderr,   "╚══════════════════════════════════════════════════════╝\n");

    if (len < 9) { hexdump("RESPONSE (raw)", data, len); return; }

    uint32_t payload_len = ((uint32_t)data[3] << 24) | ((uint32_t)data[4] << 16) |
                           ((uint32_t)data[5] <<  8) |  (uint32_t)data[6];
    uint16_t hdr_blen    = ((uint16_t)data[7] <<  8) |  (uint16_t)data[8];
    uint8_t  reason_len  = (len > 10) ? data[10] : 0;

    const char *sc_str = data[9] == BH_STATUS_2XX ? "2xx OK"        :
                         data[9] == BH_STATUS_4XX ? "4xx Error"     :
                         data[9] == BH_STATUS_5XX ? "5xx Server Err": "?";

    fprintf(stderr, "  Byte  0      : VER           = 0x%02x  (version %u)\n", data[0], data[0]);
    fprintf(stderr, "  Byte  1      : FRAME_TYPE    = 0x%02x  (%s)\n",
            data[1], data[1] == BH_TYPE_RESPONSE ? "RESPONSE" : "?");
    fprintf(stderr, "  Byte  2      : FLAGS         = 0x%02x  (%s)\n",
            data[2], (data[2] & BH_FLAG_END_STREAM) ? "END_STREAM" : "none");
    fprintf(stderr, "  Bytes 3-6    : PAYLOAD_LEN   = %u bytes\n", payload_len);
    fprintf(stderr, "  Bytes 7-8    : HDR_BLOCK_LEN = %u bytes\n", hdr_blen);
    if (len > 9)  fprintf(stderr, "  Byte  9      : STATUS_CLASS  = 0x%02x  (%s)\n",
                          data[9], sc_str);
    if (len > 10) fprintf(stderr, "  Byte  10     : REASON_LEN    = %u\n", reason_len);

    if (len > 11 && reason_len > 0) {
        char reason_buf[256] = {0};
        size_t copy = reason_len < 255 ? reason_len : 255;
        if (11 + copy <= len) memcpy(reason_buf, data + 11, copy);
        fprintf(stderr, "  Bytes 11-%-3zu : REASON        = \"%s\"\n",
                (size_t)(10 + reason_len), reason_buf);
    }

    fprintf(stderr, "\n  Headers decoded:\n");
    for (int i = 0; i < frame->header_count; i++) {
        fprintf(stderr, "    [%d]  %-16s = %s\n",
                i, frame->headers[i].name, frame->headers[i].value);
    }
    fprintf(stderr, "  Body: %u bytes\n\n", frame->body_len);

    hexdump("RESPONSE (raw bytes)", data, len);
}

/* ── connect helper ───────────────────────────────────────────────────── */

static bh_sock_t tcp_connect(const char *host, int port)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);

    /* try numeric first */
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        /* hostname lookup */
        struct hostent *he = gethostbyname(host);
        if (!he) {
            fprintf(stderr, "[bcurl] cannot resolve host: %s\n", host);
            return BH_INVALID_SOCK;
        }
        memcpy(&addr.sin_addr, he->h_addr_list[0], (size_t)he->h_length);
    }

    bh_sock_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == BH_INVALID_SOCK) { perror("socket"); return BH_INVALID_SOCK; }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        cli_close(fd);
        return BH_INVALID_SOCK;
    }
    return fd;
}

/* ── parse URL  host:port/path ────────────────────────────────────────── */

static int parse_url(const char *url, char *host, int *port, char *path)
{
    /* bcurl localhost:9000/index.html */
    const char *colon = strchr(url, ':');
    if (!colon) return -1;

    size_t hlen = (size_t)(colon - url);
    if (hlen >= 256) return -1;
    memcpy(host, url, hlen);
    host[hlen] = '\0';

    const char *slash = strchr(colon, '/');
    if (!slash) {
        *port = atoi(colon + 1);
        strcpy(path, "/");
    } else {
        char port_str[16];
        size_t plen = (size_t)(slash - colon - 1);
        if (plen >= 16) return -1;
        memcpy(port_str, colon + 1, plen);
        port_str[plen] = '\0';
        *port = atoi(port_str);
        strncpy(path, slash, 255);
        path[255] = '\0';
    }
    return 0;
}

/* ── main ─────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    int verbose = 0;
    const char *url = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) verbose = 1;
        else url = argv[i];
    }

    if (!url) {
        fprintf(stderr, "Usage: %s [-v] <host>:<port>/<path>\n", argv[0]);
        return 1;
    }

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif

    char host[256];
    char path[256];
    int  port;

    if (parse_url(url, host, &port, path) != 0) {
        fprintf(stderr, "[bcurl] invalid URL: %s\n", url);
        return 1;
    }

    fprintf(stderr, "[bcurl] connecting to %s:%d path=%s\n", host, port, path);

    bh_sock_t fd = tcp_connect(host, port);
    if (fd == BH_INVALID_SOCK) return 1;

    /* ── build REQUEST frame ── */
    bh_header_t req_hdrs[2];
    int rhc = 0;

    strcpy(req_hdrs[rhc].name,  "Host");
    {
        /* host is max 255 chars, port is max 5 digits + colon = 262 worst case.
         * Truncate host to 248 chars to guarantee the value fits in 256 bytes. */
        char safe_host[249];
        strncpy(safe_host, host, 248);
        safe_host[248] = '\0';
        snprintf(req_hdrs[rhc].value, 256, "%s:%d", safe_host, port);
    }
    rhc++;

    strcpy(req_hdrs[rhc].name,  "User-Agent");
    strcpy(req_hdrs[rhc].value, "bcurl/1.0");
    rhc++;

    bh_buf_t req_buf;
    bh_buf_init(&req_buf);

    if (bh_encode_request(&req_buf, BH_METHOD_GET, path,
                           req_hdrs, rhc, NULL, 0) != 0) {
        fprintf(stderr, "[bcurl] encode failed\n");
        cli_close(fd);
        return 1;
    }

    if (verbose) {
        annotate_request(req_buf.data, req_buf.len);
    }

    /* ── send it (one and only one connection) ── */
    if (bh_send_buf(fd, &req_buf) != 0) {
        fprintf(stderr, "[bcurl] send failed\n");
        bh_buf_free(&req_buf);
        cli_close(fd);
        return 1;
    }
    bh_buf_free(&req_buf);

    /* ── receive RESPONSE frame ── */
    /*
     * For the annotated hexdump we need the raw bytes too.
     * Re-implement a raw capture receive here.
     */
    uint8_t fixed[9];
    {
        size_t got = 0;
        while (got < 9) {
#ifdef _WIN32
            int r = recv(fd, (char *)fixed + got, (int)(9 - got), 0);
#else
            ssize_t r = read(fd, fixed + got, 9 - got);
#endif
            if (r <= 0) {
                fprintf(stderr, "[bcurl] connection closed before full header\n");
                cli_close(fd);
                return 1;
            }
            got += (size_t)r;
        }
    }

    uint32_t payload_len = ((uint32_t)fixed[3] << 24) | ((uint32_t)fixed[4] << 16) |
                           ((uint32_t)fixed[5] <<  8) |  (uint32_t)fixed[6];

    if (payload_len > (uint32_t)BH_MAX_PAYLOAD) {
        fprintf(stderr, "[bcurl] response payload too large (%u bytes)\n", payload_len);
        cli_close(fd);
        return 1;
    }

    size_t   total   = 9 + payload_len;
    uint8_t *raw_buf = malloc(total);
    if (!raw_buf) { perror("malloc"); cli_close(fd); return 1; }

    memcpy(raw_buf, fixed, 9);

    if (payload_len > 0) {
        size_t got = 0;
        while (got < payload_len) {
#ifdef _WIN32
            int r = recv(fd, (char *)raw_buf + 9 + got, (int)(payload_len - got), 0);
#else
            ssize_t r = read(fd, raw_buf + 9 + got, payload_len - got);
#endif
            if (r <= 0) {
                fprintf(stderr, "[bcurl] connection closed mid-response\n");
                free(raw_buf);
                cli_close(fd);
                return 1;
            }
            got += (size_t)r;
        }
    }

    /* ── decode ── */
    bh_frame_t resp;
    memset(&resp, 0, sizeof(resp));

    if (bh_decode_frame(raw_buf, total, &resp) < 0) {
        fprintf(stderr, "[bcurl] failed to decode response frame\n");
        free(raw_buf);
        cli_close(fd);
        return 1;
    }

    if (verbose) {
        annotate_response(raw_buf, total, &resp);
    }

    /* ── print headers to stderr ── */
    fprintf(stderr, "[bcurl] status_class=0x%02x reason=\"%s\"\n",
            resp.status_class, resp.reason);
    for (int i = 0; i < resp.header_count; i++) {
        fprintf(stderr, "[bcurl]   %s: %s\n",
                resp.headers[i].name, resp.headers[i].value);
    }

    /* ── write body to stdout ── */
    if (resp.body && resp.body_len > 0) {
        fwrite(resp.body, 1, resp.body_len, stdout);
    }

    int exit_code = 0;
    if (resp.status_class == BH_STATUS_4XX || resp.status_class == BH_STATUS_5XX) {
        exit_code = 1;
    }

    bh_free_frame(&resp);
    free(raw_buf);

    /* never open a second connection */
    cli_close(fd);

#ifdef _WIN32
    WSACleanup();
#endif
    return exit_code;
}
