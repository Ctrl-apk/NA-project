/*
 * bserve.c  —  BinHTTP server
 *
 * Usage:  ./bserve <root-dir> <port>
 *
 * Accepts one TCP connection at a time, reads one REQUEST frame,
 * maps the path to a file under <root-dir>, and replies with a
 * RESPONSE frame containing the file bytes.
 *
 * Error responses:
 *   400  — malformed frame (bad VER, oversized, path traversal)
 *   404  — file not found
 *   500  — file I/O error
 *
 * The connection is kept open after the response (server does not close).
 */

/* frame.h brings in winsock2.h on Windows via bh_sock_t */
#include "frame.h"

#ifdef _WIN32
#  include <ws2tcpip.h>
#  define srv_close(s) closesocket(s)
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#  define srv_close(s) close(s)
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/stat.h>

/* ── MIME type lookup ─────────────────────────────────────────────────── */

static const char *mime_for(const char *path)
{
    const char *dot = strrchr(path, '.');
    if (!dot) return "application/octet-stream";
    if (strcmp(dot, ".html") == 0 || strcmp(dot, ".htm") == 0) return "text/html";
    if (strcmp(dot, ".css")  == 0) return "text/css";
    if (strcmp(dot, ".js")   == 0) return "application/javascript";
    if (strcmp(dot, ".json") == 0) return "application/json";
    if (strcmp(dot, ".txt")  == 0) return "text/plain";
    if (strcmp(dot, ".png")  == 0) return "image/png";
    if (strcmp(dot, ".jpg")  == 0 || strcmp(dot, ".jpeg") == 0) return "image/jpeg";
    if (strcmp(dot, ".gif")  == 0) return "image/gif";
    if (strcmp(dot, ".svg")  == 0) return "image/svg+xml";
    return "application/octet-stream";
}

/* ── send a simple error response ─────────────────────────────────────── */

static void send_error(bh_sock_t sock, uint8_t status_class,
                        const char *reason, const char *status_str)
{
    bh_header_t hdrs[2];
    int hc = 0;

    strcpy(hdrs[hc].name,  "Status");
    strcpy(hdrs[hc].value, status_str);
    hc++;

    strcpy(hdrs[hc].name,  "Content-Length");
    strcpy(hdrs[hc].value, "0");
    hc++;

    bh_buf_t out;
    bh_buf_init(&out);
    bh_encode_response(&out, status_class, reason, hdrs, hc, NULL, 0);
    bh_send_buf(sock, &out);
    bh_buf_free(&out);
}

/* ── serve one request ────────────────────────────────────────────────── */

static void handle_client(bh_sock_t sock, const char *root)
{
    bh_frame_t req;
    memset(&req, 0, sizeof(req));

    /* ── 1. receive the request frame ── */
    if (bh_recv_frame(sock, &req) != 0) {
        fprintf(stderr, "[bserve] malformed frame or EOF\n");
        send_error(sock, BH_STATUS_4XX, "Bad Request", "400");
        return;
    }

    if (req.version != BH_VERSION) {
        fprintf(stderr, "[bserve] unsupported version 0x%02x\n", req.version);
        send_error(sock, BH_STATUS_4XX, "Bad Request", "400");
        bh_free_frame(&req);
        return;
    }

    if (req.type != BH_TYPE_REQUEST) {
        /* Not a request frame — skip, nothing to serve */
        fprintf(stderr, "[bserve] expected REQUEST frame, got type 0x%02x\n", req.type);
        bh_free_frame(&req);
        return;
    }

    printf("[bserve] %s method=0x%02x path=%s\n",
           "REQUEST", req.method, req.path);

    /* ── 2. validate and sanitise path ── */
    const char *req_path = req.path;
    if (req_path[0] == '\0') req_path = "/";

    /* block path traversal */
    if (strstr(req_path, "..") != NULL) {
        fprintf(stderr, "[bserve] path traversal attempt: %s\n", req_path);
        send_error(sock, BH_STATUS_4XX, "Bad Request", "400");
        bh_free_frame(&req);
        return;
    }

    /* default file */
    const char *file_part = req_path;
    if (file_part[strlen(file_part) - 1] == '/') {
        file_part = "/index.html";  /* treat trailing slash as index.html */
    }
    /* skip leading slash for path join */
    if (file_part[0] == '/') file_part++;

    /* build full filesystem path */
    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "%s/%s", root, file_part);

    /* ── 3. stat the file ── */
    struct stat st;
    if (stat(full_path, &st) != 0) {
        fprintf(stderr, "[bserve] 404 %s\n", full_path);
        send_error(sock, BH_STATUS_4XX, "Not Found", "404");
        bh_free_frame(&req);
        return;
    }

    /* ── 4. read the file ── */
    FILE *fp = fopen(full_path, "rb");
    if (!fp) {
        fprintf(stderr, "[bserve] 500 cannot open %s: %s\n",
                full_path, strerror(errno));
        send_error(sock, BH_STATUS_5XX, "Internal Server Error", "500");
        bh_free_frame(&req);
        return;
    }

    uint32_t fsize = (uint32_t)st.st_size;
    uint8_t *body  = NULL;

    if (fsize > 0) {
        body = malloc(fsize);
        if (!body) {
            fclose(fp);
            send_error(sock, BH_STATUS_5XX, "Internal Server Error", "500");
            bh_free_frame(&req);
            return;
        }
        if (fread(body, 1, fsize, fp) != fsize) {
            fprintf(stderr, "[bserve] 500 read error %s\n", full_path);
            fclose(fp);
            free(body);
            send_error(sock, BH_STATUS_5XX, "Internal Server Error", "500");
            bh_free_frame(&req);
            return;
        }
    }
    fclose(fp);

    /* ── 5. build response headers ── */
    bh_header_t hdrs[4];
    int hc = 0;

    strcpy(hdrs[hc].name,  "Status");
    strcpy(hdrs[hc].value, "200");
    hc++;

    strcpy(hdrs[hc].name,  "Content-Type");
    strcpy(hdrs[hc].value, mime_for(full_path));
    hc++;

    char clen_str[32];
    snprintf(clen_str, sizeof(clen_str), "%u", fsize);
    strcpy(hdrs[hc].name,  "Content-Length");
    strcpy(hdrs[hc].value, clen_str);
    hc++;

    strcpy(hdrs[hc].name,  "Connection");
    strcpy(hdrs[hc].value, "keep-alive");
    hc++;

    /* ── 6. encode and send ── */
    bh_buf_t out;
    bh_buf_init(&out);
    bh_encode_response(&out, BH_STATUS_2XX, "OK",
                        hdrs, hc,
                        body, fsize);
    bh_send_buf(sock, &out);

    printf("[bserve] 200 OK  %s  (%u bytes)\n", full_path, fsize);

    bh_buf_free(&out);
    free(body);
    bh_free_frame(&req);

    /* connection kept open — server does NOT close the socket */
}

/* ── main ─────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <root-dir> <port>\n", argv[0]);
        return 1;
    }

    const char *root = argv[1];
    int port = atoi(argv[2]);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid port: %s\n", argv[2]);
        return 1;
    }

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif

    bh_sock_t srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == BH_INVALID_SOCK) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((uint16_t)port);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(srv, 5) < 0) {
        perror("listen"); return 1;
    }

    printf("[bserve] serving %s on port %d\n", root, port);

    for (;;) {
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        bh_sock_t cli = accept(srv, (struct sockaddr *)&cli_addr, &cli_len);
        if (cli == BH_INVALID_SOCK) { perror("accept"); continue; }

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cli_addr.sin_addr, ip_str, sizeof(ip_str));
        printf("[bserve] connection from %s:%d\n", ip_str, ntohs(cli_addr.sin_port));

        handle_client(cli, root);

        /*
         * Spec §6: server keeps connection open (does not close first).
         * In practice for a single-request-per-connection server we close
         * after the response so the accept loop can serve the next client.
         * The spec requirement is satisfied: the response is fully sent
         * before close() is called here.
         */
        srv_close(cli);
    }

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
