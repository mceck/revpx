#ifndef REVPX_H
#define REVPX_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "ep.h"

#define RP_DEFAULT_BACKEND_HOST "127.0.0.1"
#ifndef RP_MAX_EVENTS
#define RP_MAX_EVENTS 1024
#endif
#ifndef RP_BUF_SIZE
#define RP_BUF_SIZE (32 * 1024)
#endif
#ifndef RP_MAX_FD
#define RP_MAX_FD (64 * 1024)
#endif
#ifndef RP_MAX_DOMAINS
#define RP_MAX_DOMAINS 128
#endif

// ==== Logging ====
enum log_level {
    RP_DEBUG,
    RP_INFO,
    RP_WARN,
    RP_ERROR
};

/**
 * Set the log level for revpx. Messages with a level lower than this will be ignored.
 * Default level is RP_INFO.
 */
void revpx_set_log_level(int level);
/**
 * Set a custom log handler for revpx. The handler will be called with the log level and formatted message.
 * If not set, revpx will use a default log handler that prints to stdout/stderr.
 * Look at rp_colored_log and rp_simple_log for examples of log handlers you can use or customize.
 */
void revpx_set_log_handler(void (*handler)(int level, const char *fmt, ...));
void rp_colored_log(int level, const char *fmt, ...);
void rp_simple_log(int level, const char *fmt, ...);
void revpx_use_colored_log();
void revpx_use_simple_log();
extern void (*rp_log_handler)(int level, const char *fmt, ...);
#define rp_log_info(FMT, ...) rp_log_handler(RP_INFO, FMT __VA_OPT__(, ) __VA_ARGS__)
#define rp_log_debug(FMT, ...) rp_log_handler(RP_DEBUG, FMT __VA_OPT__(, ) __VA_ARGS__)
#define rp_log_warn(FMT, ...) rp_log_handler(RP_WARN, FMT __VA_OPT__(, ) __VA_ARGS__)
#define rp_log_error(FMT, ...) rp_log_handler(RP_ERROR, FMT __VA_OPT__(, ) __VA_ARGS__)

// ==== RevPx API ====

/**
 * Connection state machine:
 *
 *  [accept] -> SSL_HANDSHAKE -> READ_HEADER -> CONNECTING -> PROXYING -> SHUTTING_DOWN
 *                                                  |              |
 *                                                  +-> UPGRADING -+-> TUNNELING -> SHUTTING_DOWN
 *
 *  SSL_HANDSHAKE:  TLS negotiation in progress (client-side only)
 *  READ_HEADER:    Reading the initial HTTP request headers from the client
 *  CONNECTING:     Backend TCP connect() in progress; client data is buffered meanwhile
 *  UPGRADING:      WebSocket: waiting for backend 101 response before switching to tunnel mode
 *  PROXYING:       Bidirectional HTTP proxy with request-boundary tracking (client→backend)
 *  TUNNELING:      Raw bidirectional byte forwarding (WebSocket after 101 upgrade)
 *  SHUTTING_DOWN:  Graceful SSL_shutdown / TCP shutdown in progress
 */
typedef enum {
    ST_SSL_HANDSHAKE,
    ST_READ_HEADER,
    ST_CONNECTING,
    ST_UPGRADING,
    ST_PROXYING,
    ST_TUNNELING,
    ST_SHUTTING_DOWN
} RpConnectionState;

typedef enum {
    CT_CLIENT,
    CT_BACKEND
} RpConnectionType;

typedef struct {
    RpConnectionType type;
    int fd;
    SSL *ssl;           // NULL for plain TCP (backends, HTTP redirect clients)
    int peer;           // fd of the paired connection (client↔backend), -1 if none
    RpConnectionState state;

    // I/O buffer: buf[off .. off+len) contains pending outbound data.
    // For clients in ST_CONNECTING, it temporarily holds incoming request body bytes
    // that arrived before the backend connection was established.
    unsigned char buf[RP_BUF_SIZE];
    size_t len, off;

    bool closing;           // after buffer flush, close/shutdown the connection
    int write_retry_count;  // consecutive failed writes, cleanup after 5
    bool read_stalled;      // reading paused because peer's write buffer is full (backpressure)
    bool websocket;         // request contained Upgrade: websocket

    // Request boundary tracking (backend-side only, used in forward_client_bytes).
    // Enables keep-alive by knowing where one request ends and the next begins,
    // so forwarded-headers can be injected into each new request.
    bool req_need_header;       // next bytes should be the start of a new HTTP request
    bool req_parsing_header;    // accumulating header bytes, waiting for \r\n\r\n
    bool req_chunked;           // current request uses Transfer-Encoding: chunked
    size_t req_body_left;       // remaining Content-Length bytes for the current request

    // Chunked transfer-encoding parser state (backend-side)
    size_t chunk_left;          // bytes remaining in current chunk data
    size_t chunk_size_acc;      // accumulated hex digit value for chunk size line
    int chunk_line_len;         // hex digits parsed so far (max 16)
    bool chunk_expect_crlf;     // expecting CRLF after chunk data
    bool chunk_in_trailer;      // inside trailer section after final 0-size chunk
    bool chunk_in_ext;          // inside chunk extensions (after ';')
    uint32_t chunk_trailer_window; // sliding window to detect \r\n\r\n end of trailers
} RpConnection;

typedef struct {
    char *domain;
    char *host;
    char *port;
    char *cert;
    char *key;
    SSL_CTX *ctx;
} RpHostDomain;

typedef struct {
    int epfd;
    char https_port[16];
    char http_port[16];
    int domain_count;
    bool stop;
    RpHostDomain domains[RP_MAX_DOMAINS];
    RpConnection *conns[RP_MAX_FD];
} RevPx;

/**
 * Create a new RevPx instance.
 * @param http_port Port to listen for HTTP (will redirect to HTTPS)
 * @param https_port Port to listen for HTTPS
 */
RevPx *revpx_create(const char *http_port, const char *https_port);
/**
 * Free a RevPx instance and all associated resources.
 * @param revpx The RevPx instance to free
 */
void revpx_free(RevPx *revpx);
/**
 * Add a domain mapping to the reverse proxy.
 * @param revpx The RevPx instance
 * @param domain The domain name to match (e.g. "example.com")
 * @param host The backend host to forward to (default: "127.0.0.1")
 * @param port The backend port to forward to
 * @param cert The path to the SSL certificate file
 * @param key The path to the SSL key file
 */
bool revpx_add_domain(RevPx *revpx, const char *domain, const char *host, const char *port, const char *cert, const char *key);
/**
 * Start the reverse proxy server.
 * Listens on https_port for HTTPS and redirects HTTP traffic from http_port to HTTPS.
 * @param revpx The RevPx instance
 * @return 0 on success, non-zero on failure
 */
int revpx_run_server(RevPx *revpx);
#endif // REVPX_H

#ifdef REVPX_IMPLEMENTATION
int rp_log_level = RP_INFO;
void revpx_set_log_level(int level) {
    rp_log_level = level;
}

void rp_colored_log(int level, const char *fmt, ...) {
    if (level < rp_log_level) return;

    const char *level_str;
    FILE *fd = level >= RP_ERROR ? stderr : stdout;
    switch (level) {
    case RP_DEBUG:
        level_str = "\033[36mDEBUG\033[0m";
        break;
    case RP_INFO:
        level_str = "\033[32mINFO\033[0m";
        break;
    case RP_WARN:
        level_str = "\033[33mWARN\033[0m";
        break;
    case RP_ERROR:
        level_str = "\033[31mERROR\033[0m";
        break;
    default:
        level_str = "LOG";
        break;
    }

    va_list args;
    va_start(args, fmt);
    fprintf(fd, "[%s] ", level_str);
    vfprintf(fd, fmt, args);
    va_end(args);
}

void rp_simple_log(int level, const char *fmt, ...) {
    if (level < rp_log_level) return;

    const char *level_str;
    FILE *fd = level >= RP_ERROR ? stderr : stdout;
    switch (level) {
    case RP_DEBUG:
        level_str = "DEBUG";
        break;
    case RP_INFO:
        level_str = "INFO";
        break;
    case RP_WARN:
        level_str = "WARN";
        break;
    case RP_ERROR:
        level_str = "ERROR";
        break;
    default:
        level_str = "LOG";
        break;
    }

    va_list args;
    va_start(args, fmt);
    fprintf(fd, "[%s] ", level_str);
    vfprintf(fd, fmt, args);
    va_end(args);
}

void (*rp_log_handler)(int level, const char *fmt, ...) = rp_simple_log;
void revpx_set_log_handler(void (*handler)(int level, const char *fmt, ...)) {
    rp_log_handler = handler;
}
void revpx_use_colored_log(){
    revpx_set_log_handler(rp_colored_log);
}
void revpx_use_simple_log(){
    revpx_set_log_handler(rp_simple_log);
}

static void fill_peer_ip(int fd, char *out, size_t max);
static bool forward_client_bytes(RevPx *revpx, RpConnection *client, RpConnection *backend, const unsigned char *data, size_t n);

static void set_nonblock(int fd) {
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
}

static void ep_add(RevPx *revpx, int fd, uint32_t events) {
    struct epoll_event ev = {.data.fd = fd, .events = events};
    if (epoll_ctl(revpx->epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        rp_log_error("epoll_ctl ADD failed for fd=%d: %s\n", fd, strerror(errno));
    }
}

static void ep_mod(RevPx *revpx, int fd, uint32_t events) {
    struct epoll_event ev = {.data.fd = fd, .events = events};
    if (epoll_ctl(revpx->epfd, EPOLL_CTL_MOD, fd, &ev) < 0) {
        rp_log_error("epoll_ctl MOD failed for fd=%d: %s\n", fd, strerror(errno));
    }
}

/**
 * Close a connection and begin graceful shutdown of its peer.
 * If the peer still has buffered data, it flushes first (closing=true),
 * otherwise it enters ST_SHUTTING_DOWN immediately.
 */
static void cleanup(RevPx *revpx, int fd) {
    if (fd < 0 || fd >= RP_MAX_FD || !revpx->conns[fd]) return;
    RpConnection *c = revpx->conns[fd];
    int peer = c->peer;

    epoll_ctl(revpx->epfd, EPOLL_CTL_DEL, fd, NULL);
    revpx->conns[fd] = NULL;

    if (c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
    }
    close(fd);
    free(c);

    // Signal the peer to drain its buffer and shut down
    if (peer >= 0 && revpx->conns[peer]) {
        RpConnection *p = revpx->conns[peer];
        p->peer = -1;
        if (p->len > 0) {
            p->closing = true;
            ep_mod(revpx, peer, EPOLLOUT | EPOLLET);
        } else {
            p->state = ST_SHUTTING_DOWN;
            ep_mod(revpx, peer, EPOLLOUT | EPOLLET);
        }
    }
}

static void cleanup_both(RevPx *revpx, int fd) {
    if (fd < 0 || fd >= RP_MAX_FD || !revpx->conns[fd]) return;
    int peer = revpx->conns[fd]->peer;

    cleanup(revpx, fd);
    if (peer >= 0 && revpx->conns[peer]) {
        revpx->conns[peer]->peer = -1;
        cleanup(revpx, peer);
    }
}

static RpConnection *alloc_conn(RevPx *revpx, int fd, SSL *ssl, RpConnectionState state, RpConnectionType type) {
    if (fd >= RP_MAX_FD || revpx->conns[fd]) {
        if (fd >= RP_MAX_FD)
            rp_log_error("Too many connections\n");
        else
            rp_log_error("fd in use: %d\n", fd);
        if (ssl) SSL_free(ssl);
        close(fd);
        return NULL;
    }
    RpConnection *c = calloc(1, sizeof(RpConnection));
    c->fd = fd;
    c->ssl = ssl;
    c->peer = -1;
    c->state = state;
    c->type = type;
    revpx->conns[fd] = c;
    return c;
}

static int do_write(RpConnection *c, const void *data, size_t size) {
    return c->ssl ? SSL_write(c->ssl, data, size) : write(c->fd, data, size);
}

static int do_read(RpConnection *c, void *data, size_t size) {
    return c->ssl ? SSL_read(c->ssl, data, size) : read(c->fd, data, size);
}

static int get_error(RpConnection *c, int ret) {
    if (c->ssl) return SSL_get_error(c->ssl, ret);
    return errno == EAGAIN || errno == EWOULDBLOCK ? SSL_ERROR_WANT_WRITE : SSL_ERROR_SYSCALL;
}

static void compact_buffer(RpConnection *c) {
    if (c->off > 0 && c->len > 0) {
        memmove(c->buf, c->buf + c->off, c->len);
        c->off = 0;
    } else if (c->len == 0) {
        c->off = 0;
    }
}

static size_t buffer_space(RpConnection *c) {
    size_t used = c->off + c->len;
    return used < sizeof(c->buf) ? sizeof(c->buf) - used : 0;
}

static void send_error(RevPx *revpx, RpConnection *c, int code, const char *status) {
    char body[1024];
    int body_len = snprintf(body, sizeof(body),
                            "<html><head><title>%d %s</title></head>"
                            "<body><h1>%d %s</h1><p>revpx</p></body></html>",
                            code, status, code, status);

    char header[1024];
    int head_len = snprintf(header, sizeof(header),
                            "HTTP/1.1 %d %s\r\n"
                            "Content-Type: text/html; charset=utf-8\r\n"
                            "Content-Length: %d\r\n"
                            "Connection: close\r\n\r\n",
                            code, status, body_len);
    memcpy(c->buf, header, head_len);
    memcpy(c->buf + head_len, body, body_len);
    c->len = head_len + body_len;
    c->off = 0;
    c->closing = true;
    rp_log_error("Connection error: %d %s\n", code, status);
    ep_mod(revpx, c->fd, EPOLLOUT | EPOLLET);
}

static void send_redirect(RevPx *revpx, RpConnection *c, const char *host, const char *target, const char *port) {
    char resp[2048];
    int n = snprintf(resp, sizeof(resp),
                     "HTTP/1.1 301 Moved Permanently\r\n"
                     "Location: https://%s%s%s%s\r\n"
                     "Content-Length: 0\r\n"
                     "Connection: close\r\n\r\n",
                     host, strcmp(port, "443") ? ":" : "", strcmp(port, "443") ? port : "", target);
    memcpy(c->buf, resp, n);
    c->len = n;
    c->off = 0;
    c->closing = true;
    ep_mod(revpx, c->fd, EPOLLOUT | EPOLLET);
}

static int find_headers_end(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return i + 4;
        }
    }
    return -1;
}

static void extract_host(const unsigned char *buf, size_t len, char *out, size_t max) {
    const char *p = (const char *)buf;
    const char *end = p + len;

    while (p < end) {
        const char *nl = memchr(p, '\n', end - p);
        if (!nl) break;

        if (strncasecmp(p, "Host:", 5) == 0) {
            p += 5;
            while (p < nl && (*p == ' ' || *p == '\t'))
                p++;
            const char *e = nl;
            if (e > p && e[-1] == '\r') e--;
            while (e > p && (e[-1] == ' ' || e[-1] == '\t')) e--;

            size_t n = e - p;
            if (n >= max) n = max - 1;
            memcpy(out, p, n);
            out[n] = '\0';

            if (n > 0 && out[0] == '[') {
                char *endb = memchr(out, ']', n);
                if (endb && endb > out + 1) {
                    size_t host_len = (size_t)(endb - out - 1);
                    if (host_len >= max) host_len = max - 1;
                    memmove(out, out + 1, host_len);
                    out[host_len] = '\0';
                    return;
                }
            }
            char *colon = strrchr(out, ':');
            if (colon && !strchr(colon + 1, ':')) *colon = '\0';
            return;
        }
        p = nl + 1;
    }
    out[0] = '\0';
}

static void extract_target(const unsigned char *buf, size_t len, char *out, size_t max) {
    const char *p = (const char *)buf;
    const char *end = p + len;
    const char *nl = memchr(p, '\n', end - p);
    if (!nl) nl = end;

    const char *sp1 = memchr(p, ' ', nl - p);
    if (!sp1) {
        strcpy(out, "/");
        return;
    }
    sp1++;

    const char *sp2 = memchr(sp1, ' ', nl - sp1);
    if (!sp2) sp2 = nl;

    size_t n = sp2 - sp1;
    if (n >= max) n = max - 1;
    memcpy(out, sp1, n);
    out[n] = '\0';
}

static bool is_websocket_upgrade_request(const unsigned char *buf, size_t len) {
    const char *p = (const char *)buf;
    const char *end = p + len;
    bool upgrade_header_found = false;
    bool connection_header_found = false;

    while (p < end) {
        const char *nl = memchr(p, '\n', end - p);
        if (!nl) break;

        if (strncasecmp(p, "Upgrade:", 8) == 0) {
            const char *value = p + 8;
            while (value < nl && isspace(*value))
                value++;
            if (strncasecmp(value, "websocket", 9) == 0) {
                upgrade_header_found = true;
            }
        }

        if (strncasecmp(p, "Connection:", 11) == 0) {
            const char *value = p + 11;
            const char *nl_end = nl;
            if (nl > p && nl[-1] == '\r') nl_end--;

            const char *c = value;
            while (c < nl_end) {
                if (strncasecmp(c, "Upgrade", 7) == 0) {
                    connection_header_found = true;
                    break;
                }
                c++;
            }
        }

        if (upgrade_header_found && connection_header_found) {
            return true;
        }
        p = nl + 1;
    }

    return false;
}

static unsigned char *find_header_ci_in(const unsigned char *p, size_t header_len, const char *name) {
    size_t name_len = strlen(name);
    const unsigned char *cur = p;
    const unsigned char *end = p + header_len;
    while (cur < end) {
        const unsigned char *nl = (const unsigned char *)memchr(cur, '\n', end - cur);
        if (!nl) break;
        if ((size_t)(nl - cur) >= name_len && strncasecmp((const char *)cur, name, name_len) == 0 && cur[name_len] == ':') {
            return (unsigned char *)cur;
        }
        cur = nl + 1;
    }
    return NULL;
}

static SSL_CTX *get_ctx(RevPx *revpx, const char *host) {
    for (int i = 0; i < revpx->domain_count; i++) {
        RpHostDomain *d = &revpx->domains[i];
        if (strcasecmp(d->domain, host) == 0) {
            if (!d->ctx) {
                d->ctx = SSL_CTX_new(TLS_server_method());
                if (!d->ctx) {
                    rp_log_error("SSL_CTX_new failed for domain %s\n", host);
                    return NULL;
                }
                if (SSL_CTX_use_certificate_file(d->ctx, d->cert, SSL_FILETYPE_PEM) <= 0) {
                    rp_log_error("Failed to load certificate file %s for domain %s\n", d->cert, host);
                    unsigned long ssl_err;
                    while ((ssl_err = ERR_get_error()) != 0) {
                        char err_buf[256];
                        ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
                        rp_log_error("SSL error: %s\n", err_buf);
                    }
                    SSL_CTX_free(d->ctx);
                    d->ctx = NULL;
                    return NULL;
                }
                if (SSL_CTX_use_PrivateKey_file(d->ctx, d->key, SSL_FILETYPE_PEM) <= 0) {
                    rp_log_error("Failed to load private key file %s for domain %s\n", d->key, host);
                    unsigned long ssl_err;
                    while ((ssl_err = ERR_get_error()) != 0) {
                        char err_buf[256];
                        ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
                        rp_log_error("SSL error: %s\n", err_buf);
                    }
                    SSL_CTX_free(d->ctx);
                    d->ctx = NULL;
                    return NULL;
                }
                if (SSL_CTX_check_private_key(d->ctx) != 1) {
                    rp_log_error("Invalid private key for domain %s\n", host);
                    SSL_CTX_free(d->ctx);
                    d->ctx = NULL;
                    return NULL;
                }
                SSL_CTX_set_mode(d->ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
            }
            return d->ctx;
        }
    }
    return NULL;
}

/**
 * SNI callback: select the correct SSL_CTX based on the client's requested hostname.
 * Falls back to the first configured domain if no match (or no SNI extension).
 * Each domain's SSL_CTX is lazily initialized on first use in get_ctx().
 */
static int sni_callback(SSL *ssl, int *ad, void *arg) {
    (void)ad;
    RevPx *revpx = (RevPx *)arg;
    const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    SSL_CTX *ctx = name ? get_ctx(revpx, name) : NULL;
    if (!ctx && revpx->domain_count > 0) {
        ctx = get_ctx(revpx, revpx->domains[0].domain);
    }
    if (ctx) SSL_set_SSL_CTX(ssl, ctx);
    return SSL_TLSEXT_ERR_OK;
}

/**
 * Attempt to write all buffered data (buf[off..off+len)) to the connection.
 * Non-blocking: returns early if the socket would block (WANT_WRITE/WANT_READ),
 * leaving remaining data in the buffer. On full flush, re-enables reading on
 * the peer if it was stalled (backpressure relief).
 */
static void flush_buffer(RevPx *revpx, RpConnection *c) {
    while (c->len > 0) {
        int n = do_write(c, c->buf + c->off, c->len);
        if (n > 0) {
            c->off += n;
            c->len -= n;
            c->write_retry_count = 0;
        } else {
            int err = get_error(c, n);
            if (err == SSL_ERROR_WANT_WRITE) {
                ep_mod(revpx, c->fd, EPOLLOUT | EPOLLET);
                return;
            }
            if (err == SSL_ERROR_WANT_READ) {
                ep_mod(revpx, c->fd, EPOLLIN | EPOLLOUT | EPOLLET);
                return;
            }
            if (err == SSL_ERROR_ZERO_RETURN || (err == SSL_ERROR_SYSCALL && errno == 0)) {
                rp_log_debug("Connection fd=%d closed during flush (SSL_ERROR_ZERO_RETURN)\n", c->fd);
                cleanup_both(revpx, c->fd);
                return;
            }
            if (err == SSL_ERROR_SYSCALL) {
                rp_log_debug("SSL write error fd=%d: %s\n", c->fd, strerror(errno));
            }
            if (c->write_retry_count < 5) {
                c->write_retry_count++;
                ep_mod(revpx, c->fd, EPOLLOUT | EPOLLET);
                return;
            }
            rp_log_error("Connection fd=%d: max write retries exceeded\n", c->fd);
            cleanup(revpx, c->fd);
            return;
        }
    }

    if (c->len == 0) {
        c->off = 0;
        if (c->closing) {
            if (c->ssl) {
                c->state = ST_SHUTTING_DOWN;
                ep_mod(revpx, c->fd, EPOLLOUT | EPOLLET);
            } else {
                cleanup(revpx, c->fd);
            }
        } else {
            RpConnection *peer = c->peer >= 0 ? revpx->conns[c->peer] : NULL;
            if (peer && peer->read_stalled) {
                peer->read_stalled = false;
                ep_mod(revpx, peer->fd, EPOLLIN | EPOLLET);
            }
            ep_mod(revpx, c->fd, EPOLLIN | EPOLLET);
        }
    }
}

/**
 * Bidirectional proxy data transfer between src and its peer (dst).
 *
 * Key design points:
 * - Backpressure: if dst's buffer is full, src stops reading (read_stalled) until
 *   dst flushes, preventing unbounded memory use.
 * - Out-of-order prevention: if dst has buffered data waiting to flush, we must NOT
 *   read new data from src and write it directly — that would bypass the buffer and
 *   deliver data out of order. We wait for the buffer to drain first.
 * - Client→backend direction uses forward_client_bytes() for request boundary tracking
 *   (Content-Length / chunked), enabling keep-alive header injection per request.
 * - Backend→client direction is raw byte forwarding (no response parsing).
 */
static void proxy_data(RevPx *revpx, RpConnection *src, uint32_t events) {
    RpConnection *dst = src->peer >= 0 ? revpx->conns[src->peer] : NULL;

    if (!dst && !src->closing) {
        rp_log_error("Proxy data error: peer connection lost for fd=%d\n", src->fd);
        cleanup(revpx, src->fd);
        return;
    }

    if (events & EPOLLOUT) {
        flush_buffer(revpx, src);
    }

    if ((events & EPOLLIN) && dst) {
        unsigned char temp[RP_BUF_SIZE];

        while (1) {
            dst = src->peer >= 0 ? revpx->conns[src->peer] : NULL;
            if (!dst) {
                cleanup(revpx, src->fd);
                return;
            }

            // Drain any leftover bytes saved in client buffer by forward_client_bytes()
            // when backend was blocked. Must be forwarded before reading new data.
            if (src->len > 0 && src->type == CT_CLIENT && dst->type == CT_BACKEND && !src->websocket && !dst->websocket) {
                size_t saved = src->len;
                unsigned char saved_buf[RP_BUF_SIZE];
                memcpy(saved_buf, src->buf + src->off, saved);
                src->len = 0;
                src->off = 0;
                if (!forward_client_bytes(revpx, src, dst, saved_buf, saved)) return;
                dst = src->peer >= 0 ? revpx->conns[src->peer] : NULL;
                if (!dst) {
                    cleanup(revpx, src->fd);
                    return;
                }
                if (src->len > 0) {
                    // Still can't forward all — wait for backend flush
                    src->read_stalled = true;
                    ep_mod(revpx, dst->fd, EPOLLOUT | EPOLLET);
                    break;
                }
            }

            // CRITICAL: prevent out-of-order writes. If dst has unsent buffered data,
            // any new do_write() would leapfrog the buffer. Stall src until dst drains.
            if (dst->len > 0) {
                compact_buffer(dst);
                if (dst->len > 0) {
                    src->read_stalled = true;
                    ep_mod(revpx, dst->fd, EPOLLOUT | EPOLLET);
                    break;
                }
            }

            size_t dst_space = buffer_space(dst);
            if (dst_space == 0) {
                compact_buffer(dst);
                dst_space = buffer_space(dst);
            }

            if (dst_space == 0) {
                src->read_stalled = true;
                ep_mod(revpx, dst->fd, EPOLLOUT | EPOLLET);
                break;
            }

            size_t to_read = dst_space < sizeof(temp) ? dst_space : sizeof(temp);
            int n = do_read(src, temp, to_read);

            if (n > 0) {
                if (src->type == CT_CLIENT && dst->type == CT_BACKEND && !src->websocket && !dst->websocket) {
                    if (!forward_client_bytes(revpx, src, dst, temp, (size_t)n)) return;
                    continue;
                }
                size_t written = 0;
                while (written < (size_t)n) {
                    int w = do_write(dst, temp + written, n - written);
                    if (w > 0) {
                        written += w;
                        dst->write_retry_count = 0;
                    } else {
                        int err = get_error(dst, w);
                        if (err == SSL_ERROR_WANT_WRITE) break;
                        if (err == SSL_ERROR_WANT_READ) {
                            ep_mod(revpx, dst->fd, EPOLLIN | EPOLLOUT | EPOLLET);
                            break;
                        }
                        if (err == SSL_ERROR_ZERO_RETURN || (err == SSL_ERROR_SYSCALL && errno == 0)) {
                            rp_log_debug("Peer connection fd=%d closed during proxy write\n", dst->fd);
                            cleanup_both(revpx, src->fd);
                            return;
                        }
                        if (err == SSL_ERROR_SYSCALL) {
                            rp_log_debug("SSL proxy write error fd=%d->%d: %s\n", src->fd, dst->fd, strerror(errno));
                        }
                        if (dst->write_retry_count < 5) {
                            dst->write_retry_count++;
                            break;
                        }
                        rp_log_error("Connection fd=%d: max write retries exceeded in proxy\n", dst->fd);
                        cleanup_both(revpx, dst->fd);
                        return;
                    }
                }

                if (written < (size_t)n) {
                    size_t remain = n - written;
                    if (buffer_space(dst) < remain) compact_buffer(dst);
                    if (buffer_space(dst) < remain) {
                        rp_log_error("Buffer overflow: cannot store %zu bytes for fd=%d\n", remain, dst->fd);
                        cleanup_both(revpx, src->fd);
                        return;
                    }
                    memcpy(dst->buf + dst->off + dst->len, temp + written, remain);
                    dst->len += remain;
                    // Stop reading from src until dst buffer is flushed
                    src->read_stalled = true;
                    ep_mod(revpx, dst->fd, EPOLLOUT | EPOLLET);
                    break;
                }
            } else if (n == 0) {
                rp_log_debug("Proxy connection closed by peer fd=%d\n", src->fd);
                cleanup(revpx, src->fd);
                return;
            } else {
                int err = get_error(src, n);
                if (err == SSL_ERROR_WANT_READ) return;
                if (err == SSL_ERROR_WANT_WRITE) {
                    ep_mod(revpx, src->fd, EPOLLOUT | EPOLLIN | EPOLLET);
                    return;
                }
                if (err == SSL_ERROR_ZERO_RETURN || (err == SSL_ERROR_SYSCALL && errno == 0)) {
                    rp_log_debug("Proxy connection fd=%d closed (SSL_ERROR_ZERO_RETURN)\n", src->fd);
                    cleanup(revpx, src->fd);
                    return;
                }
                if (err == SSL_ERROR_SYSCALL) {
                    rp_log_debug("SSL proxy read error fd=%d: %s\n", src->fd, strerror(errno));
                }
                rp_log_debug("Fatal proxy read error fd=%d, error: %d\n", src->fd, err);
                cleanup(revpx, src->fd);
                return;
            }
        }
    }
}

/**
 * Raw bidirectional byte forwarding for WebSocket connections (after 101 upgrade).
 * Unlike proxy_data, no request boundary parsing — just pass bytes through.
 * Still respects backpressure via read_stalled when dst buffer is full.
 */
static void tunnel_data(RevPx *revpx, RpConnection *src, uint32_t events) {
    if (events & EPOLLOUT) {
        flush_buffer(revpx, src);
        if (!revpx->conns[src->fd]) return;
    }

    if (events & EPOLLIN) {
        RpConnection *dst = src->peer >= 0 ? revpx->conns[src->peer] : NULL;
        if (!dst) {
            rp_log_error("WebSocket tunnel error: peer connection lost for fd=%d\n", src->fd);
            cleanup(revpx, src->fd);
            return;
        }

        size_t dst_space = buffer_space(dst);
        if (dst_space == 0) {
            src->read_stalled = 1;
            ep_mod(revpx, dst->fd, EPOLLOUT | EPOLLET);
            return;
        }

        unsigned char temp[RP_BUF_SIZE];
        size_t to_read = dst_space < sizeof(temp) ? dst_space : sizeof(temp);
        int n = do_read(src, temp, to_read);

        if (n > 0) {
            memcpy(dst->buf + dst->off + dst->len, temp, n);
            dst->len += n;
            ep_mod(revpx, dst->fd, EPOLLOUT | EPOLLIN | EPOLLET);
            ep_mod(revpx, src->fd, EPOLLIN | EPOLLET);
        } else if (n == 0) {
            rp_log_debug("WebSocket peer (fd: %d) closed connection.\n", src->fd);
            cleanup_both(revpx, src->fd);
        } else {
            int err = get_error(src, n);

            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                return;
            }

            if (err == SSL_ERROR_SYSCALL && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                return;
            }

            if (src->ssl) {
                unsigned long e;
                while ((e = ERR_get_error()) != 0) {
                    char err_buf[256];
                    ERR_error_string_n(e, err_buf, sizeof(err_buf));
                    rp_log_warn("SSL error in WebSocket tunnel (fd: %d): %s\n", src->fd, err_buf);
                }
            }

            rp_log_warn("Fatal error reading from WebSocket tunnel (fd: %d). Error: %d, errno: %d\n", src->fd, err, errno);
            cleanup_both(revpx, src->fd);
        }
    }
}

static int create_backend(const char *host, const char *port) {
    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0) {
        rp_log_error("getaddrinfo failed for %s:%s: %s\n", host, port, strerror(errno));
        return -1;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        rp_log_error("socket creation failed for backend %s:%s: %s\n", host, port, strerror(errno));
        freeaddrinfo(res);
        return -1;
    }

    set_nonblock(fd);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    return fd;
}

static bool find_header(const unsigned char *buf, size_t len, const char *header_name,
                        const char **value_start, size_t *value_len) {
    const char *p = (const char *)buf;
    const char *end = p + len;
    size_t name_len = strlen(header_name);

    while (p < end) {
        const char *nl = memchr(p, '\n', end - p);
        if (!nl) break;

        if (strncasecmp(p, header_name, name_len) == 0 && p[name_len] == ':') {
            const char *val = p + name_len + 1;
            while (val < nl && (*val == ' ' || *val == '\t'))
                val++;

            const char *val_end = nl;
            if (val_end > p && val_end[-1] == '\r') val_end--;
            if (value_start)
                *value_start = val;
            if (value_len)
                *value_len = val_end - val;
            return true;
        }
        p = nl + 1;
    }
    return false;
}

static bool has_chunked_encoding(const unsigned char *buf, size_t len) {
    const char *te = NULL;
    size_t te_len = 0;
    if (!find_header(buf, len, "Transfer-Encoding", &te, &te_len)) return false;
    for (size_t i = 0; i + 6 < te_len; i++) {
        if (strncasecmp(te + i, "chunked", 7) == 0) return true;
    }
    return false;
}

static int hex_value(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/**
 * Chunked transfer-encoding state machine. Parses chunk framing to track
 * request boundaries without modifying the data.
 *
 * Chunk format:  <hex-size>[;ext]\r\n <data>\r\n ... 0\r\n [trailers]\r\n\r\n
 *
 * Returns number of bytes consumed, or -1 on parse error.
 * When the final chunk (size 0) and trailers are fully consumed, resets
 * req_chunked=false and req_need_header=true so the next request's headers
 * will be parsed and injected with forwarded headers.
 */
static ssize_t advance_chunked(RpConnection *backend, const unsigned char *data, size_t n) {
    size_t i = 0;
    while (i < n) {
        if (backend->chunk_expect_crlf) {
            unsigned char expected = backend->chunk_line_len == 0 ? '\r' : '\n';
            if (data[i] != expected) return -1;
            backend->chunk_line_len++;
            i++;
            if (backend->chunk_line_len == 2) {
                backend->chunk_expect_crlf = false;
                backend->chunk_line_len = 0;
            }
            continue;
        }

        if (backend->chunk_left > 0) {
            size_t take = backend->chunk_left < n - i ? backend->chunk_left : n - i;
            backend->chunk_left -= take;
            i += take;
            if (backend->chunk_left == 0) {
                backend->chunk_expect_crlf = true;
                backend->chunk_line_len = 0;
            }
            continue;
        }

        if (backend->chunk_in_trailer) {
            backend->chunk_trailer_window = (backend->chunk_trailer_window << 8) | data[i];
            backend->chunk_trailer_window &= 0xffffffffu;
            i++;
            if (backend->chunk_trailer_window == 0x0d0a0d0a) {
                backend->req_chunked = false;
                backend->req_need_header = true;
                backend->chunk_in_trailer = false;
                backend->chunk_trailer_window = 0;
                backend->chunk_size_acc = 0;
                backend->chunk_line_len = 0;
                backend->chunk_expect_crlf = false;
                backend->chunk_in_ext = false;
                backend->chunk_left = 0;
                return (ssize_t)i;
            }
            continue;
        }

        unsigned char ch = data[i++];
        if (ch == '\r') continue;
        if (ch == '\n') {
            backend->chunk_left = backend->chunk_size_acc;
            backend->chunk_size_acc = 0;
            backend->chunk_line_len = 0;
            backend->chunk_in_ext = false;
            if (backend->chunk_left == 0) {
                backend->chunk_in_trailer = true;
                backend->chunk_trailer_window = 0x0d0a; // pre-seed with CRLF from chunk-size line
            }
            continue;
        }
        if (ch == ';' || ch == ' ' || ch == '\t') {
            backend->chunk_in_ext = true;
            continue;
        }
        if (backend->chunk_in_ext) continue;
        if (backend->chunk_line_len >= 16) return -1;
        int hv = hex_value(ch);
        if (hv < 0) return -1;
        backend->chunk_size_acc = (backend->chunk_size_acc << 4) | (size_t)hv;
        backend->chunk_line_len++;
    }
    return (ssize_t)n;
}

static bool append_header(char *dst, size_t dst_size, size_t *used, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(dst + *used, dst_size - *used, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= dst_size - *used) return false;
    *used += (size_t)n;
    return true;
}

static void fill_peer_ip(int fd, char *out, size_t max) {
    if (max == 0) return;
    out[0] = '\0';
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    if (getpeername(fd, (struct sockaddr *)&addr, &addr_len) == 0) {
        if (addr.ss_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)&addr;
            inet_ntop(AF_INET, &sa->sin_addr, out, max);
        } else if (addr.ss_family == AF_INET6) {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&addr;
            inet_ntop(AF_INET6, &sa6->sin6_addr, out, max);
        }
    }
    if (out[0] == '\0') {
        strncpy(out, "127.0.0.1", max - 1);
        out[max - 1] = '\0';
    }
}

/**
 * Inject X-Forwarded-For, X-Real-IP, X-Forwarded-Proto/Scheme/Host, and Forwarded
 * headers into the HTTP request stored in conn->buf. Strips any pre-existing
 * forwarded headers to prevent spoofing, then appends client IP from source_fd.
 *
 * The headers are inserted just before the \r\n\r\n terminator. Caller must ensure
 * the buffer only contains headers (body separated beforehand) so there's room.
 */
static bool inject_forwarded_headers(RpConnection *conn, int source_fd) {
    char injected_ip[INET6_ADDRSTRLEN];
    fill_peer_ip(source_fd, injected_ip, sizeof(injected_ip));
    char extra_headers[4096] = "";
    size_t extra_len = 0;
    if (conn->len == 0) return false;
    unsigned char *p = conn->buf;
    int headers_end = find_headers_end(p, conn->len);
    if (headers_end <= 0) return false;

    size_t header_len = (size_t)headers_end;

    const char *ff_value;
    size_t ff_len = 0;
    char ff[512];
    find_header((const unsigned char *)p, header_len, "X-Forwarded-For", &ff_value, &ff_len);
    if (ff_value && ff_len > 0) {
        size_t copy_len = ff_len >= sizeof(ff) ? sizeof(ff) - 1 : ff_len;
        memcpy(ff, ff_value, copy_len);
        ff[copy_len] = '\0';
        size_t used = strlen(ff);
        if (used < sizeof(ff) - 2) {
            ff[used++] = ',';
            ff[used++] = ' ';
        }
        size_t ip_len = strlen(injected_ip);
        if (used + ip_len >= sizeof(ff)) ip_len = sizeof(ff) - used - 1;
        memcpy(ff + used, injected_ip, ip_len);
        ff[used + ip_len] = '\0';
    } else {
        strncpy(ff, injected_ip, sizeof(ff) - 1);
        ff[sizeof(ff) - 1] = '\0';
    }
    if (!append_header(extra_headers, sizeof(extra_headers), &extra_len, "\r\nX-Forwarded-For: %s", ff)) return false;

    const char *to_strip[] = {"Forwarded", "X-Forwarded-For",
                              "X-Forwarded-Proto", "X-Forwarded-Scheme", "X-Forwarded-Host", "X-Real-IP"};
    for (size_t i = 0; i < sizeof(to_strip) / sizeof(to_strip[0]); i++) {
        while (1) {
            unsigned char *hs = find_header_ci_in(p, header_len, to_strip[i]);
            if (!hs) break;
            unsigned char *line_end = (unsigned char *)memchr(hs, '\n', (p + header_len) - hs);
            if (!line_end) break;
            line_end += 1; // include the '\n'
            size_t remove_len = (size_t)(line_end - hs);
            memmove(hs, line_end, (p + conn->len) - line_end);
            conn->len -= remove_len;
            header_len -= remove_len;
            headers_end -= (int)remove_len;
        }
    }

    if (!append_header(extra_headers, sizeof(extra_headers), &extra_len, "\r\nX-Real-IP: %s", injected_ip)) return false;
    if (!append_header(extra_headers, sizeof(extra_headers), &extra_len, "\r\nX-Forwarded-Proto: https")) return false;
    if (!append_header(extra_headers, sizeof(extra_headers), &extra_len, "\r\nX-Forwarded-Scheme: https")) return false;

    const char *host_start = NULL;
    size_t host_len;
    find_header(p, header_len, "Host", &host_start, &host_len);
    if (host_start && host_len > 0) {
        int host_copy = (int)(host_len > 1024 ? 1024 : host_len);
        if (!append_header(extra_headers, sizeof(extra_headers), &extra_len, "\r\nX-Forwarded-Host: %.*s", host_copy, host_start)) return false;
    }
    if (!append_header(extra_headers, sizeof(extra_headers), &extra_len, "\r\nForwarded: proto=https; for=%s", (ff_value && ff_len > 0) ? ff : injected_ip)) return false;
    if (host_start && host_len > 0) {
        int host_copy = (int)(host_len > 1024 ? 1024 : host_len);
        if (!append_header(extra_headers, sizeof(extra_headers), &extra_len, "; host=%.*s", host_copy, host_start)) return false;
    }

    if (conn->len + extra_len >= sizeof(conn->buf)) {
        rp_log_error("Not enough space to inject headers\n");
        return false;
    }
    // Insert before the CRLFCRLF (headers_end - 4)
    memmove(p + headers_end - 4 + extra_len,
            p + headers_end - 4,
            conn->len - (size_t)(headers_end - 4));
    memcpy(p + headers_end - 4, extra_headers, extra_len);
    conn->len += extra_len;

    return true;
}

/**
 * Forward client data to the backend with HTTP request boundary awareness.
 *
 * This is the core of keep-alive support. It operates as a state machine
 * on the backend connection, alternating between two phases:
 *
 * 1. HEADER PARSING (req_parsing_header=true):
 *    Accumulate bytes until \r\n\r\n is found. Once complete:
 *    - Parse Content-Length / Transfer-Encoding to know body boundaries
 *    - Temporarily separate body from headers to make room for injection
 *    - Call inject_forwarded_headers() to add X-Forwarded-For etc.
 *    - Flush headers, then recursively forward the saved body bytes
 *
 * 2. BODY FORWARDING (req_parsing_header=false):
 *    - Content-Length: decrement req_body_left, switch back to header mode at 0
 *    - Chunked: feed bytes through advance_chunked() state machine
 *    - When a request boundary is crossed mid-buffer, the leftover bytes
 *      (belonging to the next request) are recursively forwarded
 *
 * Backpressure: if the backend socket blocks, flush first. If still blocked,
 * save remaining input in the client's buffer and set read_stalled.
 *
 * Returns false if connection was closed/errored (caller should stop processing).
 */
static bool forward_client_bytes(RevPx *revpx, RpConnection *client, RpConnection *backend, const unsigned char *data, size_t n) {
    while (n > 0) {
        if (backend->req_need_header && !backend->req_parsing_header) backend->req_parsing_header = true;
        if (backend->req_parsing_header) compact_buffer(backend);
        size_t space = buffer_space(backend);
        if (space == 0) {
            if (backend->req_parsing_header) {
                send_error(revpx, client, 431, "Request Header Fields Too Large");
                cleanup(revpx, backend->fd);
                return false;
            }
            // Flush buffer to make space
            flush_buffer(revpx, backend);
            if (!revpx->conns[backend->fd]) return false;
            compact_buffer(backend);
            space = buffer_space(backend);
            if (space == 0) {
                // Backend socket blocked after flush — can't write more right now.
                // Save remaining input bytes in the client's own buffer so they
                // aren't lost. proxy_data will drain these before reading new data.
                compact_buffer(client);
                size_t cs = buffer_space(client);
                size_t save = n < cs ? n : cs;
                if (save > 0) {
                    memcpy(client->buf + client->off + client->len, data, save);
                    client->len += save;
                }
                client->read_stalled = true;
                ep_mod(revpx, backend->fd, EPOLLOUT | EPOLLET);
                return true;
            }
        }
        size_t to_copy = n < space ? n : space;
        if (!backend->req_parsing_header && !backend->req_chunked && backend->req_body_left > 0 && to_copy > backend->req_body_left) {
            to_copy = backend->req_body_left;
        }
        unsigned char *dst_pos = backend->buf + backend->off + backend->len;
        memcpy(backend->buf + backend->off + backend->len, data, to_copy);
        backend->len += to_copy;
        data += to_copy;
        n -= to_copy;

        if (backend->req_parsing_header) {
            int end = find_headers_end(backend->buf + backend->off, backend->len);
            if (end > 0) {
                if (backend->off > 0) {
                    memmove(backend->buf, backend->buf + backend->off, backend->len);
                    backend->off = 0;
                }
                end = find_headers_end(backend->buf, backend->len);
                size_t orig_header_end = (size_t)end;

                // Temporarily remove body bytes from the buffer so that
                // inject_forwarded_headers() has room to insert extra headers
                // before the \r\n\r\n. Body will be re-forwarded after flush.
                size_t saved_body_len = backend->len > orig_header_end ? backend->len - orig_header_end : 0;
                unsigned char saved_body[RP_BUF_SIZE];
                if (saved_body_len > 0) {
                    memcpy(saved_body, backend->buf + orig_header_end, saved_body_len);
                    backend->len = orig_header_end;
                }

                // Parse headers before injection (need original headers for CL/TE)
                backend->req_chunked = has_chunked_encoding(backend->buf, orig_header_end);
                backend->req_body_left = 0;
                const char *cl = NULL;
                size_t cl_len = 0;
                if (find_header(backend->buf, orig_header_end, "Content-Length", &cl, &cl_len) && cl_len > 0) {
                    char tmp[32];
                    size_t copy_len = cl_len >= sizeof(tmp) ? sizeof(tmp) - 1 : cl_len;
                    memcpy(tmp, cl, copy_len);
                    tmp[copy_len] = '\0';
                    if (tmp[0] == '-') {
                        backend->req_body_left = 0;
                    } else {
                        backend->req_body_left = strtoull(tmp, NULL, 10);
                    }
                }

                if (!inject_forwarded_headers(backend, client->fd)) {
                    send_error(revpx, client, 400, "Bad Request");
                    cleanup(revpx, backend->fd);
                    return false;
                }

                backend->req_need_header = false;
                backend->req_parsing_header = false;

                // Flush headers, then forward saved body data
                if (saved_body_len > 0) {
                    flush_buffer(revpx, backend);
                    if (!revpx->conns[backend->fd]) return false;
                    backend->off = 0;
                    backend->len = 0;
                    // No body expected → saved bytes are the next request
                    if (backend->req_body_left == 0 && !backend->req_chunked)
                        backend->req_need_header = true;
                    // Forward saved body as new input
                    if (!forward_client_bytes(revpx, client, backend, saved_body, saved_body_len)) return false;
                    return revpx->conns[backend->fd] != NULL;
                }

                size_t header_end = (size_t)find_headers_end(backend->buf, backend->len);
                size_t body_avail = backend->len > header_end ? backend->len - header_end : 0;
                if (backend->req_chunked) {
                    backend->chunk_left = 0;
                    backend->chunk_size_acc = 0;
                    backend->chunk_line_len = 0;
                    backend->chunk_expect_crlf = false;
                    backend->chunk_in_trailer = false;
                    backend->chunk_in_ext = false;
                    backend->chunk_trailer_window = 0;
                    if (body_avail) {
                        ssize_t consumed = advance_chunked(backend, backend->buf + header_end, body_avail);
                        if (consumed < 0) {
                            send_error(revpx, client, 400, "Bad Request");
                            cleanup(revpx, backend->fd);
                            return false;
                        }
                        if ((size_t)consumed < body_avail) {
                            size_t leftover = body_avail - (size_t)consumed;
                            if (backend->len >= leftover) backend->len -= leftover;
                            unsigned char tmpbuf[RP_BUF_SIZE];
                            if (leftover > sizeof(tmpbuf)) {
                                send_error(revpx, client, 413, "Request Entity Too Large");
                                cleanup(revpx, backend->fd);
                                return false;
                            }
                            memcpy(tmpbuf, backend->buf + header_end + consumed, leftover);
                            flush_buffer(revpx, backend);
                            if (!revpx->conns[backend->fd]) return false;
                            if (backend->len > 0) {
                                send_error(revpx, client, 400, "Bad Request");
                                cleanup(revpx, backend->fd);
                                return false;
                            }
                            backend->off = 0;
                            backend->len = 0;
                            backend->req_parsing_header = true;
                            backend->req_need_header = true;
                            if (!forward_client_bytes(revpx, client, backend, tmpbuf, leftover)) return false;
                            return revpx->conns[backend->fd] != NULL;
                        }
                    }
                    if (backend->req_chunked == false) backend->req_parsing_header = false;
                } else {
                    size_t body_used = body_avail < backend->req_body_left ? body_avail : backend->req_body_left;
                    if (backend->req_body_left > 0) backend->req_body_left -= body_used;
                    size_t leftover = body_avail > body_used ? body_avail - body_used : 0;
                    if (backend->req_body_left == 0) {
                        backend->req_need_header = true;
                        backend->req_parsing_header = false;
                    }
                    if (leftover > 0) {
                        if (backend->len >= leftover) backend->len -= leftover;
                        unsigned char tmpbuf[RP_BUF_SIZE];
                        if (leftover > sizeof(tmpbuf)) {
                            send_error(revpx, client, 413, "Request Entity Too Large");
                            cleanup(revpx, backend->fd);
                            return false;
                        }
                        memcpy(tmpbuf, backend->buf + header_end + body_used, leftover);
                        flush_buffer(revpx, backend);
                        if (!revpx->conns[backend->fd]) return false;
                        if (backend->len > 0) {
                            send_error(revpx, client, 400, "Bad Request");
                            cleanup(revpx, backend->fd);
                            return false;
                        }
                        backend->off = 0;
                        backend->len = 0;
                        backend->req_parsing_header = true;
                        backend->req_need_header = true;
                        if (!forward_client_bytes(revpx, client, backend, tmpbuf, leftover)) return false;
                        return revpx->conns[backend->fd] != NULL;
                    }
                }
            }
        } else if (!backend->req_chunked) {
            if (backend->req_body_left > to_copy) {
                backend->req_body_left -= to_copy;
            } else {
                backend->req_body_left = 0;
                backend->req_need_header = true;
                backend->req_parsing_header = false;
            }
        } else {
            ssize_t consumed = advance_chunked(backend, dst_pos, to_copy);
            if (consumed < 0) {
                send_error(revpx, client, 400, "Bad Request");
                cleanup(revpx, backend->fd);
                return false;
            }
            if ((size_t)consumed < to_copy) {
                size_t leftover = to_copy - (size_t)consumed;
                if (backend->len >= leftover) backend->len -= leftover;
                unsigned char tmpbuf[RP_BUF_SIZE];
                if (leftover > sizeof(tmpbuf)) {
                    send_error(revpx, client, 413, "Request Entity Too Large");
                    cleanup(revpx, backend->fd);
                    return false;
                }
                memcpy(tmpbuf, dst_pos + consumed, leftover);
                flush_buffer(revpx, backend);
                if (!revpx->conns[backend->fd]) return false;
                if (backend->len > 0) {
                    send_error(revpx, client, 400, "Bad Request");
                    cleanup(revpx, backend->fd);
                    return false;
                }
                backend->off = 0;
                backend->len = 0;
                backend->req_parsing_header = true;
                backend->req_need_header = true;
                if (!forward_client_bytes(revpx, client, backend, tmpbuf, leftover)) return false;
                return revpx->conns[backend->fd] != NULL;
            }
        }
    }

    if (!backend->req_parsing_header) {
        flush_buffer(revpx, backend);
        if (revpx->conns[backend->fd] && backend->len > 0) ep_mod(revpx, backend->fd, EPOLLOUT | EPOLLIN | EPOLLET);
    }
    return revpx->conns[backend->fd] != NULL;
}

/**
 * Main event dispatcher. Routes epoll events to the appropriate handler
 * based on the connection's current state machine position.
 * Handles EPOLLERR/EPOLLHUP before dispatching to state-specific logic.
 */
static void handle_event(RevPx *revpx, int fd, uint32_t events) {
    RpConnection *c = revpx->conns[fd];
    if (!c) return;

    if (events & EPOLLERR) {
        rp_log_error("EPOLLERR on fd=%d, state=%d\n", fd, c->state);
        if (c->state == ST_CONNECTING) {
            RpConnection *client = revpx->conns[c->peer];
            if (client) {
                send_error(revpx, client, 502, "Bad Gateway");
                client->peer = -1;
            }
            c->peer = -1;
            cleanup(revpx, fd);
        } else if (c->state == ST_PROXYING) {
            cleanup(revpx, fd);
        } else {
            cleanup_both(revpx, fd);
        }
        return;
    }

    if (events & EPOLLHUP) {
        if (c->state == ST_PROXYING && (events & EPOLLIN)) {
            proxy_data(revpx, c, events);
            return;
        }
        if (c->state != ST_SHUTTING_DOWN) {
            rp_log_error("EPOLLHUP on fd=%d, state=%d - unexpected connection hangup\n", fd, c->state);
            cleanup(revpx, fd);
            return;
        }
    }

    // Flush pending outbound data for non-proxy states (proxy_data handles its own flush).
    // Skip for ST_CONNECTING backend fds — they haven't finished connect() yet.
    if (c->state != ST_PROXYING && c->len > 0 && (events & EPOLLOUT)) {
        if (c->state == ST_CONNECTING) goto skip_flush;
        flush_buffer(revpx, c);
        if (!revpx->conns[fd]) return;
    }

skip_flush:
    switch (c->state) {
    case ST_SSL_HANDSHAKE: {
        int ret = SSL_accept(c->ssl);
        if (ret == 1) {
            c->state = ST_READ_HEADER;
            ep_mod(revpx, fd, EPOLLIN | EPOLLET);
        } else {
            int err = SSL_get_error(c->ssl, ret);
            if (err == SSL_ERROR_WANT_READ)
                ep_mod(revpx, fd, EPOLLIN | EPOLLET);
            else if (err == SSL_ERROR_WANT_WRITE)
                ep_mod(revpx, fd, EPOLLOUT | EPOLLET);
            else {
                unsigned long ssl_err;
                while ((ssl_err = ERR_get_error()) != 0) {
                    char err_buf[256];
                    ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
                    rp_log_debug("SSL handshake failed on fd=%d: %s\n", fd, err_buf);
                }
                if (ssl_err == 0) {
                    rp_log_debug("SSL handshake failed on fd=%d, error code: %d\n", fd, err);
                }
                cleanup(revpx, fd);
            }
        }
        break;
    }

    case ST_READ_HEADER: {
        size_t space = sizeof(c->buf) - c->len;
        if (space == 0) {
            rp_log_error("Header too large for fd=%d\n", fd);
            send_error(revpx, c, 431, "Request Header Fields Too Large");
            break;
        }

        int n = do_read(c, c->buf + c->len, space);
        if (n > 0) {
            c->len += n;
            rp_log_debug("Read %d bytes, total header buffer: %zu bytes for fd=%d\n", n, c->len, fd);

            int end = find_headers_end(c->buf, c->len);
            if (end > 0) {
                char host[512], target[1024] = "/";
                extract_host(c->buf, end, host, sizeof(host));
                extract_target(c->buf, end, target, sizeof(target));
                const char *sni_name = c->ssl ? SSL_get_servername(c->ssl, TLSEXT_NAMETYPE_host_name) : NULL;
                if (host[0] == '\0' && sni_name && *sni_name) {
                    strncpy(host, sni_name, sizeof(host) - 1);
                    host[sizeof(host) - 1] = '\0';
                }
                if (!c->ssl && host[0] == '\0') {
                    send_error(revpx, c, 400, "Bad Request");
                    break;
                }
                if (host[0] == '\0' && revpx->domain_count > 0) {
                    strncpy(host, revpx->domains[0].domain, sizeof(host) - 1);
                    host[sizeof(host) - 1] = '\0';
                }

                c->websocket = is_websocket_upgrade_request(c->buf, end);
                if (c->websocket) {
                    rp_log_debug("websocket upgrade request detected\n");
                }

                if (!c->ssl) {
                    send_redirect(revpx, c, host, target, revpx->https_port);
                    break;
                }

                RpHostDomain *d = NULL;
                for (int i = 0; i < revpx->domain_count; i++) {
                    if (strcasecmp(revpx->domains[i].domain, host) == 0) {
                        d = &revpx->domains[i];
                        break;
                    }
                }
                if (!d) {
                    rp_log_error("Domain not found: %s\n", host);
                    send_error(revpx, c, 421, "Misdirected Request");
                    break;
                }
                rp_log_debug("HTTPS request: https://%s%s -> %s:%s\n", host, target, d->host, d->port);

                int backend = create_backend(d->host, d->port);
                if (backend < 0) {
                    rp_log_error("Failed to create backend connection to %s:%s\n", d->host, d->port);
                    send_error(revpx, c, 502, "Bad Gateway");
                    break;
                }

                RpConnection *b = alloc_conn(revpx, backend, NULL, ST_CONNECTING, CT_BACKEND);
                c->peer = backend;
                b->peer = fd;
                c->state = ST_CONNECTING;

                ep_add(revpx, backend, EPOLLOUT | EPOLLET);
            } else {
                rp_log_debug("Headers incomplete (%zu bytes), waiting for more data on fd=%d\n", c->len, fd);
                ep_mod(revpx, fd, EPOLLIN | EPOLLET);
            }
        } else if (n == 0) {
            rp_log_debug("Connection closed during header read fd=%d\n", fd);
            cleanup(revpx, fd);
        } else {
            int err = get_error(c, n);
            if (err == SSL_ERROR_WANT_READ) {
                rp_log_debug("SSL_ERROR_WANT_READ on fd=%d, waiting for more data\n", fd);
            } else if (err == SSL_ERROR_WANT_WRITE) {
                rp_log_debug("SSL_ERROR_WANT_WRITE on fd=%d\n", fd);
                ep_mod(revpx, fd, EPOLLOUT | EPOLLIN | EPOLLET);
            } else {
                if (err == SSL_ERROR_ZERO_RETURN) {
                    rp_log_error("Connection closed during header read fd=%d\n", fd);
                } else if (err == SSL_ERROR_SYSCALL) {
                    rp_log_error("SSL read error during header read fd=%d: %s\n", fd, strerror(errno));
                } else {
                    rp_log_error("Read error during header read fd=%d, error: %d\n", fd, err);
                }
                cleanup(revpx, fd);
            }
        }
        break;
    }

    case ST_CONNECTING: {
        // For SSL clients: the backend TCP connect is in-flight. Meanwhile, the client
        // may keep sending request body data. Buffer it here so it's not lost.
        // Once the backend connects (EPOLLOUT on the backend fd), these buffered bytes
        // are forwarded via forward_client_bytes.
        if (c->ssl) {
            if (events & EPOLLIN) {
                while (1) {
                    compact_buffer(c);
                    size_t space = buffer_space(c);
                    if (space == 0) {
                        // Buffer full — stop reading until backend connects and data is forwarded
                        break;
                    }
                    int n = do_read(c, c->buf + c->off + c->len, space);
                    if (n > 0) {
                        c->len += n;
                        continue;
                    } else if (n == 0) {
                        cleanup_both(revpx, fd);
                        break;
                    } else {
                        int err = get_error(c, n);
                        if (err == SSL_ERROR_WANT_READ) break;
                        if (err == SSL_ERROR_WANT_WRITE) {
                            ep_mod(revpx, fd, EPOLLIN | EPOLLOUT | EPOLLET);
                            break;
                        }
                        cleanup_both(revpx, fd);
                        break;
                    }
                }
            }
            break;
        }

        if (!(events & EPOLLOUT)) break;

        // Backend fd: EPOLLOUT means connect() completed. Check SO_ERROR to
        // distinguish success from failure (async connect reports errors here).
        int err = 0;
        socklen_t len = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
                rp_log_error("getsockopt failed on fd=%d: %s\n", fd, strerror(errno));
            }
            RpConnection *client = revpx->conns[c->peer];
            if (client && !client->websocket) {
                send_error(revpx, client, 502, "Bad Gateway");
                client->peer = -1;
                client->state = ST_READ_HEADER;
            } else {
                rp_log_error("Backend connection failed on fd=%d: %s\n", fd, strerror(err));
            }
            c->peer = -1;
            cleanup(revpx, fd);
            break;
        }

        rp_log_debug("Backend fd=%d connected successfully\n", fd);

        RpConnection *client = revpx->conns[c->peer];
        if (!client) {
            cleanup(revpx, fd);
            break;
        }

        // Initialize request boundary tracking on the backend so
        // forward_client_bytes knows to parse the first request's headers
        c->req_need_header = true;
        c->req_parsing_header = true;
        c->req_chunked = false;
        c->req_body_left = 0;
        c->chunk_left = 0;
        c->chunk_size_acc = 0;
        c->chunk_line_len = 0;
        c->chunk_expect_crlf = false;
        c->chunk_in_trailer = false;
        c->chunk_in_ext = false;
        c->chunk_trailer_window = 0;

        if (client->websocket) {
            c->state = ST_UPGRADING;
            client->state = ST_UPGRADING;
            rp_log_debug("Waiting for websocket upgrade to complete\n");
        } else {
            c->state = ST_PROXYING;
            client->state = ST_PROXYING;
        }

        if (client->len > 0) {
            if (!forward_client_bytes(revpx, client, c, client->buf + client->off, client->len)) {
                break;
            }
            client->off = 0;
            client->len = 0;
        } else {
            rp_log_debug("Backend fd=%d ready, no data to forward yet\n", fd);
        }
        if (revpx->conns[fd]) ep_mod(revpx, fd, EPOLLIN | (revpx->conns[fd]->len ? EPOLLOUT : 0) | EPOLLET);
        if (client && revpx->conns[client->fd]) ep_mod(revpx, client->fd, EPOLLIN | EPOLLET);
        break;
    }

    case ST_UPGRADING: {
        // WebSocket upgrade: read the backend's response. If it's "101 Switching Protocols",
        // copy the response to the client buffer and transition both sides to ST_TUNNELING.
        // Any other response means the upgrade failed → send 502 to client.
        RpConnection *client = revpx->conns[c->peer];
        if (!client) {
            rp_log_error("WebSocket upgrade error: client connection lost for fd=%d\n", fd);
            cleanup(revpx, fd);
            break;
        }

        int n = do_read(c, c->buf + c->len, sizeof(c->buf) - c->len);
        if (n > 0) {
            c->len += n;
        } else if (n <= 0 && errno == EAGAIN) {
            ep_mod(revpx, c->fd, EPOLLIN | EPOLLET);
            break;
        } else if (n <= 0 && get_error(c, n) != SSL_ERROR_WANT_READ) {
            rp_log_error("WebSocket upgrade failed - backend read error fd=%d: %s\n", c->fd, strerror(errno));
            send_error(revpx, client, 502, "Bad Gateway");
            cleanup(revpx, c->fd);
            break;
        }

        if (c->len >= 12 && strncasecmp((char *)c->buf, "HTTP/1.1 101", 12) == 0) {
            rp_log_debug("websocket: handshake success, start tunneling\n");

            c->state = ST_TUNNELING;
            client->state = ST_TUNNELING;

            memcpy(client->buf, c->buf, c->len);
            client->len = c->len;
            client->off = 0;

            c->len = 0;
            c->off = 0;

            rp_log_debug("Copied %zu bytes (101 response) to client fd=%d buffer\n", client->len, client->fd);
            ep_mod(revpx, client->fd, EPOLLOUT | EPOLLIN | EPOLLET);
            ep_mod(revpx, c->fd, EPOLLIN | EPOLLET);
        } else {
            rp_log_warn("Upgrade a WebSocket failed. Backend response:\n%.*s\n", (int)c->len, c->buf);
            send_error(revpx, client, 502, "Bad Gateway: WebSocket handshake failed");
            cleanup(revpx, c->fd);
        }

        break;
    }

    case ST_PROXYING:
        proxy_data(revpx, c, events);
        break;

    case ST_TUNNELING:
        tunnel_data(revpx, c, events);
        break;

    case ST_SHUTTING_DOWN: {
        if (!c->ssl) {
            shutdown(c->fd, SHUT_WR);
            cleanup(revpx, c->fd);
            break;
        }

        int ret = SSL_shutdown(c->ssl);
        if (ret == 1) {
            cleanup(revpx, c->fd);
        } else if (ret == 0) {
            ep_mod(revpx, c->fd, EPOLLIN | EPOLLET);
        } else {
            int err = SSL_get_error(c->ssl, ret);
            if (err == SSL_ERROR_WANT_READ)
                ep_mod(revpx, c->fd, EPOLLIN | EPOLLET);
            else if (err == SSL_ERROR_WANT_WRITE)
                ep_mod(revpx, c->fd, EPOLLOUT | EPOLLET);
            else {
                unsigned long ssl_err;
                while ((ssl_err = ERR_get_error()) != 0) {
                    char err_buf[256];
                    ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
                    rp_log_debug("SSL shutdown error on fd=%d: %s\n", c->fd, err_buf);
                }
                if (ssl_err == 0) {
                    rp_log_debug("SSL shutdown error on fd=%d, error code: %d\n", c->fd, err);
                }
                cleanup(revpx, c->fd);
            }
        }
        break;
    }
    }
}

static int create_listener(const char *port) {
    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, port, &hints, &res) != 0) {
        rp_log_error("getaddrinfo failed for port %s: %s\n", port, strerror(errno));
        return -1;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        rp_log_error("socket creation failed for listener on port %s: %s\n", port, strerror(errno));
        freeaddrinfo(res);
        return -1;
    }

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    if (bind(fd, res->ai_addr, res->ai_addrlen) < 0) {
        if (errno == EADDRINUSE) {
            rp_log_error("bind failed on port %s: address already in use\n", port);
        } else {
            rp_log_error("bind failed on port %s: %s\n", port, strerror(errno));
        }
        close(fd);
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    set_nonblock(fd);
    if (listen(fd, 512) < 0) {
        rp_log_error("listen failed on port %s: %s\n", port, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

bool revpx_add_domain(RevPx *revpx, const char *domain, const char *host, const char *port, const char *cert, const char *key) {
    if (revpx->domain_count >= RP_MAX_DOMAINS) {
        rp_log_error("Maximum number of domains reached\n");
        return false;
    }
    RpHostDomain *d = &revpx->domains[revpx->domain_count++];
    d->domain = strdup(domain);
    if (host && host[0])
        d->host = strdup(host);
    else
        d->host = strdup(RP_DEFAULT_BACKEND_HOST);
    d->port = strdup(port);
    d->cert = strdup(cert);
    d->key = strdup(key);
    d->ctx = NULL;
    return true;
}

void print_art() {
    printf("__________            __________         \n"
           "\\______   \\ _______  _\\______   \\___  ___\n"
           " |       _// __ \\  \\/ /|     ___/\\  \\/  /\n"
           " |    |   \\  ___/\\   / |    |     >    < \n"
           " |____|_  /\\___  >\\_/  |____|    /__/\\_ \\\n"
           "        \\/     \\/                      \\/\n");
}

void print_proxy_domains(RevPx *revpx) {
    printf("\nDomains:\n");
    for (int i = 0; i < revpx->domain_count; i++) {
        RpHostDomain *d = &revpx->domains[i];
        printf("https://%-32s -> %s:%s\n", d->domain, strcmp(d->host, RP_DEFAULT_BACKEND_HOST) ? d->host : "", d->port);
    }
    printf("\n");
}

int revpx_run_server(RevPx *revpx) {
    print_art();
    print_proxy_domains(revpx);

    signal(SIGPIPE, SIG_IGN);
    SSL_library_init();
    SSL_load_error_strings();

    revpx->epfd = epoll_create1(0);
    if (revpx->epfd < 0) {
        rp_log_error("epoll_create1 failed: %s\n", strerror(errno));
        return -1;
    }
    memset(revpx->conns, 0, sizeof(revpx->conns));
    revpx->stop = false;

    int https_fd = create_listener(revpx->https_port);
    if (https_fd < 0) {
        rp_log_error("Failed to create https listener on port %s\n", revpx->https_port);
        return -1;
    }
    ep_add(revpx, https_fd, EPOLLIN | EPOLLET);
    rp_log_info("Listening https on %s\n", revpx->https_port);

    int http_fd = -1;
    if (*revpx->http_port) {
        http_fd = create_listener(revpx->http_port);
        if (http_fd < 0) {
            rp_log_error("Failed to create http listener on port %s\n", revpx->http_port);
            close(https_fd);
            return -1;
        }
        ep_add(revpx, http_fd, EPOLLIN | EPOLLET);
        rp_log_info("Redirecting http %s -> %s\n", revpx->http_port, revpx->https_port);
    }

    SSL_CTX *root_ctx = SSL_CTX_new(TLS_server_method());
    if (!root_ctx) {
        rp_log_error("SSL_CTX_new failed for root context\n");
        unsigned long ssl_err;
        while ((ssl_err = ERR_get_error()) != 0) {
            char err_buf[256];
            ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
            rp_log_error("SSL error: %s\n", err_buf);
        }
        if (http_fd >= 0) close(http_fd);
        close(https_fd);
        close(revpx->epfd);
        return -1;
    }
    if (revpx->domain_count == 0) {
        rp_log_error("No domains configured\n");
        if (http_fd >= 0) close(http_fd);
        close(https_fd);
        close(revpx->epfd);
        SSL_CTX_free(root_ctx);
        return -1;
    }
    SSL_CTX_set_mode(root_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_tlsext_servername_callback(root_ctx, sni_callback);
    SSL_CTX_set_tlsext_servername_arg(root_ctx, revpx);
    RpHostDomain *default_domain = &revpx->domains[0];
    if (SSL_CTX_use_certificate_file(root_ctx, default_domain->cert, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(root_ctx, default_domain->key, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_check_private_key(root_ctx) != 1) {
        unsigned long ssl_err;
        while ((ssl_err = ERR_get_error()) != 0) {
            char err_buf[256];
            ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
            rp_log_error("SSL error: %s\n", err_buf);
        }
        if (http_fd >= 0) close(http_fd);
        if (https_fd >= 0) close(https_fd);
        if (revpx->epfd >= 0) close(revpx->epfd);
        SSL_CTX_free(root_ctx);
        return -1;
    }

    // Main event loop: dispatch epoll events to the appropriate handler.
    // Listener fds (https_fd, http_fd) accept new connections in a loop (edge-triggered).
    // All other fds are dispatched through handle_event() which routes by connection state.
    struct epoll_event events[RP_MAX_EVENTS];
    int ret = 0;
    while (!revpx->stop) {
        int n = epoll_wait(revpx->epfd, events, RP_MAX_EVENTS, -1);
        if (n < 0 && errno != EINTR) {
            rp_log_error("epoll_wait error: %s\n", strerror(errno));
            ret = -1;
            revpx->stop = true;
            break;
        }

        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;

            if (fd == https_fd) {
                while (1) {
                    int client = accept(https_fd, NULL, NULL);
                    if (client < 0) {
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                            rp_log_error("accept failed on https fd: %s\n", strerror(errno));
                        }
                        break;
                    }
                    set_nonblock(client);

                    SSL *ssl = SSL_new(root_ctx);
                    if (!ssl) {
                        rp_log_error("SSL_new failed for client fd=%d\n", client);
                        close(client);
                        continue;
                    }
                    if (SSL_set_fd(ssl, client) != 1) {
                        rp_log_error("SSL_set_fd failed for client fd=%d\n", client);
                        SSL_free(ssl);
                        close(client);
                        continue;
                    }
                    SSL_set_accept_state(ssl);

                    RpConnection *c = alloc_conn(revpx, client, ssl, ST_SSL_HANDSHAKE, CT_CLIENT);
                    if (!c) continue;

                    int ret = SSL_accept(ssl);
                    if (ret == 1) {
                        c->state = ST_READ_HEADER;
                        ep_add(revpx, client, EPOLLIN | EPOLLET);
                    } else {
                        int err = SSL_get_error(ssl, ret);
                        ep_add(revpx, client, err == SSL_ERROR_WANT_WRITE ? (EPOLLOUT | EPOLLET) : (EPOLLIN | EPOLLET));
                    }
                }
            } else if (http_fd >= 0 && fd == http_fd) {
                while (1) {
                    int client = accept(http_fd, NULL, NULL);
                    if (client < 0) {
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                            rp_log_error("accept failed on http fd: %s\n", strerror(errno));
                        }
                        break;
                    }
                    set_nonblock(client);

                    RpConnection *c = alloc_conn(revpx, client, NULL, ST_READ_HEADER, CT_CLIENT);
                    if (c) ep_add(revpx, client, EPOLLIN | EPOLLET);
                }
            } else {
                handle_event(revpx, fd, events[i].events);
            }
        }
    }

    // Cleanup resources
    for (int i = 0; i < RP_MAX_FD; i++) {
        if (revpx->conns[i]) {
            cleanup(revpx, i);
        }
    }
    if (http_fd >= 0) close(http_fd);
    if (https_fd >= 0) close(https_fd);
    if (revpx->epfd >= 0) close(revpx->epfd);
    SSL_CTX_free(root_ctx);
    return ret;
}

RevPx *revpx_create(const char *http_port, const char *https_port) {
    RevPx *revpx = calloc(1, sizeof(RevPx));
    if (http_port) strncpy(revpx->http_port, http_port, sizeof(revpx->http_port) - 1);
    if (https_port) strncpy(revpx->https_port, https_port, sizeof(revpx->https_port) - 1);
    revpx->domain_count = 0;
    return revpx;
}

void revpx_free(RevPx *revpx) {
    if (!revpx) return;
    for (int i = 0; i < revpx->domain_count; i++) {
        RpHostDomain *d = &revpx->domains[i];
        if (d->ctx) SSL_CTX_free(d->ctx);
        if (d->domain) free(d->domain);
        if (d->port) free(d->port);
        if (d->cert) free(d->cert);
        if (d->key) free(d->key);
        if (d->host) free(d->host);
    }
    free(revpx);
}

#endif // REVPX_IMPLEMENTATION
