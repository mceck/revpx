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
#define RP_MAX_EVENTS 1024
#define RP_BUF_SIZE (128 * 1024)
#define RP_MAX_FD (64 * 1024)
#define RP_MAX_DOMAINS 128
#define RP_INITIAL_RESP_HEADER 1024
#define RP_MAX_RESP_HEADER (64 * 1024)
#define RP_MAX_DECODED_BODY (16 * 1024 * 1024)

enum log_level {
    RP_DEBUG,
    RP_INFO,
    RP_WARN,
    RP_ERROR
};

void revpx_set_log_level(int level);
void rp_log(int level, const char *fmt, ...);
#define rp_log_info(FMT, ...) rp_log(RP_INFO, FMT __VA_OPT__(,) __VA_ARGS__)
#define rp_log_debug(FMT, ...) rp_log(RP_DEBUG, FMT __VA_OPT__(,) __VA_ARGS__)
#define rp_log_warn(FMT, ...) rp_log(RP_WARN, FMT __VA_OPT__(,) __VA_ARGS__)
#define rp_log_error(FMT, ...) rp_log(RP_ERROR, FMT __VA_OPT__(,) __VA_ARGS__)

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
    SSL *ssl;
    int peer;
    RpConnectionState state;
    unsigned char buf[RP_BUF_SIZE];
    size_t len, off;
    bool closing;
    int write_retry_count;
    bool read_stalled;
    bool websocket;
    bool req_need_header;
    bool req_parsing_header;
    bool req_chunked;
    size_t req_body_left;
    size_t chunk_left;
    size_t chunk_size_acc;
    int chunk_line_len;
    bool chunk_expect_crlf;
    bool chunk_in_trailer;
    bool chunk_in_ext;
    uint32_t chunk_trailer_window;
    bool resp_need_header;
    bool resp_parsing_header;
    bool resp_chunked;
    size_t resp_content_length;
    size_t resp_body_sent;
    unsigned char *resp_header_buf;
    size_t resp_header_len;
    size_t resp_header_cap;
    size_t resp_chunk_left;
    size_t resp_chunk_size_acc;
    int resp_chunk_line_len;
    bool resp_chunk_expect_crlf;
    bool resp_chunk_in_trailer;
    bool resp_chunk_in_ext;
    uint32_t resp_chunk_trailer_window;
    // Pending data buffer for backpressure handling
    unsigned char *pending_data;
    size_t pending_len;
    size_t pending_cap;
    // Chunked request decoding buffer
    bool decoding_chunked;
    unsigned char *decoded_body;
    size_t decoded_body_len;
    size_t decoded_body_cap;
    unsigned char *saved_headers;
    size_t saved_headers_len;
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

RevPx *revpx_create(const char *http_port, const char *https_port);
void revpx_free(RevPx *revpx);
bool revpx_add_domain(RevPx *revpx, const char *domain, const char *host, const char *port, const char *cert, const char *key);
int revpx_run_server(RevPx *revpx);
#endif // REVPX_H

#ifdef REVPX_IMPLEMENTATION
int rp_log_level = RP_INFO;
void revpx_set_log_level(int level){
    rp_log_level = level;
}

void rp_log(int level, const char *fmt, ...) {
    if (level < rp_log_level) return;

    const char *level_str;
    switch (level) {
        case RP_DEBUG: level_str = "\033[36mDEBUG\033[0m"; break;
        case RP_INFO: level_str = "\033[32mINFO\033[0m"; break;
        case RP_WARN: level_str = "\033[33mWARN\033[0m"; break;
        case RP_ERROR: level_str = "\033[31mERROR\033[0m"; break;
        default: level_str = "LOG"; break;
    }

    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[%s] ", level_str);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

static void fill_peer_ip(int fd, char *out, size_t max);
static bool forward_client_bytes(RevPx *revpx, RpConnection *client, RpConnection *backend, const unsigned char *data, size_t n);
static bool handle_backend_response_bytes(RevPx *revpx, RpConnection *backend, const unsigned char *data, size_t n);
static bool ensure_pending_capacity(RpConnection *conn, size_t additional);

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

static void cleanup(RevPx *revpx, int fd) {
    // Close fd, release SSL/buffers, and notify the peer so it can finish pending work.
    if (fd < 0 || fd >= RP_MAX_FD || !revpx->conns[fd]) return;
    RpConnection *c = revpx->conns[fd];
    int peer = c->peer;

    if (c->type == CT_BACKEND && c->resp_content_length > 0 && !c->resp_chunked) {
        if (c->resp_body_sent < c->resp_content_length) {
            rp_log_warn("Backend fd=%d closed early: sent %zu/%zu response bytes\n",
                        fd, c->resp_body_sent, c->resp_content_length);
        }
    }

    epoll_ctl(revpx->epfd, EPOLL_CTL_DEL, fd, NULL);
    revpx->conns[fd] = NULL;

    if (c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
    }
    if (c->resp_header_buf) {
        free(c->resp_header_buf);
        c->resp_header_buf = NULL;
        c->resp_header_cap = 0;
        c->resp_header_len = 0;
    }
    if (c->pending_data) {
        free(c->pending_data);
        c->pending_data = NULL;
        c->pending_cap = 0;
        c->pending_len = 0;
    }
    if (c->decoded_body) {
        free(c->decoded_body);
        c->decoded_body = NULL;
        c->decoded_body_cap = 0;
        c->decoded_body_len = 0;
    }
    if (c->saved_headers) {
        free(c->saved_headers);
        c->saved_headers = NULL;
        c->saved_headers_len = 0;
    }
    close(fd);
    free(c);

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

// Tear down both halves of a proxied pair, ensuring neither side keeps dangling state.
static void cleanup_both(RevPx *revpx, int fd) {
    if (fd < 0 || fd >= RP_MAX_FD || !revpx->conns[fd]) return;
    int peer = revpx->conns[fd]->peer;

    cleanup(revpx, fd);
    if (peer >= 0 && revpx->conns[peer]) {
        revpx->conns[peer]->peer = -1;
        cleanup(revpx, peer);
    }
}

// Clear every bit of response bookkeeping so the backend parser can start fresh.
static void reset_response_state(RpConnection *backend) {
    backend->resp_need_header = true;
    backend->resp_parsing_header = false;
    backend->resp_chunked = false;
    backend->resp_content_length = 0;
    backend->resp_body_sent = 0;
    backend->resp_chunk_left = 0;
    backend->resp_chunk_size_acc = 0;
    backend->resp_chunk_line_len = 0;
    backend->resp_chunk_expect_crlf = false;
    backend->resp_chunk_in_trailer = false;
    backend->resp_chunk_in_ext = false;
    backend->resp_chunk_trailer_window = 0;
    backend->resp_header_len = 0;
}

// Allocate and register a new RpConnection, rejecting descriptors above RP_MAX_FD.
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

// Format and queue a tiny HTML error response, then mark the client for close.
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

// Issue an HTTP 301 redirect that pushes plain HTTP users onto the HTTPS listener.
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

static int hex_value(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int find_headers_end(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return i + 4;
        }
    }
    return -1;
}

// Parse the Host header (first occurrence) out of an HTTP request buffer.
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

// Extract the request target from the request line, defaulting to '/'.
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

// Lazily build (and cache) an SSL_CTX per domain so SNI can swap certificates on demand.
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

static void flush_buffer(RevPx *revpx, RpConnection *c) {
    // Drain the write buffer for connection c, handling SSL backpressure and retries.
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
                rp_log_error("Connection fd=%d closed during flush (SSL_ERROR_ZERO_RETURN)\n", c->fd);
                cleanup_both(revpx, c->fd);
                return;
            }
            if (err == SSL_ERROR_SYSCALL) {
                rp_log_error("SSL write error fd=%d: %s\n", c->fd, strerror(errno));
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
                // Process any pending data from the stalled peer first
                if (peer->pending_len > 0 && peer->type == CT_CLIENT) {
                    unsigned char *pending = peer->pending_data;
                    size_t pending_len = peer->pending_len;
                    peer->pending_len = 0;  // Clear before calling to avoid infinite loop
                    if (!forward_client_bytes(revpx, peer, c, pending, pending_len)) {
                        return;  // Error handled in forward_client_bytes
                    }
                    if (!revpx->conns[c->fd]) return;  // Connection was cleaned up
                }
                ep_mod(revpx, peer->fd, EPOLLIN | EPOLLET);
            }
            ep_mod(revpx, c->fd, EPOLLIN | EPOLLET);
        }
    }
}

static void proxy_data(RevPx *revpx, RpConnection *src, uint32_t events) {
    // Move bytes between client/backend while respecting buffer capacity on both sides.
    RpConnection *dst = src->peer >= 0 ? revpx->conns[src->peer] : NULL;

    if (!dst && !src->closing) {
        rp_log_error("Proxy data error: peer connection lost for fd=%d\n", src->fd);
        cleanup(revpx, src->fd);
        return;
    }

    if (events & EPOLLOUT) {
        flush_buffer(revpx, src);
        if (!revpx->conns[src->fd]) return;
        /* Client writable: try to drain backend's pending response data to the client */
        if (src->type == CT_CLIENT && dst && dst->type == CT_BACKEND && dst->pending_len > 0) {
            size_t space = buffer_space(src);
            if (space > 0) {
                size_t to_send = space < dst->pending_len ? space : dst->pending_len;
                int w = do_write(src, dst->pending_data, to_send);
                if (w > 0) {
                    if ((size_t)w < dst->pending_len)
                        memmove(dst->pending_data, dst->pending_data + w, dst->pending_len - (size_t)w);
                    dst->pending_len -= (size_t)w;
                    if (dst->pending_len > 0) ep_mod(revpx, src->fd, EPOLLOUT | EPOLLIN | EPOLLET);
                }
            }
        }
    }

    if ((events & EPOLLIN) && dst) {
        unsigned char temp[RP_BUF_SIZE];

        while (1) {
            dst = src->peer >= 0 ? revpx->conns[src->peer] : NULL;
            if (!dst) {
                cleanup(revpx, src->fd);
                return;
            }

            size_t dst_space = buffer_space(dst);
            if (dst_space == 0) {
                compact_buffer(dst);
                dst_space = buffer_space(dst);
            }

            /* Backend->client: drain pending response data first if client has space */
            if (src->type == CT_BACKEND && dst->type == CT_CLIENT && src->pending_len > 0 && dst_space > 0) {
                size_t to_send = dst_space < src->pending_len ? dst_space : src->pending_len;
                int w = do_write(dst, src->pending_data, to_send);
                if (w > 0) {
                    if ((size_t)w < src->pending_len)
                        memmove(src->pending_data, src->pending_data + w, src->pending_len - (size_t)w);
                    src->pending_len -= (size_t)w;
                    dst->write_retry_count = 0;
                    ep_mod(revpx, dst->fd, EPOLLOUT | EPOLLIN | EPOLLET);
                    if (src->pending_len > 0) ep_mod(revpx, dst->fd, EPOLLOUT | EPOLLET);
                    continue;
                } else {
                    int err = get_error(dst, w);
                    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                        ep_mod(revpx, dst->fd, EPOLLIN | EPOLLOUT | EPOLLET);
                        break;
                    }
                }
            }

            if (dst_space == 0) {
                /* Client full: for backend->client we still read and buffer in backend pending */
                if (src->type != CT_BACKEND || dst->type != CT_CLIENT) {
                    if (!src->read_stalled) {
                        src->read_stalled = true;
                        uint32_t ev = src->len > 0 ? (EPOLLOUT | EPOLLET) : 0;
                        if (ev) ep_mod(revpx, src->fd, ev);
                    }
                    ep_mod(revpx, dst->fd, EPOLLOUT | EPOLLET);
                    break;
                }
            }

            /* Backend->client: read up to full buffer so we don't leave data in kernel; else limit by client space */
            size_t to_read = (src->type == CT_BACKEND && dst->type == CT_CLIENT) ? sizeof(temp)
                : (dst_space < sizeof(temp) ? dst_space : sizeof(temp));
            int n = do_read(src, temp, to_read);

            if (n > 0) {
                if (src->type == CT_CLIENT && dst->type == CT_BACKEND && !src->websocket && !dst->websocket) {
                    if (!forward_client_bytes(revpx, src, dst, temp, (size_t)n)) return;
                    continue;
                }
                if (src->type == CT_BACKEND && dst->type == CT_CLIENT && !src->websocket && !dst->websocket) {
                    if (!handle_backend_response_bytes(revpx, src, temp, (size_t)n)) return;
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
                            rp_log_error("Peer connection fd=%d closed during proxy write\n", dst->fd);
                            cleanup_both(revpx, src->fd);
                            return;
                        }
                        if (err == SSL_ERROR_SYSCALL) {
                            rp_log_error("SSL proxy write error fd=%d->%d: %s\n", src->fd, dst->fd, strerror(errno));
                        }
                        if (dst->write_retry_count < 5) {
                            dst->write_retry_count++;
                            break;
                        }
                        rp_log_error("Connection fd=%d: max write retries exceeded in proxy\n", src->fd);
                        cleanup(revpx, src->fd);
                        return;
                    }
                }

                if (written < (size_t)n) {
                    size_t remain = n - written;
                    size_t space = buffer_space(dst);
                    if (space >= remain) {
                        memcpy(dst->buf + dst->off + dst->len, temp + written, remain);
                        dst->len += remain;
                    } else {
                        if (space > 0) {
                            memcpy(dst->buf + dst->off + dst->len, temp + written, space);
                            dst->len += space;
                            written += space;
                            remain -= space;
                        }
                        /* Backend->client: buffer overflow in backend pending so we don't drop data */
                        if (remain > 0 && src->type == CT_BACKEND && ensure_pending_capacity(src, remain)) {
                            memcpy(src->pending_data + src->pending_len, temp + written, remain);
                            src->pending_len += remain;
                        }
                    }
                    ep_mod(revpx, dst->fd, EPOLLOUT | EPOLLET);
                }
            } else if (n == 0) {
                rp_log_debug("Proxy connection closed by peer fd=%d\n", src->fd);
                /* Backend closed: push any buffered response to client before cleanup */
                if (src->type == CT_BACKEND && src->pending_len > 0 && dst && dst->type == CT_CLIENT) {
                    size_t space = buffer_space(dst);
                    if (space == 0) compact_buffer(dst);
                    space = buffer_space(dst);
                    size_t to_copy = space < src->pending_len ? space : src->pending_len;
                    if (to_copy > 0) {
                        memcpy(dst->buf + dst->off + dst->len, src->pending_data, to_copy);
                        dst->len += to_copy;
                        ep_mod(revpx, dst->fd, EPOLLOUT | EPOLLET);
                    }
                }
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
                    /* Same: push backend pending to client before cleanup */
                    if (src->type == CT_BACKEND && src->pending_len > 0 && dst && dst->type == CT_CLIENT) {
                        size_t space = buffer_space(dst);
                        if (space == 0) compact_buffer(dst);
                        space = buffer_space(dst);
                        size_t to_copy = space < src->pending_len ? space : src->pending_len;
                        if (to_copy > 0) {
                            memcpy(dst->buf + dst->off + dst->len, src->pending_data, to_copy);
                            dst->len += to_copy;
                            ep_mod(revpx, dst->fd, EPOLLOUT | EPOLLET);
                        }
                    }
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

static void tunnel_data(RevPx *revpx, RpConnection *src, uint32_t events) {
    // WebSocket/CONNECT tunnel: blindly shuffle bytes until either side closes.
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

// Resolve and open a non-blocking TCP socket to the configured upstream.
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

// Grow the temporary response-header buffer until it can fit 'needed' bytes (capped by RP_MAX_RESP_HEADER).
static bool ensure_response_header_capacity(RpConnection *backend, size_t needed) {
    if (needed > RP_MAX_RESP_HEADER) return false;
    size_t cap = backend->resp_header_cap ? backend->resp_header_cap : RP_INITIAL_RESP_HEADER;
    while (cap < needed && cap < RP_MAX_RESP_HEADER) {
        cap *= 2;
        if (cap > RP_MAX_RESP_HEADER) cap = RP_MAX_RESP_HEADER;
    }
    if (cap < needed) return false;
    unsigned char *buf = realloc(backend->resp_header_buf, cap);
    if (!buf) return false;
    backend->resp_header_buf = buf;
    backend->resp_header_cap = cap;
    return true;
}

// Expand the per-connection pending buffer used when backpressure pauses reads.
static bool ensure_pending_capacity(RpConnection *conn, size_t additional) {
    size_t needed = conn->pending_len + additional;
    if (needed > RP_BUF_SIZE * 4) return false;  // Limit pending to 4x buffer
    if (needed <= conn->pending_cap) return true;
    size_t cap = conn->pending_cap ? conn->pending_cap : 4096;
    while (cap < needed) cap *= 2;
    if (cap > RP_BUF_SIZE * 4) cap = RP_BUF_SIZE * 4;
    unsigned char *buf = realloc(conn->pending_data, cap);
    if (!buf) return false;
    conn->pending_data = buf;
    conn->pending_cap = cap;
    return true;
}

// Ensure we have enough room to accumulate a fully decoded chunked request body.
static bool ensure_decoded_body_capacity(RpConnection *conn, size_t additional) {
    size_t needed = conn->decoded_body_len + additional;
    if (needed > RP_MAX_DECODED_BODY) return false;
    if (needed <= conn->decoded_body_cap) return true;
    size_t cap = conn->decoded_body_cap ? conn->decoded_body_cap : 4096;
    while (cap < needed) cap *= 2;
    if (cap > RP_MAX_DECODED_BODY) cap = RP_MAX_DECODED_BODY;
    unsigned char *buf = realloc(conn->decoded_body, cap);
    if (!buf) return false;
    conn->decoded_body = buf;
    conn->decoded_body_cap = cap;
    return true;
}

// Decode chunked body into decoded_body buffer
// Returns: bytes consumed on success, -1 on error, sets decoding_chunked=false when complete
static ssize_t decode_chunked_to_buffer(RpConnection *conn, const unsigned char *data, size_t n) {
    size_t i = 0;
    while (i < n) {
        if (conn->chunk_expect_crlf) {
            unsigned char expected = conn->chunk_line_len == 0 ? '\r' : '\n';
            if (data[i] != expected) return -1;
            conn->chunk_line_len++;
            i++;
            if (conn->chunk_line_len == 2) {
                conn->chunk_expect_crlf = false;
                conn->chunk_line_len = 0;
            }
            continue;
        }

        if (conn->chunk_left > 0) {
            size_t take = conn->chunk_left < n - i ? conn->chunk_left : n - i;
            // Copy chunk data to decoded_body
            if (!ensure_decoded_body_capacity(conn, take)) return -1;
            memcpy(conn->decoded_body + conn->decoded_body_len, data + i, take);
            conn->decoded_body_len += take;
            conn->chunk_left -= take;
            i += take;
            if (conn->chunk_left == 0) {
                conn->chunk_expect_crlf = true;
                conn->chunk_line_len = 0;
            }
            continue;
        }

        if (conn->chunk_in_trailer) {
            conn->chunk_trailer_window = (conn->chunk_trailer_window << 8) | data[i];
            conn->chunk_trailer_window &= 0xffffffffu;
            i++;
            if (conn->chunk_trailer_window == 0x0d0a0d0a) {
                // Chunked body complete
                conn->decoding_chunked = false;
                conn->chunk_in_trailer = false;
                conn->chunk_trailer_window = 0;
                conn->chunk_size_acc = 0;
                conn->chunk_line_len = 0;
                conn->chunk_expect_crlf = false;
                conn->chunk_in_ext = false;
                conn->chunk_left = 0;
                return (ssize_t)i;
            }
            continue;
        }

        unsigned char ch = data[i++];
        if (ch == '\r') continue;
        if (ch == '\n') {
            conn->chunk_left = conn->chunk_size_acc;
            conn->chunk_size_acc = 0;
            conn->chunk_line_len = 0;
            conn->chunk_in_ext = false;
            if (conn->chunk_left == 0) {
                conn->chunk_in_trailer = true;
                // Pre-populate window with the CRLF that ended the chunk size line
                conn->chunk_trailer_window = 0x0d0a;
            }
            continue;
        }
        if (ch == ';' || ch == ' ' || ch == '\t') {
            conn->chunk_in_ext = true;
            continue;
        }
        if (conn->chunk_in_ext) continue;
        if (conn->chunk_line_len >= 16) return -1;
        int hv = hex_value(ch);
        if (hv < 0) return -1;
        conn->chunk_size_acc = (conn->chunk_size_acc << 4) | (size_t)hv;
        conn->chunk_line_len++;
    }
    return (ssize_t)n;
}

// Once CRLFCRLF is seen, compute backend response metadata (chunked?, content-length, etc.).
static bool finalize_response_headers(RpConnection *backend) {
    if (!backend->resp_header_buf || backend->resp_header_len == 0) return false;
    int headers_end = find_headers_end(backend->resp_header_buf, backend->resp_header_len);
    if (headers_end <= 0) return false;

    size_t header_len = (size_t)headers_end;
    backend->resp_chunked = has_chunked_encoding(backend->resp_header_buf, header_len);

    const char *cl = NULL;
    size_t cl_len = 0;
    if (find_header(backend->resp_header_buf, header_len, "Content-Length", &cl, &cl_len) && cl_len > 0) {
        char tmp[32];
        size_t copy_len = cl_len >= sizeof(tmp) ? sizeof(tmp) - 1 : cl_len;
        memcpy(tmp, cl, copy_len);
        tmp[copy_len] = '\0';
        backend->resp_content_length = strtoull(tmp, NULL, 10);
    } else {
        backend->resp_content_length = 0;
    }

    backend->resp_need_header = false;
    backend->resp_parsing_header = false;
    backend->resp_body_sent = 0;
    backend->resp_chunk_left = 0;
    backend->resp_chunk_size_acc = 0;
    backend->resp_chunk_line_len = 0;
    backend->resp_chunk_expect_crlf = false;
    backend->resp_chunk_in_trailer = false;
    backend->resp_chunk_in_ext = false;
    backend->resp_chunk_trailer_window = 0;
    rp_log_debug("Response headers parsed: fd=%d, Content-Length=%zu, chunked=%d, header_len=%zu\n",
                 backend->fd, backend->resp_content_length, backend->resp_chunked, header_len);
    backend->resp_header_len = 0;
    return true;
}

// Walk the backend chunk stream, updating resp_chunk_* bookkeeping and signaling when done.
static ssize_t advance_response_chunked(RpConnection *backend, const unsigned char *data, size_t n) {
    size_t i = 0;
    while (i < n) {
        if (backend->resp_chunk_expect_crlf) {
            unsigned char expected = backend->resp_chunk_line_len == 0 ? '\r' : '\n';
            if (data[i] != expected) return -1;
            backend->resp_chunk_line_len++;
            i++;
            if (backend->resp_chunk_line_len == 2) {
                backend->resp_chunk_expect_crlf = false;
                backend->resp_chunk_line_len = 0;
            }
            continue;
        }

        if (backend->resp_chunk_left > 0) {
            size_t take = backend->resp_chunk_left < (n - i) ? backend->resp_chunk_left : (n - i);
            backend->resp_chunk_left -= take;
            backend->resp_body_sent += take;
            i += take;
            if (backend->resp_chunk_left == 0) {
                backend->resp_chunk_expect_crlf = true;
                backend->resp_chunk_line_len = 0;
            }
            continue;
        }

        if (backend->resp_chunk_in_trailer) {
            backend->resp_chunk_trailer_window = (backend->resp_chunk_trailer_window << 8) | data[i];
            backend->resp_chunk_trailer_window &= 0xffffffffu;
            i++;
            if (backend->resp_chunk_trailer_window == 0x0d0a0d0a) {
                reset_response_state(backend);
                return (ssize_t)i;
            }
            continue;
        }

        unsigned char ch = data[i++];
        if (ch == '\r') continue;
        if (ch == '\n') {
            backend->resp_chunk_left = backend->resp_chunk_size_acc;
            backend->resp_chunk_size_acc = 0;
            backend->resp_chunk_line_len = 0;
            backend->resp_chunk_in_ext = false;
            if (backend->resp_chunk_left == 0) {
                backend->resp_chunk_in_trailer = true;
                backend->resp_chunk_trailer_window = 0;
            }
            continue;
        }
        if (ch == ';' || ch == ' ' || ch == '\t') {
            backend->resp_chunk_in_ext = true;
            continue;
        }
        if (backend->resp_chunk_in_ext) continue;
        if (backend->resp_chunk_line_len >= 16) return -1;
        int hv = hex_value(ch);
        if (hv < 0) return -1;
        backend->resp_chunk_size_acc = (backend->resp_chunk_size_acc << 4) | (size_t)hv;
        backend->resp_chunk_line_len++;
    }
    return (ssize_t)n;
}

// Parse backend bytes into headers/body so we know when a response completes (for keep-alive correctness).
static bool handle_backend_response_bytes(RevPx *revpx, RpConnection *backend, const unsigned char *data, size_t n) {
    size_t offset = 0;

    while (offset < n) {
        if (backend->resp_need_header || backend->resp_parsing_header) {
            backend->resp_parsing_header = true;
            while (offset < n) {
                if (!ensure_response_header_capacity(backend, backend->resp_header_len + 1)) {
                    rp_log_error("Failed to allocate response header buffer for fd=%d\n", backend->fd);
                    cleanup_both(revpx, backend->fd);
                    return false;
                }
                backend->resp_header_buf[backend->resp_header_len++] = data[offset++];
                if (backend->resp_header_len >= 4 &&
                    backend->resp_header_buf[backend->resp_header_len - 4] == '\r' &&
                    backend->resp_header_buf[backend->resp_header_len - 3] == '\n' &&
                    backend->resp_header_buf[backend->resp_header_len - 2] == '\r' &&
                    backend->resp_header_buf[backend->resp_header_len - 1] == '\n') {
                    if (!finalize_response_headers(backend)) {
                        rp_log_warn("Failed to finalize backend response headers for fd=%d\n", backend->fd);
                        cleanup_both(revpx, backend->fd);
                        return false;
                    }
                    break;
                }
                if (backend->resp_header_len >= RP_MAX_RESP_HEADER) {
                    rp_log_warn("Backend response headers exceed limit (%zu bytes) on fd=%d\n",
                                backend->resp_header_len, backend->fd);
                    cleanup_both(revpx, backend->fd);
                    return false;
                }
            }

            if (backend->resp_need_header) {
                return true;
            }

            if (!backend->resp_chunked && backend->resp_content_length == 0) {
                rp_log_debug("Response with zero-length body on fd=%d\n", backend->fd);
                reset_response_state(backend);
                continue;
            }
        }

        size_t body_available = n - offset;
        if (body_available == 0) break;

        if (backend->resp_chunked) {
            ssize_t consumed = advance_response_chunked(backend, data + offset, body_available);
            if (consumed < 0) {
                rp_log_warn("Invalid chunked encoding from backend fd=%d\n", backend->fd);
                cleanup_both(revpx, backend->fd);
                return false;
            }
            offset += (size_t)consumed;
            if (backend->resp_need_header) {
                continue;
            }
        } else if (backend->resp_content_length > 0) {
            size_t remaining = backend->resp_content_length - backend->resp_body_sent;
            size_t take = body_available < remaining ? body_available : remaining;
            backend->resp_body_sent += take;
            offset += take;
            if (backend->resp_body_sent == backend->resp_content_length) {
                rp_log_debug("Response complete fd=%d (%zu bytes)\n", backend->fd, backend->resp_body_sent);
                reset_response_state(backend);
                continue;
            }
        } else {
            backend->resp_body_sent += body_available;
            offset = n;
        }
    }

    return true;
}

// Track how much of a chunked *request* body has traversed the wire (before optional decoding kicks in).
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
                backend->chunk_trailer_window = 0;
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

// Strip any user-supplied forwarding headers and replace them with ones derived from the client socket.
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

static bool forward_decoded_chunked_request(RevPx *revpx, RpConnection *client, RpConnection *backend);

static bool forward_client_bytes(RevPx *revpx, RpConnection *client, RpConnection *backend, const unsigned char *data, size_t n) {
    // Parse the client stream, inject proxy headers, and normalize bodies before backend sees them.
    // If we're decoding a chunked request body, continue decoding
    if (backend->decoding_chunked) {
        ssize_t consumed = decode_chunked_to_buffer(backend, data, n);
        if (consumed < 0) {
            send_error(revpx, client, 400, "Bad Request");
            cleanup(revpx, backend->fd);
            return false;
        }
        // Check if decoding is complete
        if (!backend->decoding_chunked) {
            // Decoding finished - forward the complete request
            if (!forward_decoded_chunked_request(revpx, client, backend)) {
                return false;
            }
            // Handle any leftover data (next pipelined request)
            if ((size_t)consumed < n) {
                size_t leftover = n - (size_t)consumed;
                backend->req_need_header = true;
                backend->req_parsing_header = true;
                return forward_client_bytes(revpx, client, backend, data + consumed, leftover);
            }
        }
        return true;
    }

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
            // Store remaining data in pending buffer to avoid data loss
            if (n > 0) {
                if (!ensure_pending_capacity(client, n)) {
                    send_error(revpx, client, 413, "Request Entity Too Large");
                    cleanup(revpx, backend->fd);
                    return false;
                }
                memcpy(client->pending_data + client->pending_len, data, n);
                client->pending_len += n;
            }
            if (!client->read_stalled) {
                client->read_stalled = true;
                ep_mod(revpx, client->fd, 0);  // Stop reading entirely
            }
            ep_mod(revpx, backend->fd, EPOLLOUT | EPOLLET);
            return true;
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
                if (!inject_forwarded_headers(backend, client->fd)) {
                    send_error(revpx, client, 400, "Bad Request");
                    cleanup(revpx, backend->fd);
                    return false;
                }
                end = find_headers_end(backend->buf, backend->len);
                size_t header_end = (size_t)end;
                backend->req_chunked = has_chunked_encoding(backend->buf, header_end);
                backend->req_body_left = 0;

                const char *cl = NULL;
                size_t cl_len = 0;
                if (find_header(backend->buf, header_end, "Content-Length", &cl, &cl_len) && cl_len > 0) {
                    char tmp[32];
                    size_t copy_len = cl_len >= sizeof(tmp) ? sizeof(tmp) - 1 : cl_len;
                    memcpy(tmp, cl, copy_len);
                    tmp[copy_len] = '\0';
                    backend->req_body_left = strtoull(tmp, NULL, 10);
                }

                backend->req_need_header = false;
                backend->req_parsing_header = false;
                size_t body_avail = backend->len > header_end ? backend->len - header_end : 0;
                if (backend->req_chunked) {
                    // Save headers for later transformation (will add Content-Length)
                    backend->saved_headers = malloc(header_end);
                    if (!backend->saved_headers) {
                        send_error(revpx, client, 500, "Internal Server Error");
                        cleanup(revpx, backend->fd);
                        return false;
                    }
                    memcpy(backend->saved_headers, backend->buf, header_end);
                    backend->saved_headers_len = header_end;

                    // Initialize chunked decoding state
                    backend->decoding_chunked = true;
                    backend->decoded_body_len = 0;
                    backend->chunk_left = 0;
                    backend->chunk_size_acc = 0;
                    backend->chunk_line_len = 0;
                    backend->chunk_expect_crlf = false;
                    backend->chunk_in_trailer = false;
                    backend->chunk_in_ext = false;
                    backend->chunk_trailer_window = 0;

                    // Decode any available body data
                    if (body_avail) {
                        // Copy body data before clearing buffer
                        unsigned char body_tmp[RP_BUF_SIZE];
                        if (body_avail > sizeof(body_tmp)) {
                            send_error(revpx, client, 413, "Request Entity Too Large");
                            cleanup(revpx, backend->fd);
                            return false;
                        }
                        memcpy(body_tmp, backend->buf + header_end, body_avail);

                        // Clear buffer - don't forward headers yet
                        backend->off = 0;
                        backend->len = 0;

                        ssize_t consumed = decode_chunked_to_buffer(backend, body_tmp, body_avail);
                        if (consumed < 0) {
                            send_error(revpx, client, 400, "Bad Request");
                            cleanup(revpx, backend->fd);
                            return false;
                        }
                        // Check if decoding is complete
                        if (!backend->decoding_chunked) {
                            if (!forward_decoded_chunked_request(revpx, client, backend)) {
                                return false;
                            }
                            // Handle leftover (next pipelined request)
                            if ((size_t)consumed < body_avail) {
                                size_t leftover = body_avail - (size_t)consumed;
                                backend->req_need_header = true;
                                backend->req_parsing_header = true;
                                return forward_client_bytes(revpx, client, backend, body_tmp + consumed, leftover);
                            }
                        }
                    } else {
                        // Clear buffer - don't forward headers yet
                        backend->off = 0;
                        backend->len = 0;
                    }
                    return true;
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

// Forward a decoded chunked request to the backend
// Called after chunked body is fully decoded in decoded_body
static bool forward_decoded_chunked_request(RevPx *revpx, RpConnection *client, RpConnection *backend) {
    if (!backend->saved_headers || backend->saved_headers_len == 0) {
        send_error(revpx, client, 500, "Internal Server Error");
        cleanup(revpx, backend->fd);
        return false;
    }

    // Find Transfer-Encoding header in saved headers and remove it
    unsigned char *headers = backend->saved_headers;
    size_t headers_len = backend->saved_headers_len;

    // Find headers end (should be at saved_headers_len)
    int hdr_end = find_headers_end(headers, headers_len);
    if (hdr_end <= 0) {
        send_error(revpx, client, 500, "Internal Server Error");
        cleanup(revpx, backend->fd);
        return false;
    }

    // Build new headers without Transfer-Encoding, with Content-Length
    // Calculate space needed
    char cl_header[64];
    int cl_len = snprintf(cl_header, sizeof(cl_header), "Content-Length: %zu\r\n", backend->decoded_body_len);

    // Copy headers to buffer, filtering out Transfer-Encoding
    backend->off = 0;
    backend->len = 0;

    const unsigned char *src = headers;
    const unsigned char *src_end = headers + hdr_end - 4;  // Exclude final CRLFCRLF
    bool first_line = true;

    while (src < src_end) {
        const unsigned char *line_end = (const unsigned char *)memchr(src, '\n', src_end - src);
        if (!line_end) line_end = src_end;
        else line_end++;

        size_t line_len = line_end - src;

        // Skip Transfer-Encoding header (case-insensitive)
        if (!first_line && line_len > 18 &&
            strncasecmp((const char *)src, "Transfer-Encoding:", 18) == 0) {
            src = line_end;
            continue;
        }

        // Copy line to buffer
        if (backend->len + line_len >= sizeof(backend->buf)) {
            send_error(revpx, client, 431, "Request Header Fields Too Large");
            cleanup(revpx, backend->fd);
            return false;
        }
        memcpy(backend->buf + backend->len, src, line_len);
        backend->len += line_len;

        first_line = false;
        src = line_end;
    }

    // Add Content-Length header and final CRLFCRLF
    if (backend->len + (size_t)cl_len + 2 >= sizeof(backend->buf)) {
        send_error(revpx, client, 431, "Request Header Fields Too Large");
        cleanup(revpx, backend->fd);
        return false;
    }
    memcpy(backend->buf + backend->len, cl_header, cl_len);
    backend->len += cl_len;

    // Add final CRLF to end headers (cl_header already has CRLF at end)
    memcpy(backend->buf + backend->len, "\r\n", 2);
    backend->len += 2;

    // Free saved headers - no longer needed
    free(backend->saved_headers);
    backend->saved_headers = NULL;
    backend->saved_headers_len = 0;

    // Set up for body forwarding
    backend->req_chunked = false;
    backend->req_parsing_header = false;

    // Copy decoded body to buffer (assuming it fits with headers)
    size_t space = buffer_space(backend);
    if (backend->decoded_body_len > space) {
        // Body too large for buffer - this shouldn't happen for reasonably sized requests
        send_error(revpx, client, 413, "Request Entity Too Large");
        cleanup(revpx, backend->fd);
        return false;
    }

    if (backend->decoded_body_len > 0) {
        memcpy(backend->buf + backend->len, backend->decoded_body, backend->decoded_body_len);
        backend->len += backend->decoded_body_len;
    }

    // Free decoded body
    if (backend->decoded_body) {
        free(backend->decoded_body);
        backend->decoded_body = NULL;
        backend->decoded_body_len = 0;
        backend->decoded_body_cap = 0;
    }

    backend->req_body_left = 0;
    backend->req_need_header = true;

    // Flush the complete request to backend
    flush_buffer(revpx, backend);
    return revpx->conns[backend->fd] != NULL;
}

static void handle_event(RevPx *revpx, int fd, uint32_t events) {
    // Central epoll dispatcher: advance each connection's state machine based on readiness flags.
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
        if (c->state == ST_PROXYING) {
            /* Drain any remaining data before closing; treat HUP as readable */
            proxy_data(revpx, c, events | EPOLLIN);
            return;
        }
        if (c->state != ST_SHUTTING_DOWN) {
            rp_log_error("EPOLLHUP on fd=%d, state=%d - unexpected connection hangup\n", fd, c->state);
            cleanup(revpx, fd);
            return;
        }
    }

    if (c->state != ST_PROXYING && c->len > 0 && (events & EPOLLOUT)) {
        if (c->state == ST_CONNECTING) goto skip_flush;
        flush_buffer(revpx, c);
        if (!revpx->conns[fd]) return;
    }

skip_flush:
    switch (c->state) {
    case ST_SSL_HANDSHAKE: { // Finish TLS negotiation before reading HTTP bytes.
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

    case ST_READ_HEADER: { // Accumulate an HTTP request header from the client.
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

    case ST_CONNECTING: { // Backend socket is in-flight; once ready flip to proxying/upgrading.
        if (c->ssl) {
            if (events & EPOLLIN) {
                while (1) {
                    size_t space = buffer_space(c);
                    if (space == 0) {
                        send_error(revpx, c, 413, "Request Entity Too Large");
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
        reset_response_state(c);

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

    case ST_UPGRADING: { // Wait for a 101 response to complete the WebSocket handshake.
        RpConnection *client = revpx->conns[c->peer];
        if (!client) {
            rp_log_error("WebSocket upgrade error: client connection lost for fd=%d\n", fd);
            cleanup(revpx, fd);
            break;
        }

        int n = do_read(c, c->buf + c->len, sizeof(c->buf) - c->len);
        if (n > 0) {
            c->len = n;
        } else if (n <= 0 && errno == EAGAIN) {
            ep_mod(revpx, c->fd, EPOLLIN | EPOLLET);
            break;
        } else if (n <= 0 && get_error(c, n) != SSL_ERROR_WANT_READ) {
            rp_log_error("WebSocket upgrade failed - backend read error fd=%d: %s\n", c->fd, strerror(errno));
            send_error(revpx, client, 502, "Bad Gateway");
            cleanup(revpx, c->fd);
            break;
        }

        if (n >= 12 && strncasecmp((char *)c->buf, "HTTP/1.1 101", 12) == 0) {
            rp_log_debug("websocket: handshake success, start tunneling\n");

            c->state = ST_TUNNELING;
            client->state = ST_TUNNELING;

            memcpy(client->buf, c->buf, n);
            client->len = n;
            client->off = 0;

            c->len = 0;
            c->off = 0;

            rp_log_debug("Copied %d bytes (101 response) to client fd=%d buffer\n", n, client->fd);
            ep_mod(revpx, client->fd, EPOLLOUT | EPOLLIN | EPOLLET);
            ep_mod(revpx, c->fd, EPOLLIN | EPOLLET);
        } else {
            rp_log_warn("Upgrade a WebSocket failed. Backend response:\n%.*s\n", n, c->buf);
            send_error(revpx, client, 502, "Bad Gateway: WebSocket handshake failed");
            cleanup(revpx, c->fd);
        }

        break;
    }

    case ST_PROXYING: // Normal HTTP proxy path once both sides are established.
        proxy_data(revpx, c, events);
        break;

    case ST_TUNNELING: // After CONNECT/WebSocket upgrade, blindly tunnel bytes.
        tunnel_data(revpx, c, events);
        break;

    case ST_SHUTTING_DOWN: { // Coordinate half-close so lingering SSL shutdown completes cleanly.
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

// Bind a non-blocking listening socket for either HTTP or HTTPS traffic.
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
    // Initialize listeners, bootstrap TLS, and drive the epoll loop until shutdown.
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
