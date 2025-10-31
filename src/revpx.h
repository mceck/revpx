#ifndef REVPX_H
#define REVPX_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "ep.h"

#define RP_DEFAULT_BACKEND_HOST "127.0.0.1"
#define RP_MAX_EVENTS 1024
#define RP_BUF_SIZE 32768
#define RP_MAX_FD 65536
#define RP_MAX_DOMAINS 128

enum log_level {
    RP_DEBUG,
    RP_INFO,
    RP_WARN,
    RP_ERROR
};

#ifndef RP_LOG_LEVEL
#define RP_LOG_LEVEL RP_INFO
#endif // RP_LOG_LEVEL

static const char *RpLogLevelStrings[] = {
    [RP_DEBUG] = "DEBUG",
    [RP_INFO] = "INFO",
    [RP_WARN] = "WARN",
    [RP_ERROR] = "ERROR"};

#define rp_log(LVL, FMT, ...)                                                                  \
    do {                                                                                       \
        if (RP_LOG_LEVEL <= LVL) {                                                             \
            FILE *log_file = LVL >= RP_ERROR ? stderr : stdout;                                \
            fprintf(log_file, "[%s] " FMT, RpLogLevelStrings[LVL] __VA_OPT__(, ) __VA_ARGS__); \
            fflush(log_file);                                                                  \
        }                                                                                      \
    } while (0)
#define rp_log_info(FMT, ...) rp_log(RP_INFO, FMT, __VA_ARGS__)
#define rp_log_debug(FMT, ...) rp_log(RP_DEBUG, FMT, __VA_ARGS__)
#define rp_log_warn(FMT, ...) rp_log(RP_WARN, FMT, __VA_ARGS__)
#define rp_log_error(FMT, ...) rp_log(RP_ERROR, FMT, __VA_ARGS__)

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
    int write_retry_count; // Changed from bool to int for multiple retries
    bool read_stalled;
    bool websocket;
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

#ifdef REVPX_IMPLEMENTATION

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
    rp_log_error("connection error: %d %s\n", code, status);
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

            size_t n = e - p;
            if (n >= max) n = max - 1;
            memcpy(out, p, n);
            out[n] = '\0';

            char *colon = strchr(out, ':');
            if (colon) *colon = '\0';
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
                }
                if (SSL_CTX_use_PrivateKey_file(d->ctx, d->key, SSL_FILETYPE_PEM) <= 0) {
                    rp_log_error("Failed to load private key file %s for domain %s\n", d->key, host);
                    unsigned long ssl_err;
                    while ((ssl_err = ERR_get_error()) != 0) {
                        char err_buf[256];
                        ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
                        rp_log_error("SSL error: %s\n", err_buf);
                    }
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
    if (ctx) SSL_set_SSL_CTX(ssl, ctx);
    return SSL_TLSEXT_ERR_OK;
}

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
                ep_mod(revpx, peer->fd, EPOLLIN | EPOLLET);
            }
            ep_mod(revpx, c->fd, EPOLLIN | EPOLLET);
        }
    }
}

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

            size_t dst_space = buffer_space(dst);
            if (dst_space == 0) {
                compact_buffer(dst);
                dst_space = buffer_space(dst);
            }

            if (dst_space == 0) {
                if (!src->read_stalled) {
                    src->read_stalled = true;
                    uint32_t ev = src->len > 0 ? (EPOLLOUT | EPOLLET) : 0;
                    if (ev) ep_mod(revpx, src->fd, ev);
                }
                ep_mod(revpx, dst->fd, EPOLLOUT | EPOLLET);
                break;
            }

            size_t to_read = dst_space < sizeof(temp) ? dst_space : sizeof(temp);
            int n = do_read(src, temp, to_read);

            if (n > 0) {
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
                    if (buffer_space(dst) < remain) compact_buffer(dst);
                    memcpy(dst->buf + dst->off + dst->len, temp + written, remain);
                    dst->len += remain;
                    ep_mod(revpx, dst->fd, EPOLLOUT | EPOLLET);
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
            rp_log_info("WebSocket peer (fd: %d) closed connection.\n", src->fd);
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

static bool inject_forwarded_headers(RpConnection *client) {
    const char injected_ip[] = "127.0.0.1";
    char extra_headers[1024] = "\r\nConnection: close";
    if (client->len == 0) return false;
    unsigned char *p = client->buf + client->off;
    int headers_end = find_headers_end(p, client->len);
    if (headers_end <= 0) return false;

    size_t header_len = (size_t)headers_end;

    char method[16] = "GET"; // Default method
    const char *end = memchr((char *)p, '\n', header_len);
    if (end) {
        const char *space = memchr((char *)p, ' ', end - (char *)p);
        if (space) {
            size_t method_len = (size_t)(space - (char *)p);
            if (method_len > 0 && method_len < sizeof(method)) {
                memset(method, 0, sizeof(method));
                memcpy(method, p, method_len);
                rp_log_debug("Extracted method: %s\n", method);
            }
        }
    }

    const char *ff_value;
    size_t ff_len = 0;
    char ff[256];
    find_header((const unsigned char *)p, header_len, "X-Forwarded-For", &ff_value, &ff_len);
    if (ff_value && ff_len > 0) {
        strncpy(ff, ff_value, ff_len);
        strcat(ff, ", ");
    } else {
        strcpy(ff, injected_ip);
    }
    strcat(extra_headers, "\r\nX-Forwarded-For: ");
    strcat(extra_headers, ff);

    const char *to_strip[] = {"Connection", "Proxy-Connection", "Forwarded", "X-Forwarded-For",
                              "X-Forwarded-Proto", "X-Forwarded-Scheme", "X-Forwarded-Host", "X-Real-IP"};
    for (size_t i = 0; i < sizeof(to_strip) / sizeof(to_strip[0]); i++) {
        while (1) {
            unsigned char *hs = find_header_ci_in(p, header_len, to_strip[i]);
            if (!hs) break;
            unsigned char *line_end = (unsigned char *)memchr(hs, '\n', (p + header_len) - hs);
            if (!line_end) break;
            line_end += 1; // include the '\n'
            size_t remove_len = (size_t)(line_end - hs);
            memmove(hs, line_end, (p + client->len) - line_end);
            client->len -= remove_len;
            header_len -= remove_len;
            headers_end -= (int)remove_len;
        }
    }

    strcat(extra_headers, "\r\nX-Real-IP: ");
    strcat(extra_headers, injected_ip);
    strcat(extra_headers, "\r\nX-Forwarded-Proto: https");
    strcat(extra_headers, "\r\nX-Forwarded-Scheme: https");

    const char *host_start = NULL;
    size_t host_len;
    find_header(p, header_len, "Host", &host_start, &host_len);
    char hbuff[1024];
    if (host_start) {
        snprintf(hbuff, sizeof(hbuff), "\r\nX-Forwarded-Host: %.*s", (int)host_len, host_start);
        strcat(extra_headers, hbuff);
    }
    strcat(extra_headers, "\r\nForwarded: proto=https");
    snprintf(hbuff, sizeof(hbuff), "; for=%s", (ff_value && ff_len > 0) ? ff : injected_ip);
    strcat(extra_headers, hbuff);
    if (host_start) {
        snprintf(hbuff, sizeof(hbuff), "; host=%.*s", (int)host_len, host_start);
        strcat(extra_headers, hbuff);
    }

    size_t add_len = strlen(extra_headers);
    // Insert before the CRLFCRLF (headers_end - 4)
    memmove(p + headers_end - 4 + add_len,
            p + headers_end - 4,
            client->len - (size_t)(headers_end - 4));
    memcpy(p + headers_end - 4, extra_headers, add_len);
    client->len += add_len;
    rp_log_debug("Injected buffer:\n%.*s\n", 300, p + (client->len > 300 ? client->len - 300 : 0));

    return true;
}

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

    if (c->state != ST_PROXYING && c->len > 0 && (events & EPOLLOUT)) {
        flush_buffer(revpx, c);
        if (!revpx->conns[fd]) return;
    }

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

                c->websocket = is_websocket_upgrade_request(c->buf, end);
                if (c->websocket) {
                    rp_log_info("websocket upgrade request detected\n");
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
                rp_log_info("HTTPS request: https://%s%s -> %s:%s\n", host, target, d->host, d->port);

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
        if (c->ssl || !(events & EPOLLOUT)) {
            rp_log_debug("ST_CONNECTING: Client side: just wait, do nothing\n");
            break;
        }

        int err = 0;
        socklen_t len = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
                rp_log_error("getsockopt failed on fd=%d: %s\n", fd, strerror(errno));
            } else {
                rp_log_error("Backend connection failed on fd=%d: %s\n", fd, strerror(err));
            }
            RpConnection *client = revpx->conns[c->peer];
            if (client) {
                send_error(revpx, client, 502, "Bad Gateway");
                client->peer = -1;
                client->state = ST_READ_HEADER;
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

        if (client->websocket) {
            c->state = ST_UPGRADING;
            client->state = ST_UPGRADING;
            rp_log_debug("Waiting for websocket upgrade to complete\n");
        } else {
            c->state = ST_PROXYING;
            client->state = ST_PROXYING;
        }

        if (client->len > 0) {
            if (client->ssl && !client->websocket) {
                rp_log_debug("Injecting X-Forwarded headers into SSL client fd=%d to backend fd=%d\n", client->fd, fd);
                inject_forwarded_headers(client);
            }
            compact_buffer(c);
            size_t room = buffer_space(c);
            size_t to_copy = client->len <= room ? client->len : room;
            if (to_copy > 0) {
                rp_log_debug("Copying %zu bytes from client fd=%d to backend fd=%d buffer\n", to_copy, client->fd, fd);
                memcpy(c->buf + c->off + c->len, client->buf + client->off, to_copy);
                c->len += to_copy;
                client->off += to_copy;
                client->len -= to_copy;
                if (client->len == 0) client->off = 0;
            }
            ep_mod(revpx, fd, EPOLLOUT | EPOLLIN | EPOLLET);
        } else {
            rp_log_debug("Backend fd=%d ready, no data to forward yet\n", fd);
            ep_mod(revpx, fd, EPOLLIN | EPOLLET);
        }
        ep_mod(revpx, client->fd, EPOLLIN | EPOLLET);
        break;
    }

    case ST_UPGRADING: {
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
            rp_log_info("websocket: handshake success, start tunneling\n");

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
    SSL_CTX_set_mode(root_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_tlsext_servername_callback(root_ctx, sni_callback);
    SSL_CTX_set_tlsext_servername_arg(root_ctx, revpx);

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
#endif // REVPX_H