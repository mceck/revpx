#ifndef REVPX_H
#define REVPX_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "ds.h"
#include "ep.h"

#define RP_DEFAULT_BACKEND_HOST "127.0.0.1"
#define RP_MAX_EVENTS 1024
#define RP_BUF_SIZE 16384
#define RP_MAX_FD 65536

typedef enum {
    ST_SSL_HANDSHAKE,
    ST_READ_HEADER,
    ST_CONNECTING,
    ST_PROXYING,
    ST_SHUTTING_DOWN
} RpConnectionState;

typedef struct {
    int fd;
    SSL *ssl;
    int peer;
    RpConnectionState state;
    unsigned char buf[RP_BUF_SIZE];
    size_t len, off;
    int closing;
    int write_retry;
    int read_stalled;
} RpConnection;

typedef struct {
    char *domain;
    char *host;
    char *port;
    char *cert;
    char *key;
    SSL_CTX *ctx;
} RpHostDomain;

ds_da_declare(RpDomains, RpHostDomain);

static RpConnection *rp_conns[RP_MAX_FD];
static RpDomains rp_domains = {0};
static int rp_epfd;

void revpx_add_domain(const char *domain, const char *host, const char *port, const char *cert, const char *key);
void revpx_run_server(const char *http_port, const char *https_port);

#ifdef REVPX_IMPLEMENTATION

static void set_nonblock(int fd) {
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
}

static void ep_add(int fd, uint32_t events) {
    struct epoll_event ev = {.data.fd = fd, .events = events};
    epoll_ctl(rp_epfd, EPOLL_CTL_ADD, fd, &ev);
}

static void ep_mod(int fd, uint32_t events) {
    struct epoll_event ev = {.data.fd = fd, .events = events};
    epoll_ctl(rp_epfd, EPOLL_CTL_MOD, fd, &ev);
}

static void cleanup(int fd) {
    if (fd < 0 || fd >= RP_MAX_FD || !rp_conns[fd]) return;
    RpConnection *c = rp_conns[fd];
    int peer = c->peer;

    epoll_ctl(rp_epfd, EPOLL_CTL_DEL, fd, NULL);
    rp_conns[fd] = NULL;

    if (c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
    }
    close(fd);
    free(c);

    if (peer >= 0 && rp_conns[peer]) {
        RpConnection *p = rp_conns[peer];
        p->peer = -1;
        if (p->len > 0) {
            p->closing = 1;
            ep_mod(peer, EPOLLOUT | EPOLLET);
        } else {
            p->state = ST_SHUTTING_DOWN;
            ep_mod(peer, EPOLLOUT | EPOLLET);
        }
    }
}

static void cleanup_both(int fd) {
    if (fd < 0 || fd >= RP_MAX_FD || !rp_conns[fd]) return;
    int peer = rp_conns[fd]->peer;

    cleanup(fd);
    if (peer >= 0 && rp_conns[peer]) {
        rp_conns[peer]->peer = -1;
        cleanup(peer);
    }
}

static RpConnection *alloc_conn(int fd, SSL *ssl, RpConnectionState state) {
    if (fd >= RP_MAX_FD) {
        if (ssl) SSL_free(ssl);
        close(fd);
        return NULL;
    }
    RpConnection *c = calloc(1, sizeof(RpConnection));
    c->fd = fd;
    c->ssl = ssl;
    c->peer = -1;
    c->state = state;
    rp_conns[fd] = c;
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

static void send_error(RpConnection *c, int code, const char *status) {
    char body[4096];
    int body_len = snprintf(body, sizeof(body),
                            "<html><head><title>%d %s</title></head>"
                            "<body><h1>%d %s</h1><p>revpx</p></body></html>",
                            code, status, code, status);

    char header[1024];
    int head_len = snprintf(header, sizeof(header),
                            "HTTP/1.1 %d %s\r\n"
                            "Content-Type: text/html; charset=utf-8\r\n"
                            "Content-Length: %d\r\n"
                            "RpConnection: close\r\n\r\n",
                            code, status, body_len);
    memcpy(c->buf, header, head_len);
    memcpy(c->buf + head_len, body, body_len);
    c->len = head_len + body_len;
    c->off = 0;
    c->closing = 1;
    ep_mod(c->fd, EPOLLOUT | EPOLLET);
}

static void send_redirect(RpConnection *c, const char *host, const char *target, const char *port) {
    char resp[4096];
    int n = snprintf(resp, sizeof(resp),
                     "HTTP/1.1 301 Moved Permanently\r\n"
                     "Location: https://%s%s%s%s\r\n"
                     "Content-Length: 0\r\nRpConnection: close\r\n\r\n",
                     host, strcmp(port, "443") ? ":" : "", strcmp(port, "443") ? port : "", target);
    memcpy(c->buf, resp, n);
    c->len = n;
    c->off = 0;
    c->closing = 1;
    ep_mod(c->fd, EPOLLOUT | EPOLLET);
}

static int find_headers_end(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
            return i + 4;
    }
    for (size_t i = 0; i + 1 < len; i++) {
        if (buf[i] == '\n' && buf[i + 1] == '\n')
            return i + 2;
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

static SSL_CTX *get_ctx(const char *host) {
    ds_da_foreach(&rp_domains, d) {
        if (strcasecmp(d->domain, host) == 0) {
            if (!d->ctx) {
                d->ctx = SSL_CTX_new(TLS_server_method());
                SSL_CTX_use_certificate_file(d->ctx, d->cert, SSL_FILETYPE_PEM);
                SSL_CTX_use_PrivateKey_file(d->ctx, d->key, SSL_FILETYPE_PEM);
                SSL_CTX_set_mode(d->ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
            }
            return d->ctx;
        }
    }
    return NULL;
}

static int sni_callback(SSL *ssl, int *ad, void *arg) {
    (void)ad;
    (void)arg;
    const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    SSL_CTX *ctx = name ? get_ctx(name) : NULL;
    if (ctx) SSL_set_SSL_CTX(ssl, ctx);
    return SSL_TLSEXT_ERR_OK;
}

static void flush_buffer(RpConnection *c) {
    while (c->len > 0) {
        int n = do_write(c, c->buf + c->off, c->len);
        if (n > 0) {
            c->off += n;
            c->len -= n;
            c->write_retry = 0;
        } else {
            int err = get_error(c, n);
            if (err == SSL_ERROR_WANT_WRITE) {
                ep_mod(c->fd, EPOLLOUT | EPOLLET);
                return;
            }
            if (err == SSL_ERROR_WANT_READ) {
                ep_mod(c->fd, EPOLLIN | EPOLLOUT | EPOLLET);
                return;
            }
            if (err == SSL_ERROR_ZERO_RETURN || (err == SSL_ERROR_SYSCALL && errno == 0)) {
                cleanup_both(c->fd);
                return;
            }
            if (!c->write_retry) {
                c->write_retry = 1;
                ep_mod(c->fd, EPOLLOUT | EPOLLET);
                return;
            }
            cleanup(c->fd);
            return;
        }
    }

    if (c->len == 0) {
        c->off = 0;
        if (c->closing) {
            if (c->ssl) {
                c->state = ST_SHUTTING_DOWN;
                ep_mod(c->fd, EPOLLOUT | EPOLLET);
            } else {
                cleanup(c->fd);
            }
        } else {
            RpConnection *peer = c->peer >= 0 ? rp_conns[c->peer] : NULL;
            if (peer && peer->read_stalled) {
                peer->read_stalled = 0;
                ep_mod(peer->fd, EPOLLIN | EPOLLET);
            }
            ep_mod(c->fd, EPOLLIN | EPOLLET);
        }
    }
}

static void proxy_data(RpConnection *src, uint32_t events) {
    RpConnection *dst = src->peer >= 0 ? rp_conns[src->peer] : NULL;

    if (!dst && !src->closing) {
        cleanup(src->fd);
        return;
    }

    if (events & EPOLLOUT) {
        flush_buffer(src);
    }

    if ((events & EPOLLIN) && dst) {
        unsigned char temp[RP_BUF_SIZE];

        while (1) {
            dst = src->peer >= 0 ? rp_conns[src->peer] : NULL;
            if (!dst) {
                cleanup(src->fd);
                return;
            }

            size_t dst_space = buffer_space(dst);
            if (dst_space == 0) {
                compact_buffer(dst);
                dst_space = buffer_space(dst);
            }

            if (dst_space == 0) {
                if (!src->read_stalled) {
                    src->read_stalled = 1;
                    uint32_t ev = src->len > 0 ? (EPOLLOUT | EPOLLET) : 0;
                    if (ev) ep_mod(src->fd, ev);
                }
                ep_mod(dst->fd, EPOLLOUT | EPOLLET);
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
                        dst->write_retry = 0;
                    } else {
                        int err = get_error(dst, w);
                        if (err == SSL_ERROR_WANT_WRITE) break;
                        if (err == SSL_ERROR_WANT_READ) {
                            ep_mod(dst->fd, EPOLLIN | EPOLLOUT | EPOLLET);
                            break;
                        }
                        if (err == SSL_ERROR_ZERO_RETURN || (err == SSL_ERROR_SYSCALL && errno == 0)) {
                            cleanup_both(src->fd);
                            return;
                        }
                        if (!dst->write_retry) {
                            dst->write_retry = 1;
                            break;
                        }
                        cleanup(src->fd);
                        return;
                    }
                }

                if (written < (size_t)n) {
                    size_t remain = n - written;
                    if (buffer_space(dst) < remain) compact_buffer(dst);
                    memcpy(dst->buf + dst->off + dst->len, temp + written, remain);
                    dst->len += remain;
                    ep_mod(dst->fd, EPOLLOUT | EPOLLET);
                }
            } else if (n == 0) {
                cleanup(src->fd);
                return;
            } else {
                int err = get_error(src, n);
                if (err == SSL_ERROR_WANT_READ) break;
                if (err == SSL_ERROR_WANT_WRITE) {
                    ep_mod(src->fd, EPOLLOUT | EPOLLIN | EPOLLET);
                    break;
                }
                if (err == SSL_ERROR_ZERO_RETURN || (err == SSL_ERROR_SYSCALL && errno == 0)) {
                    cleanup(src->fd);
                    return;
                }
                cleanup(src->fd);
                return;
            }
        }
    }
}

static int create_backend(const char *host, const char *port) {
    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    set_nonblock(fd);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    struct linger lin = {.l_onoff = 0, .l_linger = 0};
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lin, sizeof(lin));

    connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    return fd;
}

static void handle_event(int fd, uint32_t events, const char *https_port) {
    RpConnection *c = rp_conns[fd];
    if (!c) return;

    if (events & EPOLLERR) {
        if (c->state == ST_CONNECTING) {
            RpConnection *client = rp_conns[c->peer];
            if (client) {
                send_error(client, 502, "Bad Gateway");
                client->peer = -1;
            }
            c->peer = -1;
            cleanup(fd);
        } else if (c->state == ST_PROXYING) {
            cleanup(fd);
        } else {
            cleanup_both(fd);
        }
        return;
    }

    if (events & EPOLLHUP) {
        if (c->state == ST_PROXYING && (events & EPOLLIN)) {
            proxy_data(c, events);
            return;
        }
        if (c->state != ST_SHUTTING_DOWN) {
            cleanup(fd);
            return;
        }
    }

    if (c->state != ST_PROXYING && c->len > 0 && (events & EPOLLOUT)) {
        flush_buffer(c);
        if (!rp_conns[fd]) return;
    }

    switch (c->state) {
    case ST_SSL_HANDSHAKE: {
        int ret = SSL_accept(c->ssl);
        if (ret == 1) {
            c->state = ST_READ_HEADER;
            ep_mod(fd, EPOLLIN | EPOLLET);
        } else {
            int err = SSL_get_error(c->ssl, ret);
            if (err == SSL_ERROR_WANT_READ)
                ep_mod(fd, EPOLLIN | EPOLLET);
            else if (err == SSL_ERROR_WANT_WRITE)
                ep_mod(fd, EPOLLOUT | EPOLLET);
            else
                cleanup(fd);
        }
        break;
    }

    case ST_READ_HEADER: {
        int n = do_read(c, c->buf + c->len, sizeof(c->buf) - c->len);
        if (n > 0)
            c->len += n;
        else if (n <= 0 && get_error(c, n) != SSL_ERROR_WANT_READ) {
            cleanup(fd);
            break;
        }

        int end = find_headers_end(c->buf, c->len);
        if (end > 0) {
            char host[256], target[512] = "/";
            extract_host(c->buf, end, host, sizeof(host));
            extract_target(c->buf, end, target, sizeof(target));

            if (!c->ssl) {
                send_redirect(c, host, target, https_port);
                break;
            }

            RpHostDomain *d = ds_da_find(&rp_domains, strcasecmp(e->domain, host) == 0);
            if (!d) {
                send_error(c, 421, "Misdirected Request");
                break;
            }

            ds_log_info("proxy: %s%s -> %s:%s\n", host, target, d->host, d->port);

            int backend = create_backend(d->host, d->port);
            if (backend < 0) {
                send_error(c, 502, "Bad Gateway");
                break;
            }

            RpConnection *b = alloc_conn(backend, NULL, ST_CONNECTING);
            c->peer = backend;
            b->peer = fd;
            ep_add(backend, EPOLLOUT | EPOLLET);
        } else if (c->len == sizeof(c->buf)) {
            send_error(c, 400, "Bad Request");
        }
        break;
    }

    case ST_CONNECTING: {
        int err = 0;
        socklen_t len = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
            RpConnection *client = rp_conns[c->peer];
            if (client) {
                send_error(client, 502, "Bad Gateway");
                client->peer = -1;
            }
            c->peer = -1;
            cleanup(fd);
            break;
        }

        RpConnection *client = rp_conns[c->peer];
        if (!client) {
            cleanup(fd);
            break;
        }

        c->state = ST_PROXYING;
        client->state = ST_PROXYING;

        if (client->len > 0) {
            compact_buffer(c);
            size_t room = buffer_space(c);
            size_t to_copy = client->len <= room ? client->len : room;
            if (to_copy > 0) {
                memcpy(c->buf + c->off + c->len, client->buf + client->off, to_copy);
                c->len += to_copy;
                client->off += to_copy;
                client->len -= to_copy;
                if (client->len == 0) client->off = 0;
            }
            ep_mod(fd, EPOLLOUT | EPOLLIN | EPOLLET);
            ep_mod(client->fd, EPOLLIN | EPOLLET);
        } else {
            ep_mod(fd, EPOLLIN | EPOLLET);
            ep_mod(client->fd, EPOLLIN | EPOLLET);
        }
        break;
    }

    case ST_PROXYING:
        proxy_data(c, events);
        break;

    case ST_SHUTTING_DOWN: {
        if (!c->ssl) {
            shutdown(c->fd, SHUT_WR);
            cleanup(c->fd);
            break;
        }

        int ret = SSL_shutdown(c->ssl);
        if (ret == 1) {
            cleanup(c->fd);
        } else if (ret == 0) {
            ep_mod(c->fd, EPOLLIN | EPOLLET);
        } else {
            int err = SSL_get_error(c->ssl, ret);
            if (err == SSL_ERROR_WANT_READ)
                ep_mod(c->fd, EPOLLIN | EPOLLET);
            else if (err == SSL_ERROR_WANT_WRITE)
                ep_mod(c->fd, EPOLLOUT | EPOLLET);
            else
                cleanup(c->fd);
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

    if (getaddrinfo(NULL, port, &hints, &res) != 0) return -1;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    if (bind(fd, res->ai_addr, res->ai_addrlen) < 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    set_nonblock(fd);
    listen(fd, 512);
    return fd;
}

void revpx_add_domain(const char *domain, const char *host, const char *port, const char *cert, const char *key) {
    ds_da_append(&rp_domains, ((RpHostDomain){
                                  .domain = strdup(domain),
                                  .host = host && host[0] ? strdup(host) : strdup(RP_DEFAULT_BACKEND_HOST),
                                  .port = strdup(port),
                                  .cert = strdup(cert),
                                  .key = strdup(key),
                                  .ctx = NULL}));
    ds_log_info("%s -> %s:%s\n", domain, host, port);
}

void revpx_run_server(const char *http_port, const char *https_port) {
    signal(SIGPIPE, SIG_IGN);
    SSL_library_init();
    SSL_load_error_strings();

    rp_epfd = epoll_create1(0);
    memset(rp_conns, 0, sizeof(rp_conns));

    int https_fd = create_listener(https_port);
    ep_add(https_fd, EPOLLIN | EPOLLET);
    ds_log_info("Listening https on %s\n", https_port);

    int http_fd = -1;
    if (http_port && *http_port) {
        http_fd = create_listener(http_port);
        ep_add(http_fd, EPOLLIN | EPOLLET);
        ds_log_info("Redirecting http %s -> %s\n", http_port, https_port);
    }

    SSL_CTX *default_ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_mode(default_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_tlsext_servername_callback(default_ctx, sni_callback);

    struct epoll_event events[RP_MAX_EVENTS];

    while (1) {
        int n = epoll_wait(rp_epfd, events, RP_MAX_EVENTS, -1);
        if (n < 0 && errno != EINTR) break;

        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;

            if (fd == https_fd) {
                while (1) {
                    int client = accept(https_fd, NULL, NULL);
                    if (client < 0) break;
                    set_nonblock(client);
                    struct linger lin = {.l_onoff = 0, .l_linger = 0};
                    setsockopt(client, SOL_SOCKET, SO_LINGER, &lin, sizeof(lin));

                    SSL *ssl = SSL_new(default_ctx);
                    SSL_set_fd(ssl, client);
                    SSL_set_accept_state(ssl);

                    RpConnection *c = alloc_conn(client, ssl, ST_SSL_HANDSHAKE);
                    if (!c) continue;

                    int ret = SSL_accept(ssl);
                    if (ret == 1) {
                        c->state = ST_READ_HEADER;
                        ep_add(client, EPOLLIN | EPOLLET);
                    } else {
                        int err = SSL_get_error(ssl, ret);
                        ep_add(client, err == SSL_ERROR_WANT_WRITE ? (EPOLLOUT | EPOLLET) : (EPOLLIN | EPOLLET));
                    }
                }
            } else if (http_fd >= 0 && fd == http_fd) {
                while (1) {
                    int client = accept(http_fd, NULL, NULL);
                    if (client < 0) break;
                    set_nonblock(client);
                    struct linger lin = {.l_onoff = 0, .l_linger = 0};
                    setsockopt(client, SOL_SOCKET, SO_LINGER, &lin, sizeof(lin));

                    RpConnection *c = alloc_conn(client, NULL, ST_READ_HEADER);
                    if (c) ep_add(client, EPOLLIN | EPOLLET);
                }
            } else {
                handle_event(fd, events[i].events, https_port);
            }
        }
    }

    SSL_CTX_free(default_ctx);
    ds_da_foreach(&rp_domains, d) {
        if (d->ctx) SSL_CTX_free(d->ctx);
        if (d->domain) free(d->domain);
        if (d->port) free(d->port);
        if (d->cert) free(d->cert);
        if (d->key) free(d->key);
        if (d->host) free(d->host);
    }
    ds_da_free(&rp_domains);
}

#endif // REVPX_IMPLEMENTATION
#endif // REVPX_H