#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>

#define DS_NO_PREFIX
#include "ds.h"
#include "ep.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#define BACKEND_HOST "127.0.0.1"
#define MAX_EVENTS 1024
#define BUF_SIZE 16384
#define MAX_FD_MAP 65536
#define REDIRECT_BUF_SIZE 4096
#define ERROR_BUF_SIZE 1024

typedef enum {
    ST_SSL_HANDSHAKE,
    ST_READ_CLIENT_HEADER,
    ST_READ_PLAIN_HEADER,
    ST_BACKEND_CONNECTING,
    ST_PROXYING,
    ST_SHUTTING_DOWN,
} conn_state_e;

typedef struct conn {
    int fd;
    SSL *ssl;
    int peer_fd;
    conn_state_e state;

    unsigned char buf[BUF_SIZE];
    size_t buf_len;
    size_t buf_off;
    int closing_after_flush;  // when set, close the connection once buf is fully drained
    int write_error_grace;    // allow one retry on next EPOLLOUT before half-close
    int read_stalled_by_peer; // flag: reading is stalled due to full peer buffer
} conn_t;

static conn_t *fd_map[MAX_FD_MAP];

typedef struct {
    const char *domain;
    const char *port;
    const char *cert_file;
    const char *key_file;
    SSL_CTX *ctx;
} domain_map_t;

da_declare(DomainMap, domain_map_t);

static DomainMap DOMAIN_MAP = {0};

// Diagnostic helper for SSL errors
static void log_ssl_diag(conn_t *c, const char *where, int ret, int ssl_err) {
    unsigned long e = ERR_peek_last_error();
    const char *reason = e ? ERR_reason_error_string(e) : NULL;
    int sd = c && c->ssl ? SSL_get_shutdown(c->ssl) : 0;
    log_debug("tls: %s fd=%d ret=%d ssl_err=%d shutdown=%d errno=%d openssl_reason=%s\n",
              where, c ? c->fd : -1, ret, ssl_err, sd, errno, reason ? reason : "(none)");
}

// Buffer helpers for per-connection outgoing buffer (buf_off + buf_len represent valid data)
static inline size_t conn_buf_tail_room(conn_t *c) {
    size_t used = c->buf_off + c->buf_len;
    if (used >= sizeof(c->buf)) return 0;
    return sizeof(c->buf) - used;
}

static inline void conn_buf_compact(conn_t *c) {
    if (c->buf_off > 0 && c->buf_len > 0) {
        memmove(c->buf, c->buf + c->buf_off, c->buf_len);
        c->buf_off = 0;
    } else if (c->buf_len == 0) {
        c->buf_off = 0;
    }
}

static const char *lookup_backend_port(const char *host) {
    if (!host || !*host) return NULL;
    da_foreach(&DOMAIN_MAP, item) {
        if (strcasecmp(item->domain, host) == 0) return item->port;
    }
    return NULL;
}

static void mod_epoll(int epfd, int fd, uint32_t events);
static void close_and_cleanup_fd(int epfd, int fd);

static void close_one_side_keep_peer(int epfd, int fd) {
    if (fd < 0 || fd >= MAX_FD_MAP) return;
    conn_t *c = fd_map[fd];
    if (!c) return;

    int peer_fd = c->peer_fd;
    conn_t *peer = (peer_fd >= 0 && peer_fd < MAX_FD_MAP) ? fd_map[peer_fd] : NULL;

    log_debug("half-close: closing fd=%d keep peer_fd=%d\n", fd, peer_fd);
    epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
    fd_map[fd] = NULL;
    if (c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
    }
    close(c->fd);
    free(c);

    if (peer) {
        peer->peer_fd = -1;
        if (peer->buf_len > 0) { // Removed SSL_pending check, not relevant for write-side closing
            peer->closing_after_flush = 1;
            mod_epoll(epfd, peer->fd, EPOLLOUT | EPOLLET);
        } else {
            log_debug("half-close: initiating shutdown on peer fd=%d\n", peer_fd);
            peer->state = ST_SHUTTING_DOWN;
            // SSL_shutdown() can require writes, so start with EPOLLOUT
            mod_epoll(epfd, peer->fd, EPOLLOUT | EPOLLET);
        }
    }
}

static int find_header_end(const unsigned char *buf, size_t len) {
    if (len < 4) return -1;
    for (size_t i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') return (int)(i + 4);
    }
    for (size_t i = 0; i + 1 < len; i++) {
        if (buf[i] == '\n' && buf[i + 1] == '\n') return (int)(i + 2);
    }
    return -1;
}

static int extract_host(const unsigned char *buf, size_t len, char *out, size_t outsz) {
    const char *line_start = (const char *)buf;
    const char *buf_end = (const char *)buf + len;
    while (line_start < buf_end) {
        const char *line_end = memchr(line_start, '\n', buf_end - line_start);
        if (!line_end) line_end = buf_end;
        if (line_end == line_start || (line_end > line_start && line_end[-1] == '\r' && line_end - line_start == 1)) break;
        if (strncasecmp(line_start, "Host:", 5) == 0) {
            const char *host_start = line_start + 5;
            while (host_start < line_end && (*host_start == ' ' || *host_start == '\t'))
                host_start++;
            const char *host_end = line_end;
            if (host_end > host_start && host_end[-1] == '\r') host_end--;
            while (host_end > host_start && (host_end[-1] == ' ' || host_end[-1] == '\t'))
                host_end--;
            size_t copy_len = host_end - host_start;
            if (copy_len >= outsz) copy_len = outsz - 1;
            memcpy(out, host_start, copy_len);
            out[copy_len] = '\0';
            char *colon = strchr(out, ':');
            if (colon) *colon = '\0';
            return 1;
        }
        line_start = line_end + 1;
    }
    return 0;
}

static int extract_request_target(const unsigned char *buf, size_t len, char *out, size_t outsz) {
    if (!buf || len == 0 || !out || outsz == 0) return 0;
    const char *p = (const char *)buf;
    const char *end = (const char *)buf + len;
    const char *line_end = memchr(p, '\n', end - p);
    if (!line_end) line_end = end;
    if (line_end > p && line_end[-1] == '\r') line_end--;
    const char *sp1 = memchr(p, ' ', line_end - p);
    if (!sp1) return 0;
    while (sp1 < line_end && *sp1 == ' ')
        sp1++;
    const char *sp2 = memchr(sp1, ' ', line_end - sp1);
    if (!sp2) return 0;
    size_t copy_len = (size_t)(sp2 - sp1);
    if (copy_len >= outsz) copy_len = outsz - 1;
    memcpy(out, sp1, copy_len);
    out[copy_len] = '\0';
    return 1;
}

static SSL_CTX *create_ctx(const char *crt, const char *key) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    if (SSL_CTX_use_certificate_file(ctx, crt, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    return ctx;
}

static domain_map_t *find_domain_entry(const char *host) {
    if (!host) return NULL;
    da_foreach(&DOMAIN_MAP, item) {
        if (strcasecmp(item->domain, host) == 0) return item;
    }
    return NULL;
}

static int sni_servername_cb(SSL *ssl, int *ad, void *arg) {
    (void)ad;
    (void)arg;
    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!servername) return SSL_TLSEXT_ERR_NOACK;

    domain_map_t *entry = find_domain_entry(servername);
    if (!entry) return SSL_TLSEXT_ERR_NOACK;

    if (!entry->ctx) {
        entry->ctx = create_ctx(entry->cert_file, entry->key_file);
        if (!entry->ctx) return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    if (SSL_set_SSL_CTX(ssl, entry->ctx) == NULL) return SSL_TLSEXT_ERR_NOACK;
    return SSL_TLSEXT_ERR_OK;
}

static void mod_epoll(int epfd, int fd, uint32_t events);

static void close_and_cleanup_fd(int epfd, int fd) {
    if (fd < 0 || fd >= MAX_FD_MAP) return;
    conn_t *c = fd_map[fd];
    if (!c) return;

    log_debug("cleanup: closing fd=%d peer_fd=%d\n", fd, c->peer_fd);
    epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
    fd_map[fd] = NULL;
    int peer_fd = c->peer_fd;

    if (c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
    }
    close(c->fd);
    free(c);

    if (peer_fd >= 0) {
        conn_t *peer = fd_map[peer_fd];
        if (peer) {
            // If peer has pending buffered data, allow it to flush before closing.
            if (peer->buf_len > 0 && peer->state == ST_PROXYING) {
                log_debug("cleanup: detaching peer fd=%d to flush pending=%zu before close\n", peer_fd, peer->buf_len);
                peer->peer_fd = -1;
                peer->closing_after_flush = 1;
                mod_epoll(epfd, peer->fd, EPOLLOUT | EPOLLET);
            } else {
                log_debug("cleanup: also closing peer fd=%d (no pending)\n", peer_fd);
                epoll_ctl(epfd, EPOLL_CTL_DEL, peer_fd, NULL);
                fd_map[peer_fd] = NULL;
                if (peer->ssl) {
                    SSL_shutdown(peer->ssl);
                    SSL_free(peer->ssl);
                }
                close(peer->fd);
                free(peer);
            }
        }
    }
}

static void set_nonblock(int fd) {
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
}

static void add_epoll(int epfd, int fd, uint32_t events) {
    struct epoll_event ev = {.data.fd = fd, .events = events};
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
}

static void mod_epoll(int epfd, int fd, uint32_t events) {
    struct epoll_event ev = {.data.fd = fd, .events = events};
    epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
}

static conn_t *alloc_conn(int fd, SSL *ssl, conn_state_e state) {
    if (fd >= MAX_FD_MAP) {
        close(fd);
        if (ssl) SSL_free(ssl);
        return NULL;
    }
    conn_t *c = calloc(1, sizeof(conn_t));
    c->fd = fd;
    c->ssl = ssl;
    c->peer_fd = -1;
    c->state = state;
    c->closing_after_flush = 0;
    c->write_error_grace = 0;
    c->read_stalled_by_peer = 0;
    fd_map[fd] = c;
    return c;
}

static int start_connect_backend(const char *port) {
    struct addrinfo hints = {0}, *res, *rp;
    int sfd = -1;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    log_debug("backend: resolving %s:%s\n", BACKEND_HOST, port);
    if (getaddrinfo(BACKEND_HOST, port, &hints, &res) != 0) return -1;
    for (rp = res; rp; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd < 0) continue;
        set_nonblock(sfd);
        // Reduce latency for small writes
        int one = 1;
        setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        // Disable linger to avoid RST-on-close behavior
        struct linger lin = {.l_onoff = 0, .l_linger = 0};
        setsockopt(sfd, SOL_SOCKET, SO_LINGER, &lin, sizeof(lin));
        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) == 0 || errno == EINPROGRESS) {
            log_debug("backend: connecting fd=%d to %s:%s (in-progress OK)\n", sfd, BACKEND_HOST, port);
            break;
        }
        close(sfd);
        sfd = -1;
    }
    freeaddrinfo(res);
    return sfd;
}

static int do_write(conn_t *c, const void *buf, size_t len) {
    if (c->ssl) return SSL_write(c->ssl, buf, (int)len);
    return write(c->fd, buf, len);
}

static int get_ssl_error(conn_t *c, int ret) {
    return c->ssl ? SSL_get_error(c->ssl, ret) : 0;
}

static void handle_proxy(int epfd, conn_t *c, uint32_t events) {
    conn_t *peer = (c->peer_fd >= 0 && c->peer_fd < MAX_FD_MAP) ? fd_map[c->peer_fd] : NULL;

    // If peer is gone, we should only be flushing our buffer.
    // Any other event (like EPOLLIN) or state is unexpected and we should close.
    if (!peer && !(c->closing_after_flush && (events & EPOLLOUT))) {
        log_debug("proxy: closing fd=%d because peer is gone and not flushing (events=%u).\n", c->fd, events);
        close_and_cleanup_fd(epfd, c->fd);
        return;
    }

    if (events & EPOLLOUT) {
        size_t buf_len_before = c->buf_len;
        while (c->buf_len > 0) {
            int n = do_write(c, c->buf + c->buf_off, c->buf_len);
            if (n > 0) {
                c->buf_off += n;
                c->buf_len -= n;
                if (c->write_error_grace) c->write_error_grace = 0;
                log_debug("proxy: wrote %d bytes to fd=%d (remaining=%zu)\n", n, c->fd, c->buf_len);
            } else {
                int err = get_ssl_error(c, n);
                if (err == SSL_ERROR_WANT_WRITE || errno == EAGAIN) break;
                if (err == SSL_ERROR_WANT_READ) {
                    mod_epoll(epfd, c->fd, EPOLLIN | EPOLLOUT | EPOLLET);
                    return;
                }
                if (err == SSL_ERROR_ZERO_RETURN || (err == SSL_ERROR_SYSCALL && errno == 0)) {
                    log_ssl_diag(c, "SSL_write clean shutdown", n, err);
                    if (peer) close_and_cleanup_fd(epfd, peer->fd);
                    close_and_cleanup_fd(epfd, c->fd);
                    return;
                }
                if (err == SSL_ERROR_SSL) {
                    log_ssl_diag(c, "SSL_write fatal", n, err);
                    if (peer) close_and_cleanup_fd(epfd, peer->fd);
                    close_and_cleanup_fd(epfd, c->fd);
                    return;
                }
                log_debug("proxy: EPOLLOUT write error fd=%d errno=%d ssl_err=%d buf_len=%zu (grace=%d)\n", c->fd, errno, err, c->buf_len, c->write_error_grace);
                if (c->write_error_grace == 0) {
                    c->write_error_grace = 1;
                    mod_epoll(epfd, c->fd, EPOLLIN | EPOLLOUT | EPOLLET);
                    return;
                }
                log_debug("proxy: repeated write failure (attempts=%d) on fd=%d; closing both ends (peer=%d)\n", c->write_error_grace, c->fd, peer ? peer->fd : -1);
                if (peer) close_and_cleanup_fd(epfd, peer->fd);
                close_and_cleanup_fd(epfd, c->fd);
                return;
            }
        }

        if (c->buf_len < buf_len_before) { // we made space in buffer
            conn_t *source = (c->peer_fd >= 0 && c->peer_fd < MAX_FD_MAP) ? fd_map[c->peer_fd] : NULL;
            if (source && source->read_stalled_by_peer) {
                log_debug("proxy: peer fd=%d buffer drained, unstalling read on fd=%d\n", c->fd, source->fd);
                source->read_stalled_by_peer = 0;
                mod_epoll(epfd, source->fd, EPOLLIN | EPOLLOUT | EPOLLET);
            }
        }

        if (c->buf_len == 0) {
            c->buf_off = 0;
            if (c->write_error_grace) c->write_error_grace = 0;
            if (c->closing_after_flush) {
                log_debug("proxy: flush complete on fd=%d, initiating shutdown.\n", c->fd);
                c->state = ST_SHUTTING_DOWN;
                // The shutdown handshake can require writes, so trigger EPOLLOUT.
                // The ST_SHUTTING_DOWN handler will be called on the next event loop iteration.
                mod_epoll(epfd, c->fd, EPOLLOUT | EPOLLET);
                return;
            }
            mod_epoll(epfd, c->fd, EPOLLIN | EPOLLET);
        } else {
            mod_epoll(epfd, c->fd, EPOLLIN | EPOLLOUT | EPOLLET);
        }
    }

    if (events & EPOLLIN) {
        if (!peer) {
            close_and_cleanup_fd(epfd, c->fd);
            return;
        }
        unsigned char temp_buf[BUF_SIZE];
        while (1) {
            peer = (c->peer_fd >= 0 && c->peer_fd < MAX_FD_MAP) ? fd_map[c->peer_fd] : NULL;
            if (!peer) {
                close_and_cleanup_fd(epfd, c->fd);
                return;
            }
            size_t read_cap = sizeof(temp_buf);
            size_t peer_room = conn_buf_tail_room(peer);
            if (peer_room == 0) {
                conn_buf_compact(peer);
                peer_room = conn_buf_tail_room(peer);
            }
            if (peer_room == 0) {
                if (!c->read_stalled_by_peer) {
                    log_debug("proxy: peer fd=%d buffer full, stalling read on fd=%d\n", peer->fd, c->fd);
                    c->read_stalled_by_peer = 1;
                    uint32_t source_events = (c->buf_len > 0) ? (EPOLLOUT | EPOLLET) : 0;
                    mod_epoll(epfd, c->fd, source_events);
                }
                mod_epoll(epfd, peer->fd, EPOLLIN | EPOLLOUT | EPOLLET);
                break;
            }
            if (peer_room < read_cap) read_cap = peer_room;
            if (read_cap == 0) {
                mod_epoll(epfd, peer->fd, EPOLLOUT | EPOLLET);
                break;
            }

            int nread;
            if (c->ssl)
                nread = SSL_read(c->ssl, temp_buf, (int)read_cap);
            else
                nread = read(c->fd, temp_buf, read_cap);

            if (nread > 0) {
                log_debug("proxy: read %d bytes from fd=%d\n", nread, c->fd);
                size_t nwritten = 0;
                while (nwritten < (size_t)nread) {
                    int n = do_write(peer, temp_buf + nwritten, nread - nwritten);
                    if (n > 0) {
                        nwritten += n;
                        if (peer->write_error_grace) peer->write_error_grace = 0;
                        log_debug("proxy: forwarded %d bytes to peer fd=%d (total=%zu/%d)\n", n, peer->fd, nwritten, nread);
                    } else {
                        int err = get_ssl_error(peer, n);
                        if (err == SSL_ERROR_WANT_WRITE || errno == EAGAIN) break;
                        if (err == SSL_ERROR_ZERO_RETURN || (err == SSL_ERROR_SYSCALL && errno == 0)) {
                            log_ssl_diag(peer, "forward SSL_write clean shutdown", n, err);
                            close_and_cleanup_fd(epfd, peer->fd);
                            close_and_cleanup_fd(epfd, c->fd);
                            return;
                        }
                        if (err == SSL_ERROR_SSL) {
                            log_ssl_diag(peer, "forward SSL_write fatal", n, err);
                            close_and_cleanup_fd(epfd, peer->fd);
                            close_and_cleanup_fd(epfd, c->fd);
                            return;
                        }
                        if (peer->write_error_grace == 0) {
                            peer->write_error_grace = 1;
                            break;
                        }
                        close_one_side_keep_peer(epfd, c->fd);
                        return;
                    }
                }
                if (nwritten < (size_t)nread) {
                    size_t need = (size_t)(nread - nwritten);
                    if (conn_buf_tail_room(peer) < need) {
                        conn_buf_compact(peer);
                    }
                    memcpy(peer->buf + peer->buf_off + peer->buf_len, temp_buf + nwritten, need);
                    peer->buf_len += need;
                    log_debug("proxy: queued %zu bytes to peer fd=%d buffer (buf_len=%zu, peer_fd_of_peer=%d)\n", (size_t)(nread - nwritten), peer->fd, peer->buf_len, peer->peer_fd);
                    mod_epoll(epfd, peer->fd, EPOLLOUT | EPOLLET);
                }
            } else {
                if (c->ssl) {
                    int err = SSL_get_error(c->ssl, nread);
                    if (err == SSL_ERROR_WANT_READ) break;
                    if (err == SSL_ERROR_ZERO_RETURN || (err == SSL_ERROR_SYSCALL && errno == 0)) {
                        log_ssl_diag(c, "SSL_read clean shutdown", nread, err);
                        close_one_side_keep_peer(epfd, c->fd);
                        return;
                    }
                    log_ssl_diag(c, "SSL_read fatal", nread, err);
                    close_one_side_keep_peer(epfd, c->fd);
                    return;
                } else {
                    if (nread == 0) {
                        log_debug("proxy: source fd=%d EOF, peer fd=%d buf_len=%zu\n", c->fd, peer->fd, peer->buf_len);
                        close_one_side_keep_peer(epfd, c->fd);
                        return;
                    }
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    log_debug("proxy: fatal read error on source fd=%d (errno=%d), peer fd=%d buf_len=%zu\n", c->fd, errno, peer->fd, peer->buf_len);
                    close_one_side_keep_peer(epfd, c->fd);
                    return;
                }
            }
        }
    }
}

static int create_and_bind(const char *port) {
    struct addrinfo hints = {0}, *res, *rp;
    int sfd;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(NULL, port, &hints, &res) != 0) {
        perror("getaddrinfo");
        exit(1);
    }
    for (rp = res; rp; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd < 0) continue;
        int yes = 1;
        setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(sfd);
    }
    if (!rp) {
        fprintf(stderr, "Unable to bind\n");
        exit(1);
    }
    freeaddrinfo(res);
    return sfd;
}

static int do_write(conn_t *c, const void *buf, size_t len);

static void send_http_error_and_close(int epfd, conn_t *client, int status, const char *reason, const char *detail) {
    log_error("HTTP %d %s: %s\n", status, reason, detail ? detail : "");
    if (!client) return;
    char body[ERROR_BUF_SIZE];
    int body_len = snprintf(body, sizeof(body),
                            "<html><head><title>%d %s</title></head><body><h1>%d %s</h1><p>revpx err: %s</p></body></html>",
                            status, reason, status, reason, detail ? detail : "");
    if (body_len < 0) body_len = 0;
    if (body_len > (int)sizeof(body)) body_len = (int)sizeof(body);

    char header[ERROR_BUF_SIZE];
    int header_len = snprintf(header, sizeof(header),
                              "HTTP/1.1 %d %s\r\n"
                              "Content-Type: text/html; charset=UTF-8\r\n"
                              "Content-Length: %d\r\n"
                              "Connection: close\r\n"
                              "\r\n",
                              status, reason, body_len);
    if (header_len < 0) header_len = 0;
    if (header_len > (int)sizeof(header)) header_len = (int)sizeof(header);

    // Enqueue header+body into client's buffer and flush via EPOLLOUT, then close
    size_t needed = (size_t)header_len + (size_t)body_len;
    if (needed <= sizeof(client->buf)) {
        memcpy(client->buf, header, (size_t)header_len);
        if (body_len > 0) memcpy(client->buf + header_len, body, (size_t)body_len);
        client->buf_len = needed;
        client->buf_off = 0;
        client->closing_after_flush = 1;
        mod_epoll(epfd, client->fd, EPOLLOUT | EPOLLET);
    } else {
        // Fallback: write best-effort and close (should not happen with current sizes)
        if (header_len > 0) (void)do_write(client, header, (size_t)header_len);
        if (body_len > 0) (void)do_write(client, body, (size_t)body_len);
        close_and_cleanup_fd(epfd, client->fd);
    }
}

static void send_http_redirect_and_close(int epfd, conn_t *client, const char *host, const char *target, const char *sec_port) {
    if (!client) return;
    if (!host) host = "";
    if (!target || target[0] == '\0') target = "/";

    char location[REDIRECT_BUF_SIZE];
    if (sec_port && strcmp(sec_port, "443") != 0) {
        snprintf(location, sizeof(location), "https://%s:%s%s", host, sec_port, target);
    } else {
        snprintf(location, sizeof(location), "https://%s%s", host, target);
    }

    char header[REDIRECT_BUF_SIZE];
    int header_len = snprintf(header, sizeof(header),
                              "HTTP/1.1 301 Moved Permanently\r\n"
                              "Location: %s\r\n"
                              "Content-Length: 0\r\n"
                              "Connection: close\r\n"
                              "\r\n",
                              location);
    // Enqueue header (Content-Length: 0) and flush before close to avoid truncation
    if (header_len > 0 && (size_t)header_len <= sizeof(client->buf)) {
        memcpy(client->buf, header, (size_t)header_len);
        client->buf_len = (size_t)header_len;
        client->buf_off = 0;
        client->closing_after_flush = 1;
        mod_epoll(epfd, client->fd, EPOLLOUT | EPOLLET);
    } else {
        // Fallback
        if (header_len > 0) (void)do_write(client, header, (size_t)header_len);
        close_and_cleanup_fd(epfd, client->fd);
    }
}

static void init_revpx() {
    signal(SIGPIPE, SIG_IGN);
    SSL_library_init();
    SSL_load_error_strings();
}

static void free_revpx() {
    da_foreach(&DOMAIN_MAP, item) {
        if (item->ctx) SSL_CTX_free(item->ctx);
        if (item->domain) free((void *)item->domain);
        if (item->port) free((void *)item->port);
        if (item->cert_file) free((void *)item->cert_file);
        if (item->key_file) free((void *)item->key_file);
    }
    da_free(&DOMAIN_MAP);
}

void add_domain(const char *domain, const char *port, const char *cert_file, const char *key_file) {
    char *d = domain ? strdup(domain) : NULL;
    char *p = port ? strdup(port) : NULL;
    char *c = cert_file ? strdup(cert_file) : NULL;
    char *k = key_file ? strdup(key_file) : NULL;
    da_append(&DOMAIN_MAP, ((domain_map_t){.domain = d, .port = p, .ctx = NULL, .cert_file = c, .key_file = k}));
    log_debug("domain map: %s -> %s (cert=%s, key=%s)\n", domain, port, cert_file, key_file);
}

void run_revpx_server(const char *port, const char *sec_port) {
    init_revpx();
    int listen_fd_tls = create_and_bind(sec_port);
    set_nonblock(listen_fd_tls);
    listen(listen_fd_tls, 512);
    log_info("revpx TLS listening on port %s\n", sec_port);

    int listen_fd_plain = -1;
    if (port && *port) {
        listen_fd_plain = create_and_bind(port);
        set_nonblock(listen_fd_plain);
        listen(listen_fd_plain, 512);
        log_info("revpx plain HTTP listening on port %s (redirecting to %s)\n", port, sec_port);
    }

    int epfd = epoll_create1(0);
    memset(fd_map, 0, sizeof(fd_map));

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    // Ensure default context supports partial writes and moving write buffers like per-domain contexts
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_tlsext_servername_callback(ctx, sni_servername_cb);
    SSL_CTX_set_tlsext_servername_arg(ctx, NULL);

    add_epoll(epfd, listen_fd_tls, EPOLLIN | EPOLLET);
    if (listen_fd_plain >= 0) add_epoll(epfd, listen_fd_plain, EPOLLIN | EPOLLET);
    struct epoll_event events[MAX_EVENTS];

    while (1) {
        int ready = epoll_wait(epfd, events, MAX_EVENTS, -1);
        if (ready < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < ready; ++i) {
            int fd = events[i].data.fd;
            uint32_t ev = events[i].events;

            if (fd == listen_fd_tls) {
                while (1) {
                    int cfd = accept(listen_fd_tls, NULL, NULL);
                    if (cfd < 0) break;
                    set_nonblock(cfd);
                    // Disabling TCP_NODELAY as a test
                    // int one = 1;
                    // setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
                    struct linger clin = {.l_onoff = 0, .l_linger = 0};
                    setsockopt(cfd, SOL_SOCKET, SO_LINGER, &clin, sizeof(clin));
                    SSL *ssl = SSL_new(ctx);
                    SSL_set_fd(ssl, cfd);
                    SSL_set_accept_state(ssl);
                    conn_t *client = alloc_conn(cfd, ssl, ST_SSL_HANDSHAKE);
                    if (!client) continue;
                    log_debug("accept: client fd=%d\n", cfd);

                    int ret = SSL_accept(ssl);
                    if (ret == 1) {
                        client->state = ST_READ_CLIENT_HEADER;
                        add_epoll(epfd, cfd, EPOLLIN | EPOLLET);
                        log_debug("ssl: handshake complete fd=%d -> READ_CLIENT_HEADER\n", cfd);
                    } else {
                        int err = SSL_get_error(ssl, ret);
                        if (err == SSL_ERROR_WANT_READ)
                            add_epoll(epfd, cfd, EPOLLIN | EPOLLET);
                        else if (err == SSL_ERROR_WANT_WRITE)
                            add_epoll(epfd, cfd, EPOLLOUT | EPOLLET);
                        else
                            close_and_cleanup_fd(epfd, cfd);
                    }
                }
                continue;
            } else if (listen_fd_plain >= 0 && fd == listen_fd_plain) {
                while (1) {
                    int cfd = accept(listen_fd_plain, NULL, NULL);
                    if (cfd < 0) break;
                    set_nonblock(cfd);
                    // Disabling TCP_NODELAY as a test
                    // int one = 1;
                    // setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
                    struct linger plin = {.l_onoff = 0, .l_linger = 0};
                    setsockopt(cfd, SOL_SOCKET, SO_LINGER, &plin, sizeof(plin));
                    conn_t *client = alloc_conn(cfd, NULL, ST_READ_PLAIN_HEADER);
                    if (!client) continue;
                    add_epoll(epfd, cfd, EPOLLIN | EPOLLET);
                    log_debug("accept: plain client fd=%d\n", cfd);
                }
                continue;
            }

            conn_t *c = fd_map[fd];
            if (!c) continue;

            // Handle error/hangup
            if (ev & EPOLLERR) {
                log_debug("proxy: closing fd=%d due to EPOLLERR (state=%d).\n", fd, c->state);
                if (c->state == ST_BACKEND_CONNECTING) {
                    conn_t *client = fd_map[c->peer_fd];
                    if (client) {
                        send_http_error_and_close(epfd, client, 502, "Bad Gateway", "Backend connection failed");
                        client->peer_fd = -1; // Detach client from us
                    }
                    c->peer_fd = -1;                // Detach from client
                    close_and_cleanup_fd(epfd, fd); // Close ourselves
                } else if (c->state == ST_PROXYING) {
                    close_one_side_keep_peer(epfd, fd);
                } else {
                    close_and_cleanup_fd(epfd, fd);
                }
                continue;
            }
            if (ev & EPOLLHUP) {
                // If HUP is received for a proxy connection and there's also data to be read (EPOLLIN),
                // we must let the proxy handler read the data before closing the connection.
                // Otherwise, we would close the socket and lose the pending data.
                if (c->state == ST_PROXYING && (ev & EPOLLIN)) {
                    log_debug("proxy: EPOLLHUP on fd=%d with EPOLLIN, letting proxy handler read remaining data (state=%d).\n", fd, c->state);
                    // Fall through to let handle_proxy() read the last bytes and EOF.
                } else if (c->state != ST_SHUTTING_DOWN) {
                    log_debug("proxy: closing fd=%d due to EPOLLHUP (state=%d).\n", fd, c->state);
                    close_one_side_keep_peer(epfd, fd);
                    continue;
                }
                // If in ST_SHUTTING_DOWN, the HUP is expected. Fall through.
            }

            // Generic buffered write flush for any non-proxy state (used for error/redirect responses)
            if ((ev & EPOLLOUT) && c->state != ST_PROXYING && c->buf_len > 0) {
                while (c->buf_len > 0) {
                    int n = do_write(c, c->buf + c->buf_off, c->buf_len);
                    if (n > 0) {
                        c->buf_off += n;
                        c->buf_len -= n;
                        log_debug("flush: wrote %d bytes to fd=%d (remaining=%zu)\n", n, c->fd, c->buf_len);
                    } else {
                        int err = get_ssl_error(c, n);
                        if (err == SSL_ERROR_WANT_WRITE || errno == EAGAIN) break;
                        if (err == SSL_ERROR_WANT_READ) {
                            mod_epoll(epfd, fd, EPOLLIN | EPOLLOUT | EPOLLET);
                            break;
                        }
                        close_and_cleanup_fd(epfd, fd);
                        continue; // proceed to next event in the outer loop
                    }
                }
                if (c->buf_len == 0) {
                    c->buf_off = 0;
                    if (c->closing_after_flush) {
                        c->state = ST_SHUTTING_DOWN;
                        mod_epoll(epfd, fd, EPOLLOUT | EPOLLET);
                        continue;
                    } else {
                        // Resume normal interest
                        mod_epoll(epfd, fd, EPOLLIN | EPOLLET);
                    }
                }
            }

            switch (c->state) {
            case ST_SSL_HANDSHAKE: {
                int ret = SSL_accept(c->ssl);
                if (ret == 1) {
                    c->state = ST_READ_CLIENT_HEADER;
                    mod_epoll(epfd, fd, EPOLLIN | EPOLLET);
                    log_debug("ssl: handshake complete fd=%d -> READ_CLIENT_HEADER\n", fd);
                } else {
                    int err = SSL_get_error(c->ssl, ret);
                    if (err == SSL_ERROR_WANT_READ)
                        mod_epoll(epfd, fd, EPOLLIN | EPOLLET);
                    else if (err == SSL_ERROR_WANT_WRITE)
                        mod_epoll(epfd, fd, EPOLLOUT | EPOLLET);
                    else
                        close_and_cleanup_fd(epfd, fd);
                }
                break;
            }
            case ST_READ_PLAIN_HEADER: {
                int r = read(c->fd, c->buf + c->buf_len, sizeof(c->buf) - c->buf_len);
                if (r > 0) {
                    c->buf_len += r;
                } else if (r == 0 || (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                    close_and_cleanup_fd(epfd, fd);
                    break;
                }

                int hdr_end = find_header_end(c->buf, c->buf_len);
                if (hdr_end > 0) {
                    char host[256] = {0};
                    char target[512] = "/";
                    (void)extract_host(c->buf, hdr_end, host, sizeof(host));
                    (void)extract_request_target(c->buf, (size_t)hdr_end, target, sizeof(target));
                    log_info("redirect: http://%s%s -> https://%s:%s%s\n", host, target, host, sec_port, target);
                    send_http_redirect_and_close(epfd, c, host, target, sec_port);
                } else if (c->buf_len == sizeof(c->buf)) {
                    // Malformed or too large; just close
                    close_and_cleanup_fd(epfd, fd);
                }
                break;
            }
            case ST_READ_CLIENT_HEADER: {
                int r = SSL_read(c->ssl, c->buf + c->buf_len, sizeof(c->buf) - c->buf_len);
                if (r > 0)
                    c->buf_len += r;
                else if (r == 0 || (r < 0 && SSL_get_error(c->ssl, r) != SSL_ERROR_WANT_READ)) {
                    send_http_error_and_close(epfd, c, 400, "Bad Request", "Failed to read request");
                    break;
                }

                int hdr_end = find_header_end(c->buf, c->buf_len);
                if (hdr_end > 0) {
                    char host[256];
                    const char *backend_port = NULL;
                    if (extract_host(c->buf, hdr_end, host, sizeof(host))) {
                        backend_port = lookup_backend_port(host);
                        log_debug("request: host='%s' -> port='%s'\n", host, backend_port ? backend_port : "(null)");
                    }
                    if (!backend_port) {
                        send_http_error_and_close(epfd, c, 421, "Misdirected Request", "Unknown Host header");
                        break;
                    }

                    int bfd = start_connect_backend(backend_port);
                    if (bfd < 0) {
                        send_http_error_and_close(epfd, c, 502, "Bad Gateway", "Failed to connect to backend");
                        break;
                    }

                    char target[512] = "/";
                    if (!extract_request_target(c->buf, (size_t)hdr_end, target, sizeof(target))) {
                        strcpy(target, "/");
                    }
                    log_info("proxy: %s%s -> %s:%s\n", host, target, BACKEND_HOST, backend_port);
                    conn_t *backend = alloc_conn(bfd, NULL, ST_BACKEND_CONNECTING);
                    c->peer_fd = bfd;
                    backend->peer_fd = fd;
                    add_epoll(epfd, bfd, EPOLLOUT | EPOLLET);
                } else if (c->buf_len == sizeof(c->buf)) {
                    send_http_error_and_close(epfd, c, 400, "Bad Request", "Header too large or malformed");
                }
                break;
            }
            case ST_BACKEND_CONNECTING: {
                int err = 0;
                socklen_t len = sizeof(err);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
                    conn_t *client = fd_map[c->peer_fd];
                    if (client) {
                        send_http_error_and_close(epfd, client, 502, "Bad Gateway", "Backend connection failed");
                        client->peer_fd = -1; // Detach
                    }
                    c->peer_fd = -1;
                    close_and_cleanup_fd(epfd, fd);
                    break;
                }
                conn_t *client = fd_map[c->peer_fd];
                if (!client) {
                    close_and_cleanup_fd(epfd, fd);
                    break;
                }

                c->state = ST_PROXYING;
                client->state = ST_PROXYING;
                log_debug("backend: connected fd=%d <-> client fd=%d -> PROXYING\n", fd, client->fd);
                // Move any buffered client request bytes into the backend's own outgoing buffer
                if (client->buf_len > 0) {
                    conn_buf_compact(c);
                    size_t room = conn_buf_tail_room(c);
                    size_t to_copy = client->buf_len <= room ? client->buf_len : room;
                    if (to_copy > 0) {
                        memcpy(c->buf + c->buf_off + c->buf_len, client->buf, to_copy);
                        c->buf_len += to_copy;
                        // If we couldn't copy everything, move the remainder to the front of the client buffer.
                        if (to_copy < client->buf_len) {
                            memmove(client->buf, client->buf + to_copy, client->buf_len - to_copy);
                            client->buf_len -= to_copy;
                            client->buf_off = 0;
                        } else {
                            client->buf_len = 0;
                            client->buf_off = 0;
                        }
                        // Ensure backend will flush its queued bytes
                        mod_epoll(epfd, fd, EPOLLIN | EPOLLOUT | EPOLLET);
                        // Allow client to start reading backend response while we flush
                        mod_epoll(epfd, client->fd, EPOLLIN | EPOLLET);
                    } else {
                        // Should be rare (headers > buffer). Fall back to enabling EPOLLOUT so that
                        // proxying path can progress and close with error if needed.
                        mod_epoll(epfd, fd, EPOLLIN | EPOLLOUT | EPOLLET);
                        mod_epoll(epfd, client->fd, EPOLLIN | EPOLLET);
                    }
                } else {
                    // Nothing pending from client; begin full-duplex proxying
                    mod_epoll(epfd, fd, EPOLLIN | EPOLLET);
                    mod_epoll(epfd, client->fd, EPOLLIN | EPOLLET);
                }
                break;
            }
            case ST_PROXYING: {
                handle_proxy(epfd, c, ev);
                break;
            }
            case ST_SHUTTING_DOWN: {
                if (!c->ssl) {
                    // This case is for non-SSL peers, which we don't have, but for completeness:
                    shutdown(c->fd, SHUT_WR);
                    close_and_cleanup_fd(epfd, c->fd);
                    break;
                }

                int ret = SSL_shutdown(c->ssl);
                if (ret == 1) {
                    // SSL shutdown is complete.
                    log_debug("ssl: shutdown complete for fd=%d\n", c->fd);
                    close_and_cleanup_fd(epfd, c->fd);
                } else if (ret == 0) {
                    // Shutdown initiated, but we must wait for peer's close_notify.
                    log_debug("ssl: shutdown sent, waiting for peer on fd=%d\n", c->fd);
                    mod_epoll(epfd, c->fd, EPOLLIN | EPOLLET);
                } else {
                    int err = SSL_get_error(c->ssl, ret);
                    if (err == SSL_ERROR_WANT_READ) {
                        mod_epoll(epfd, c->fd, EPOLLIN | EPOLLET);
                    } else if (err == SSL_ERROR_WANT_WRITE) {
                        mod_epoll(epfd, c->fd, EPOLLOUT | EPOLLET);
                    } else {
                        log_debug("proxy: closing fd=%d due to SSL_shutdown error.\n", c->fd);
                        log_ssl_diag(c, "SSL_shutdown error", ret, err);
                        close_and_cleanup_fd(epfd, c->fd);
                    }
                }
                break;
            }
            }
        }
    }
    close(listen_fd_tls);
    close(listen_fd_plain);
    SSL_CTX_free(ctx);
    free_revpx();
}
