#ifndef __APPLE__
#include <sys/epoll.h>
#else
#include <stdlib.h>
#include <sys/event.h>
#include <sys/time.h>
#endif

#ifdef __APPLE__
// Minimal epoll compatibility layer for macOS using kqueue
#ifndef EPOLLIN
#define EPOLLIN 0x001
#endif
#ifndef EPOLLOUT
#define EPOLLOUT 0x004
#endif
#ifndef EPOLLERR
#define EPOLLERR 0x008
#endif
#ifndef EPOLLHUP
#define EPOLLHUP 0x010
#endif
// EPOLLET is edge-triggered; with kqueue we emulate via EV_CLEAR. Flag value is unused.
#ifndef EPOLLET
#define EPOLLET 0x000
#endif

#ifndef EPOLL_CTL_ADD
#define EPOLL_CTL_ADD 1
#endif
#ifndef EPOLL_CTL_DEL
#define EPOLL_CTL_DEL 2
#endif
#ifndef EPOLL_CTL_MOD
#define EPOLL_CTL_MOD 3
#endif

struct epoll_event {
    uint32_t events;
    union {
        int fd;
        void *ptr;
        uint64_t u64;
    } data;
};

static inline int epoll_create1(int flags) {
    (void)flags;
    return kqueue();
}

static inline int epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev) {
    struct kevent changes[2];
    int nchanges = 0;
    uint16_t base_flags = EV_ADD; // Use level-triggered semantics

    if (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) {
        if (ev && (ev->events & EPOLLIN)) {
            EV_SET(&changes[nchanges++], (uintptr_t)fd, EVFILT_READ, base_flags, 0, 0, NULL);
        } else if (op == EPOLL_CTL_MOD) {
            EV_SET(&changes[nchanges++], (uintptr_t)fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        }

        if (ev && (ev->events & EPOLLOUT)) {
            EV_SET(&changes[nchanges++], (uintptr_t)fd, EVFILT_WRITE, base_flags, 0, 0, NULL);
        } else if (op == EPOLL_CTL_MOD) {
            EV_SET(&changes[nchanges++], (uintptr_t)fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
        }

        if (nchanges > 0) {
            return kevent(epfd, changes, nchanges, NULL, 0, NULL);
        }
        return 0;
    } else if (op == EPOLL_CTL_DEL) {
        EV_SET(&changes[0], (uintptr_t)fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        EV_SET(&changes[1], (uintptr_t)fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
        // kevent with EV_DELETE will return 0 if filter is successfully removed,
        // or -1 with ENOENT if it does not exist. In either case, we can
        // ignore the return value for a simple DEL operation.
        (void)kevent(epfd, changes, 2, NULL, 0, NULL);
        return 0;
    } else {
        errno = EINVAL;
        return -1;
    }
}

static inline int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
    if (maxevents <= 0) {
        errno = EINVAL;
        return -1;
    }

    struct timespec ts, *tsp = NULL;
    if (timeout >= 0) {
        ts.tv_sec = timeout / 1000;
        ts.tv_nsec = (timeout % 1000) * 1000000;
        tsp = &ts;
    }

    // Allocate evlist dynamically to respect maxevents
    struct kevent *evlist = (struct kevent *)calloc((size_t)maxevents, sizeof(struct kevent));
    if (!evlist) {
        errno = ENOMEM;
        return -1;
    }

    int n = kevent(epfd, NULL, 0, evlist, maxevents, tsp);
    if (n > 0) {
        for (int i = 0; i < n; i++) {
            events[i].data.fd = (int)evlist[i].ident;
            uint32_t mask = 0;
            if (evlist[i].filter == EVFILT_READ) {
                mask |= EPOLLIN;
                if (evlist[i].flags & EV_EOF) {
                    // Read side reached EOF: signal HUP but allow draining with EPOLLIN
                    mask |= EPOLLHUP;
                }
            }
            if (evlist[i].filter == EVFILT_WRITE) {
                mask |= EPOLLOUT;
                // Do NOT map EV_EOF on write filter to EPOLLHUP; it only means peer won't read more
                // and will be surfaced as write error (EPIPE) on write attempt.
            }
            if (evlist[i].flags & EV_ERROR) mask |= EPOLLERR;
            events[i].events = mask;
        }
    }

    free(evlist);
    return n;
}
#endif // __APPLE__