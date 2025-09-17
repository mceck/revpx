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
    if (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) {
        // For MOD, emulate by disabling/removing filters not present, then adding requested ones.
        // Delete READ if not requested
        if (!(ev && (ev->events & EPOLLIN))) {
            struct kevent kev;
            EV_SET(&kev, (uintptr_t)fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
            if (kevent(epfd, &kev, 1, NULL, 0, NULL) == -1 && errno != ENOENT) return -1;
        }
        // Delete WRITE if not requested
        if (!(ev && (ev->events & EPOLLOUT))) {
            struct kevent kev;
            EV_SET(&kev, (uintptr_t)fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
            if (kevent(epfd, &kev, 1, NULL, 0, NULL) == -1 && errno != ENOENT) return -1;
        }

        struct kevent changes[2];
        int nchanges = 0;
        uint16_t base_flags = EV_ADD | EV_CLEAR;
        if (ev && (ev->events & EPOLLIN)) {
            EV_SET(&changes[nchanges++], (uintptr_t)fd, EVFILT_READ, base_flags, 0, 0, NULL);
        }
        if (ev && (ev->events & EPOLLOUT)) {
            EV_SET(&changes[nchanges++], (uintptr_t)fd, EVFILT_WRITE, base_flags, 0, 0, NULL);
        }
        if (nchanges == 0) return 0; // nothing to add
        return kevent(epfd, changes, nchanges, NULL, 0, NULL);
    } else if (op == EPOLL_CTL_DEL) {
        struct kevent kev;
        EV_SET(&kev, (uintptr_t)fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        if (kevent(epfd, &kev, 1, NULL, 0, NULL) == -1 && errno != ENOENT) return -1;
        EV_SET(&kev, (uintptr_t)fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
        if (kevent(epfd, &kev, 1, NULL, 0, NULL) == -1 && errno != ENOENT) return -1;
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
            if (evlist[i].filter == EVFILT_READ) mask |= EPOLLIN;
            if (evlist[i].filter == EVFILT_WRITE) mask |= EPOLLOUT;
            if (evlist[i].flags & EV_ERROR) mask |= EPOLLERR;
            if (evlist[i].flags & EV_EOF) mask |= EPOLLHUP;
            events[i].events = mask;
        }
    }

    free(evlist);
    return n;
}
#endif // __APPLE__