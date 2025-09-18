#ifndef _EP_H
#define _EP_H

#ifndef __APPLE__
#include <sys/epoll.h>
#else
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>

// Map epoll constants to kqueue equivalents
#define EPOLLIN 0x001
#define EPOLLOUT 0x004
#define EPOLLERR 0x008
#define EPOLLHUP 0x010
#define EPOLLET 0x020 // just a dummy flag, EV_CLEAR handles edge-triggered

#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

struct epoll_event {
    uint32_t events; // EPOLLIN, EPOLLOUT, etc.
    union {
        void *ptr;
        int fd;
        uint32_t u32;
        uint64_t u64;
    } data;
};

static inline int epoll_create1(int flags) {
    (void)flags;
    return kqueue();
}

static inline int epoll_ctl(int kq, int op, int fd, struct epoll_event *ev) {
    struct kevent kev[2];
    int n = 0;

    if (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) {
        if (ev->events & EPOLLIN) {
            EV_SET(&kev[n++], fd, EVFILT_READ, EV_ADD | EV_ENABLE | EV_CLEAR, 0, 0, NULL);
        }
        if (ev->events & EPOLLOUT) {
            EV_SET(&kev[n++], fd, EVFILT_WRITE, EV_ADD | EV_ENABLE | EV_CLEAR, 0, 0, NULL);
        }
    } else if (op == EPOLL_CTL_DEL) {
        EV_SET(&kev[n++], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        EV_SET(&kev[n++], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
    }

    return kevent(kq, kev, n, NULL, 0, NULL);
}

static inline int epoll_wait(int kq, struct epoll_event *evs, int maxevents, int timeout) {
    struct kevent kev[maxevents];
    struct timespec ts, *pts = NULL;

    if (timeout >= 0) {
        ts.tv_sec = timeout / 1000;
        ts.tv_nsec = (timeout % 1000) * 1000000;
        pts = &ts;
    }

    int n = kevent(kq, NULL, 0, kev, maxevents, pts);
    if (n <= 0) return n;

    for (int i = 0; i < n; i++) {
        evs[i].data.fd = (int)kev[i].ident;
        evs[i].events = 0;

        if (kev[i].filter == EVFILT_READ) evs[i].events |= EPOLLIN;
        if (kev[i].filter == EVFILT_WRITE) evs[i].events |= EPOLLOUT;
        if (kev[i].flags & EV_ERROR) evs[i].events |= EPOLLERR;
        if (kev[i].flags & EV_EOF) evs[i].events |= EPOLLHUP;
    }

    return n;
}
#endif // __APPLE__

#endif // _EP_H
