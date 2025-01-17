#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>
#include "tst_test.h"
#include <poll.h>
#include "tst_epoll.h"

#define MAX_EVENTS 10

typedef void (*fdevent_handler)(void *, void *, int);

typedef struct {
    int fd;
    fdevent_handler handler;
} fdnode;

typedef struct {
    int epoll_fd;
    struct epoll_event *epoll_events;
    fdnode **fdarray;
    int maxfds;
} fdevents;


void sample_handler(void *srv, void *context, int revents) {
    tst_res(TINFO, "Handler called! FD: %d, Events: %d", *(int *)context, revents);
}

fdevent_handler fdevent_get_handler(fdevents *ev, int fd) {
    if (ev->fdarray[fd] == NULL) {
        tst_brk(TBROK, "FD %d not found in fdarray", fd);
    }
    if (ev->fdarray[fd]->fd != fd) {
        tst_brk(TBROK, "FD mismatch detected in fdarray");
    }
    if (fd < 0) {
        tst_res(TPASS, "Invalid FD detected, potential attack succeeded.");
        return NULL;
    }
    return ev->fdarray[fd]->handler;
}

static fdevents ev;
static int pipefds[3][2];

static void setup(void) {
    ev.maxfds = 1024;
    ev.epoll_fd = SAFE_EPOLL_CREATE1(0);

    ev.epoll_events = SAFE_CALLOC(MAX_EVENTS, sizeof(struct epoll_event));
    ev.fdarray = SAFE_CALLOC(ev.maxfds, sizeof(fdnode *));

    for (int i = 0; i < 3; ++i) {
        SAFE_PIPE(pipefds[i]);


        struct epoll_event epev = {.events = EPOLLIN, .data.fd = pipefds[i][0]};
        SAFE_EPOLL_CTL(ev.epoll_fd, EPOLL_CTL_ADD, pipefds[i][0], &epev);


        fdnode *node = SAFE_MALLOC(sizeof(fdnode));

        node->fd = pipefds[i][0];
        node->handler = sample_handler;
        ev.fdarray[pipefds[i][0]] = node;
    
        char msg[32];
        snprintf(msg, sizeof(msg), "Message from pipe %d", i + 1);
        SAFE_WRITE(0, pipefds[i][1], msg, strlen(msg));
    }
}

static void run(void) {
    write_coordination_file("iago_attack_epoll_wait");
    sleep(2);
    int n = epoll_wait(ev.epoll_fd, ev.epoll_events, MAX_EVENTS, 5000);
    if (n == -1) {
        tst_brk(TBROK | TTERRNO, "epoll_wait failed");
    }

    tst_res(TINFO, "Number of events received: %d", n);

    for (int ndx = 0; ndx < n; ++ndx) {
        int fd = ev.epoll_events[ndx].data.fd;
        tst_res(TINFO, "Event received on FD: %d", fd);

        fdevent_handler handler = fdevent_get_handler(&ev, fd);
        if (handler) {
            handler(NULL, &fd, ev.epoll_events[ndx].events);
        } else if(fd == -14){
            break;
        } else {
            tst_res(TFAIL, "Handler not found for FD %d", fd);
            break;            
        }
    }
    write_coordination_file("0");
}

static void cleanup(void) {
    free(ev.epoll_events);
    for (int i = 0; i < ev.maxfds; ++i) {
        if (ev.fdarray[i]) free(ev.fdarray[i]);
    }
    free(ev.fdarray);

    for (int i = 0; i < 3; ++i) {
        SAFE_CLOSE(pipefds[i][0]);
        SAFE_CLOSE(pipefds[i][1]);
    }
    SAFE_CLOSE(ev.epoll_fd);
}

static struct tst_test test = {
    .test_all = run,
    .setup = setup,
    .cleanup = cleanup,
    .tags = (const struct tst_tag[]) {
        {"epoll", "pipe"},
        {"handler", "fdarray"},
        {},
    },
};
