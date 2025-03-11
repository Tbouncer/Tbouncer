#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/epoll.h>

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
#define SHARED_FILE "/switch_file" 

void write_coordination_file(const char *data) {
    int fd = shm_open(SHARED_FILE, O_CREAT | O_RDWR, 0644);
    printf("write_coordination_file fd = %d\n", fd);
    if (fd < 0) {
        perror("Failed to open shared memory file");
        return;
    }

    size_t data_len = strlen(data);
    if (ftruncate(fd, data_len) < 0) {
        perror("Failed to set size of shared memory file");
        close(fd);
        shm_unlink(SHARED_FILE);
        return;
    }

    char *shared_mem = mmap(NULL, data_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (shared_mem == MAP_FAILED) {
        perror("Failed to map shared memory");
        close(fd);
        shm_unlink(SHARED_FILE);
        return;
    }

    memcpy(shared_mem, data, data_len);
    printf("Data written to shared memory: %s\n", shared_mem);

    munmap(shared_mem, data_len);
    close(fd);
}

void sample_handler(void *srv, void *context, int revents) {
    printf("Handler called! FD: %d, Events: %d\n", *(int *)context, revents);
}

fdevent_handler fdevent_get_handler(fdevents *ev, int fd) {
    if (ev->fdarray[fd] == NULL) {
        fprintf(stderr, "ERROR: FD %d not in fdarray\n", fd);
        exit(EXIT_FAILURE);
    }
    
    if (ev->fdarray[fd]->fd != fd) {
        fprintf(stderr, "ERROR: FD mismatch in fdarray\n");
        exit(EXIT_FAILURE);
    }
    if (fd < 0) {
        printf("attack successed\n");
        return NULL;
    }
    return ev->fdarray[fd]->handler;
}

int main() {
    int epfd = epoll_create1(0);
    if (epfd == -1) {
        perror("epoll_create1 failed");
        exit(EXIT_FAILURE);
    }

    // Initialize fdevents structure
    fdevents ev;
    ev.epoll_fd = epfd;
    ev.maxfds = 1024;
    ev.epoll_events = calloc(MAX_EVENTS, sizeof(struct epoll_event));
    ev.fdarray = calloc(ev.maxfds, sizeof(fdnode *));

    int pipefds[3][2]; // Create 3 pipes
    for (int i = 0; i < 3; ++i) {
        if (pipe(pipefds[i]) == -1) {
            perror("pipe failed");
            exit(EXIT_FAILURE);
        }

        // Add the read-end of each pipe to epoll
        struct epoll_event epev = {.events = EPOLLIN, .data.fd = pipefds[i][0]};
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipefds[i][0], &epev) == -1) {
            perror("epoll_ctl failed");
            exit(EXIT_FAILURE);
        }

        // Add handler for the pipe read-end
        fdnode *node = malloc(sizeof(fdnode));
        node->fd = pipefds[i][0];
        node->handler = sample_handler;
        ev.fdarray[pipefds[i][0]] = node;

        // Write data to the pipe to trigger an event
        char msg[32];
        snprintf(msg, sizeof(msg), "Message from pipe %d", i + 1);
        write(pipefds[i][1], msg, strlen(msg));
    }

    // Wait for events
    write_coordination_file("iago_attack_epoll_wait");
    sleep(3);
    int n = epoll_wait(ev.epoll_fd, ev.epoll_events, MAX_EVENTS, 5000);
    if (n == -1) {
        perror("epoll_wait failed");
        exit(EXIT_FAILURE);
    }
    write_coordination_file("0");

    for (int ndx = 0; ndx < n; ++ndx) {
        int fd = ev.epoll_events[ndx].data.fd;
        printf("Event on FD: %d\n", fd);

        fdevent_handler handler = fdevent_get_handler(&ev, fd);
        if (handler) {
            handler(NULL, &fd, ev.epoll_events[ndx].events);
        }
        else {
            goto Cleanup;
        }
    }
Cleanup:
    // Cleanup
    free(ev.epoll_events);
    for (int i = 0; i < ev.maxfds; ++i) {
        if (ev.fdarray[i]) free(ev.fdarray[i]);
    }
    free(ev.fdarray);

    for (int i = 0; i < 3; ++i) {
        close(pipefds[i][0]);
        close(pipefds[i][1]);
    }
    close(epfd);

    return 0;
}
