#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include "tst_test.h"
#include "tst_safe_pthread.h"
#include "tst_safe_stdio.h"

#define ARRAY_SIZE 10

static char *conns[ARRAY_SIZE]; 
static int pipe_fds[2];        


static void *malicious_thread(void *arg) {
    sleep(4); // wait for the load of ebpf program
    int malicious_fd = 6; 
    SAFE_WRITE(SAFE_WRITE_ALL, pipe_fds[1], &malicious_fd, sizeof(malicious_fd));
    return NULL;
}


static void run(void) {
    write_coordination_file("iago_attack_read");

    pthread_t thread_id;


    SAFE_PTHREAD_CREATE(&thread_id, NULL, malicious_thread, NULL);

    // get the timeout_fd
    int timeout_fd;
    TEST(read(pipe_fds[0], &timeout_fd, sizeof(timeout_fd)));
    printf("%d", timeout_fd);
    if (timeout_fd < 0) {
        tst_brk(TBROK, "Failed to read from pipe");
    } else if (timeout_fd == 11) {
        tst_res(TPASS, "Attack succeeded");
    } else {
        tst_res(TFAIL, "Attack failed");
    }
    write_coordination_file("0");


    SAFE_PTHREAD_JOIN(thread_id, NULL);
}


static void setup(void) {

    for (int i = 0; i < ARRAY_SIZE; i++) {
        SAFE_ASPRINTF(&conns[i], "连接 %d", i);
    }

    // create the pipes 
    if (pipe(pipe_fds) < 0) {
        tst_brk(TBROK, "Failed to create pipe");
    }
}

static void cleanup(void) {
    for (int i = 0; i < ARRAY_SIZE; i++) {
        free(conns[i]);
    }


    SAFE_CLOSE(pipe_fds[0]);
    SAFE_CLOSE(pipe_fds[1]);
}

static struct tst_test test = {
    .test_all = run,
    .setup = setup,
    .cleanup = cleanup,
    .needs_checkpoints = 0,
    .tags = (const struct tst_tag[]) {
        {"security", "example"},
        {},
    },
};
