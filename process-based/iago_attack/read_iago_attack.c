#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/mman.h>
#define ARRAY_SIZE 10

char *conns[ARRAY_SIZE];

int pipe_fds[2];
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


void conn_close_idle(const char *conn) {
    if (conn) {
        printf("close conn: %s\n", conn);
    } else {
        printf("attach successfully\n");
        exit(1);
    }
}

void *another_thread(void *arg) {
    sleep(1); 
    int malicious_fd =  6; 
    write(pipe_fds[1], &malicious_fd, sizeof(malicious_fd));
    return NULL;
}

int main() {
    pthread_t thread_id;

    for (int i = 0; i < ARRAY_SIZE; i++) {
        asprintf(&conns[i], "conn: %d", i);
    }

    if (pipe(pipe_fds) < 0) {
        perror("failed to create the pipe");
        return 1;
    }

    pthread_create(&thread_id, NULL, another_thread, NULL);

    int timeout_fd;
    printf("%d\n", pipe_fds[0]);
    write_coordination_file("iago_attack_read");
    sleep(3);
    ssize_t ret = read(pipe_fds[0], &timeout_fd, sizeof(timeout_fd));
    write_coordination_file("0");
    sleep(3);
    if (ret < 0) {
        perror("read failed");
        return 1;
    }

    printf("读取到 timeout_fd: %d\n", timeout_fd);
    if (timeout_fd == 11) {
        printf("attack success\n");
    }
    else {
        printf("attack failed\n");
    }

    pthread_join(thread_id, NULL);
    for (int i = 0; i < ARRAY_SIZE; i++) {
        free(conns[i]);
    }
    close(pipe_fds[0]);
    close(pipe_fds[1]);

    return 0;
}
