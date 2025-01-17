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
#define TEST_PATH "/proc/self"
#define BUFFER_SIZE 20
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

int main() {
    char buf[BUFFER_SIZE];
    ssize_t len;

    printf("Symbolic link created: %s -> /etc_passwd\n", TEST_PATH);
    write_coordination_file("iago_attack_readlink");
    sleep(2);

    len = readlink(TEST_PATH, buf, BUFFER_SIZE - 1); 
    if (len == -1) {
        perror("readlink");

    }
    printf("len = %d\n", len);

    if (len >= BUFFER_SIZE) {
        write_coordination_file("0");
        printf("attack successed\n");
        return 0;
    }

    buf[len] = '\0';

    printf("Symbolic link content: %s\n", buf);
    write_coordination_file("0");

    return 0;
}
