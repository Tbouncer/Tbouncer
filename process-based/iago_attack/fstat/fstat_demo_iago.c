#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

struct cache_file {
    uint32_t nlibs;  
    char libs[0];    
};
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
#define VERIFY_PTR(ptr, cache_data_size) ((ptr) > (cache_data_size))

int main() {

    const char *filename = "testfile";
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return EXIT_FAILURE;
    }

    struct stat st;
    write_coordination_file("iago_attack_fstat");
    sleep(5);
    if (fstat(fd, &st) < 0) {

        perror("fstat");
        close(fd);
        return EXIT_FAILURE;
    }
    write_coordination_file("0");
    size_t sizep = st.st_size;
    printf("File size reported by fstat: %zu\n", sizep);

    void *result = mmap(NULL, sizep, PROT_READ, MAP_PRIVATE, fd, 0);
    if (result == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return EXIT_FAILURE;
    }

    close(fd);

    struct cache_file *cache = (struct cache_file *)result;

    void *cache_data = &cache->libs[cache->nlibs];
    uint32_t cache_data_size = (uint32_t)((const char *)cache + sizep - (const char *)cache_data);

    printf("cache_data_size: %u\n", cache_data_size);

    if (!VERIFY_PTR((uintptr_t)cache_data, cache_data_size)) {
        fprintf(stderr, "Pointer verification failed! Invalid access detected.\n");
        munmap(result, sizep);
        return EXIT_FAILURE;
    }
    if (cache_data_size > 50) {
        printf("attack success\n");
        return 0;
    }
    printf("Accessing cache_data: %p\n", cache_data);
    munmap(result, sizep);

    return EXIT_SUCCESS;
}
