#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "tst_test.h"
#include "tst_safe_macros.h"


struct cache_file {
    uint32_t nlibs;  
    char libs[0];    
};

#define VERIFY_PTR(ptr, cache_data_size) ((ptr) > (cache_data_size))

#define TEST_FILENAME "testfile"

static void *mapped_data = NULL;
static size_t mapped_size = 0;

static void setup(void) {
    const char *libs[] = {"lib1", "lib2", "lib3"};
    uint32_t nlibs = 3;
    size_t total_size = sizeof(uint32_t); 

    for (uint32_t i = 0; i < nlibs; i++) {
        total_size += strlen(libs[i]) + 1;
    }

    int fd = SAFE_OPEN(TEST_FILENAME, O_WRONLY | O_CREAT | O_TRUNC);

    SAFE_WRITE(SAFE_WRITE_ALL, fd, &nlibs, sizeof(nlibs)) != sizeof(nlibs);

    for (uint32_t i = 0; i < nlibs; i++) {
        size_t len = strlen(libs[i]) + 1;
        SAFE_WRITE(SAFE_WRITE_ALL, fd, libs[i], len) != (ssize_t)len;
    }

    SAFE_CLOSE(fd);
    tst_res(TINFO, "Test file '%s' created successfully", TEST_FILENAME);
}

static void run(void) {
    int fd = SAFE_OPEN(TEST_FILENAME, O_RDONLY);

    struct stat st;
    write_coordination_file("iago_attack_fstat");
    sleep(2);
    TEST(fstat(fd, &st));

    mapped_size = st.st_size;
    tst_res(TINFO, "File size: %zu", mapped_size);

    mapped_data = SAFE_MMAP(NULL, mapped_size, PROT_READ, MAP_PRIVATE, fd, 0);

    SAFE_CLOSE(fd);

    struct cache_file *cache = (struct cache_file *)mapped_data;
    void *cache_data = &cache->libs[cache->nlibs];
    uint32_t cache_data_size = (uint32_t)((const char *)mapped_data + mapped_size - (const char *)cache_data);

    tst_res(TINFO, "Cache data size: %u", cache_data_size);

    if (!VERIFY_PTR((uintptr_t)cache_data, cache_data_size)) {
        tst_res(TFAIL, "Pointer verification failed! Invalid access detected.");
        return;
    }

    if (cache_data_size > 50) {
        tst_res(TPASS, "the attack successed");
    } else {
        tst_res(TFAIL, "attack failed");
    }
    write_coordination_file("0");
}

static void cleanup(void) {
    if (mapped_data) {
        munmap(mapped_data, mapped_size);
    }

    SAFE_UNLINK(TEST_FILENAME);
}


static struct tst_test test = {
    .test_all = run,
    .setup = setup,
    .cleanup = cleanup,
    .tags = (const struct tst_tag[]) {
        {"filesystem", "mmap"},
        {"security", "pointer-verification"},
        {},
    },
};
