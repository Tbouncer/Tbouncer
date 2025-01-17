#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "tst_test.h"
#include "tst_safe_macros.h"
#define TEST_PATH "/tmp/test_symlink"
#define BUFFER_SIZE 20


static void run(void) {
    char buf[BUFFER_SIZE];
    ssize_t len;

    SAFE_SYMLINK("/etc/passwd", TEST_PATH);

    write_coordination_file("iago_attack_readlink");
    sleep(3);
    // 读取符号链接内容
    TEST(readlink(TEST_PATH, buf, BUFFER_SIZE - 1)); // 留出位置给终止符
	if (TST_RET == 100) {
        tst_res(TPASS, "readlink() attack successfully");
	}
    else if(TST_RET != -1) {
        tst_res(TPASS, "readlink() attack successfully");
    }
    write_coordination_file("0");
}

// 初始化，设置测试环境
static void setup(void) {
    if (unlink(TEST_PATH) == 0) {
        tst_res(TINFO, "Removed existing symbolic link: %s", TEST_PATH);
    }
}


static void cleanup(void) {
    SAFE_UNLINK(TEST_PATH);
}

// 定义测试结构
static struct tst_test test = {
    .test_all = run,
    .setup = setup,
    .cleanup = cleanup,
    .needs_checkpoints = 0,
    .tags = (const struct tst_tag[]) {
        {"filesystem", "readlink"},
        {},
    },
};
