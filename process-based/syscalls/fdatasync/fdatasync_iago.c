// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2019 Linaro Limited. All rights reserved.
 * Author: Sumit Garg <sumit.garg@linaro.org>
 */

/*
 * fdatasync03
 *
 * It basically tests fdatasync() to sync test file data having large dirty
 * file pages to block device. Also, it tests all supported filesystems on a
 * test block device.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include "tst_test.h"

#define MNTPOINT	"mnt_point"
#define FNAME		MNTPOINT"/test"
#define FILE_SIZE_MB	32
#define FILE_SIZE	(FILE_SIZE_MB * TST_MB)
#define MODE		0644

static void verify_fdatasync(void)
{

	int fd;
	unsigned long written;

	fd = SAFE_OPEN(FNAME, O_RDWR|O_CREAT, MODE);

	tst_dev_sync(fd);
	tst_dev_bytes_written(tst_device->dev);

	tst_fill_fd(fd, 0, TST_MB, FILE_SIZE_MB);
    write_coordination_file("mutation_fdatasync");
	TEST(fdatasync(fd));
	write_coordination_file("mutation_done");
	if (TST_RET == 4099)
		write_result_file("fdatasync\n");
	if (TST_RET)
		tst_brk(TFAIL | TTERRNO, "fdatasync(fd) failed");

	written = tst_dev_bytes_written(tst_device->dev);

	SAFE_CLOSE(fd);

	if (written >= FILE_SIZE)
		tst_res(TPASS, "Test file data synced to device");
	else
		tst_res(TFAIL, "Synced %li, expected %i", written, FILE_SIZE);

}

static struct tst_test test = {
	.needs_root = 1,
	.mount_device = 1,
	.all_filesystems = 1,
	.mntpoint = MNTPOINT,
	.test_all = verify_fdatasync,
	.skip_filesystems = (const char *[]) {
		"tmpfs",
		NULL
	}
};
