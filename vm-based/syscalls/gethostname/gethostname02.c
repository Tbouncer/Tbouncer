// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2024 FUJITSU LIMITED. All Rights Reserved.
 * Author: Yang Xu <xuyang2018.jy@fujitsu.com>
 */

/*\
 * [Description]
 *
 * Verify that gethostname(2) fails with
 *
 * - ENAMETOOLONG when len is smaller than the actual size
 */

#include "tst_test.h"

static void verify_gethostname(void)
{
    write_coordination_file("gethostname02");
	char hostname[HOST_NAME_MAX];
	int real_length;

	SAFE_GETHOSTNAME(hostname, sizeof(hostname));
	real_length = strlen(hostname);

	TST_EXP_FAIL(gethostname(hostname, real_length - 1), ENAMETOOLONG,
		"len is smaller than the actual size");
    write_coordination_file("0");
}

static struct tst_test test = {
	.test_all = verify_gethostname,
};
