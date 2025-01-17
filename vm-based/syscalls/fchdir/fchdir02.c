// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (c) International Business Machines  Corp., 2001
 */

/*
 * DESCRIPTION
 *	fchdir02 - try to cd into a bad directory (bad fd).
 */

#include "tst_test.h"

static void verify_fchdir(void)
{
    write_coordination_file("fchdir02");
	const int bad_fd = -5;

	TST_EXP_FAIL(fchdir(bad_fd), EBADF);
    write_coordination_file("0");
}

static struct tst_test test = {
	.test_all = verify_fchdir,
};
