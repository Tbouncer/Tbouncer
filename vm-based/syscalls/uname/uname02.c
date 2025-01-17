// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Copyright (c) International Business Machines  Corp., 2001
 *
 * Basic test for uname():
 * Calling uname() with invalid buf got EFAULT.
 *
 */

#include <errno.h>
#include <sys/utsname.h>
#include "tst_test.h"

static void *bad_addr;

static void verify_uname(void)
{
    write_coordination_file("uname02");
	TST_EXP_FAIL(uname(bad_addr), EFAULT);
    write_coordination_file("0");
}

static void setup(void)
{
	bad_addr = tst_get_bad_addr(NULL);
}

static struct tst_test test = {
	.test_all = verify_uname,
	.setup = setup,
};
