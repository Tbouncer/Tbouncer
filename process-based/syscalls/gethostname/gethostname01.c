// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2000 Silicon Graphics, Inc.  All Rights Reserved.
 * Copyright (c) 2023 SUSE LLC Ioannis Bonatakis <ybonatakis@suse.com>
 */

/*\
 * [Description]
 *
 * Test is checking that gethostname() succeeds.
 */

#include "tst_test.h"
#include <stdlib.h>

static void run(void)
{
    write_coordination_file("gethostname01");
	char hname[100];

	TST_EXP_PASS(gethostname(hname, sizeof(hname)));
    write_coordination_file("0");
}

static struct tst_test test = {
	.test_all = run
};
