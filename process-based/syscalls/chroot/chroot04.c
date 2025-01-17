 // SPDX-License-Identifier: GPL-2.0-or-later
 /*
  *   Copyright (C) Bull S.A. 2001
  *   Copyright (c) International Business Machines  Corp., 2001
  *
  *   04/2002 Ported by Jacky Malcles
  */

/*\
 * [Description]
 *
 * Testcase to check that chroot sets errno to EACCES.
 *
 * As a non-root user attempt to perform chroot() to a directory that the user
 * does not have a search permission for. The chroot() call should fail with
 * EACESS.
 */

#include <stdio.h>
#include <pwd.h>
#include "tst_test.h"

#define TEST_TMPDIR	"chroot04_tmpdir"

static void verify_chroot(void)
{
    write_coordination_file("chroot04");
	TST_EXP_FAIL(chroot(TEST_TMPDIR), EACCES, "no search permission chroot()");
    write_coordination_file("0");
}

static void setup(void)
{
	struct passwd *ltpuser;

	SAFE_MKDIR(TEST_TMPDIR, 0222);

	ltpuser = SAFE_GETPWNAM("nobody");
	SAFE_SETEUID(ltpuser->pw_uid);
}

static struct tst_test test = {
	.setup = setup,
	.test_all = verify_chroot,
	.needs_root = 1,
	.needs_tmpdir = 1,
};
