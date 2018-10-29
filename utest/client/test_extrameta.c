#include "../test.h"
#include "../builders/build_file.h"
#include "../../src/alloc.h"
#include "../../src/cmd.h"
#include "../../src/fsops.h"
#include "../../src/client/extrameta.h"
#include "../../src/client/xattr.h"

#ifdef HAVE_ACL
#ifdef HAVE_XATTR

#define BASE		"utest_extrameta"

static void tear_down(void)
{
	fail_unless(recursive_delete(BASE)==0);
	alloc_check();
}

struct extrametadata
{
	int do_dir;
        const char *extrameta;
};

static struct extrametadata x[] = {
	{
		// File - A single extrameta
		0,
#ifdef HAVE_FREEBSD_OS
		"B0000001E0000000Cuser.comment00000002cd"
#else
		"X0000001E0000000Cuser.comment00000002cd"
#endif
	},
#ifndef HAVE_DARWIN_OS
	{
		// File - An access acl.
		0,
#ifdef HAVE_FREEBSD_OS
		"A0000003Cuser::rwx\nuser:%s:rwx\ngroup::rwx\nmask::rwx\nother::r--\n"
#else
		"A00000026u::rwx,u:1001:rwx,g::rwx,m::rwx,o::r--"
#endif
	},
	{
		// Directory - A default acl.
		1,
#ifdef HAVE_FREEBSD_OS
		"D00000020user::rwx\ngroup::rwx\nother::r-x\n"
#else
		"D00000014u::rwx,g::rwx,o::r-x"
#endif
	},
	{
		// File - A single extrameta and a single access acl.
		0,
#ifdef HAVE_FREEBSD_OS
		"A0000003Cuser::rwx\nuser:%s:rwx\ngroup::rwx\nmask::rwx\nother::r--\n"
		"B0000001E0000000Cuser.comment00000002cd"
#else
		"A00000026u::rwx,u:1001:rwx,g::rwx,m::rwx,o::r--"
		"X0000001E0000000Cuser.comment00000002cd"
#endif
	},
#endif
};

static void test_extrameta(struct extrametadata x)
{
	size_t rlen=0;
	char *retrieved=NULL;
	const char *path=NULL;
	const char *myfile=BASE "/myfile";
	char expected[256];
	enum cmd cmd;
	struct passwd *passwd=NULL;

	fail_unless(recursive_delete(BASE)==0);
	build_file(myfile, NULL);

	if(x.do_dir)
	{
		cmd=CMD_DIRECTORY;
		path=BASE;
	}
	else
	{
		cmd=CMD_FILE;
		path=myfile;
	}

	if(strstr(x.extrameta, "%s"))
		fail_unless((passwd=getpwuid(1001))!=NULL);
	snprintf(expected, sizeof(expected), x.extrameta,
		passwd?passwd->pw_name:"");

	fail_unless(has_extrameta(path, cmd,
		1, // enable_acl
		1  // enable_xattr
	)==0);

	fail_unless(!set_extrameta(
		NULL, // asfd
#ifdef HAVE_WIN32
		NULL, // bfd
#endif
		path,
		expected,
		strlen(expected),
		NULL // cntr
	));
	fail_unless(!get_extrameta(
		NULL, // asfd
#ifdef HAVE_WIN32
		NULL, // bfd
#endif
		path,
		x.do_dir,
		&retrieved,
		&rlen,
		NULL // cntr
	));
	fail_unless(rlen==strlen(expected));

	fail_unless(!memcmp(expected, retrieved, rlen));

	free_w(&retrieved);
	tear_down();
}

START_TEST(test_extrametas)
{
	FOREACH(x)
	{
		test_extrameta(x[i]);
	}
}
END_TEST

Suite *suite_client_extrameta(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("client_extrameta");

	if(!fs_supports_xattr())
		return s;

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_extrametas);

	suite_add_tcase(s, tc_core);

	return s;
}

#endif
#endif
