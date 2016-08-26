#include "../test.h"
#include "../builders/build_file.h"
#include "../../src/alloc.h"
#include "../../src/cmd.h"
#include "../../src/fsops.h"
#include "../../src/client/extrameta.h"
#include "../../src/client/acl.h"

#ifdef HAVE_ACL
#ifndef HAVE_DARWIN_OS

#define BASE		"utest_acl"

static void tear_down(void)
{
	fail_unless(recursive_delete(BASE)==0);
	alloc_check();
}

struct acldata
{
	int do_dir;
        const char *write_access;
        const char *write_default;
        const char *expected_read;
};

static struct acldata x[] = {
	{
		// File - An access acl.
		0,
		"u::rwx,u:1001:rwx,g::rwx,m::rwx,o::r--",
		NULL,
#ifdef HAVE_FREEBSD_OS
		"A0000003Cuser::rwx\nuser:%s:rwx\ngroup::rwx\nmask::rwx\nother::r--\n"
#else
		"A00000026u::rwx,u:1001:rwx,g::rwx,m::rwx,o::r--"
#endif
	},
	{
		// Directory - An access acl.
		1,
		"u::rwx,u:1001:rwx,g::rwx,m::rwx,o::r--",
		NULL,
#ifdef HAVE_FREEBSD_OS
		"A0000003Cuser::rwx\nuser:%s:rwx\ngroup::rwx\nmask::rwx\nother::r--\n"
#else
		"A00000026u::rwx,u:1001:rwx,g::rwx,m::rwx,o::r--"
#endif
	},
	{
		// Directory - A default acl.
		1,
		NULL,
		"u::rwx,g::rwx,o::r-x",
#ifdef HAVE_FREEBSD_OS
		"D00000020user::rwx\ngroup::rwx\nother::r-x\n"
#else
		"D00000014u::rwx,g::rwx,o::r-x"
#endif
	},
	{
		// Directory - An access acl and a default acl.
		1,
		"u::rwx,u:1001:rwx,g::rwx,m::rwx,o::r--",
		"u::rwx,g::rwx,o::r-x",
#ifdef HAVE_FREEBSD_OS
		"A0000003Cuser::rwx\nuser:%s:rwx\ngroup::rwx\nmask::rwx\nother::r--\nD00000020user::rwx\ngroup::rwx\nother::r-x\n"
#else
		"A00000026u::rwx,u:1001:rwx,g::rwx,m::rwx,o::r--D00000014u::rwx,g::rwx,o::r-x"
#endif
	},
};

static void test_acl(struct acldata x)
{
	size_t rlen=0;
	char *retrieved=NULL;
	const char *path=NULL;
	const char *myfile=BASE "/myfile";
	enum cmd cmd;
	char expected[256];
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

	fail_unless(has_acl(path, cmd)==0);

	if(x.write_access)
		fail_unless(!set_acl(
			NULL, // asfd
			path,
			x.write_access,
			META_ACCESS_ACL,
			NULL // cntr
		));
	if(x.write_default)
		fail_unless(!set_acl(
			NULL, // asfd
			path,
			x.write_default,
			META_DEFAULT_ACL,
			NULL // cntr
		));

	if(x.write_access || x.write_default)
		fail_unless(has_acl(path, cmd)==1);

	fail_unless(!get_acl(
		NULL, // asfd
		path,
		x.do_dir,
		&retrieved,
		&rlen,
		NULL // cntr
	));

	if(strstr(x.expected_read, "%s"))
		fail_unless((passwd=getpwuid(1001))!=NULL);

	snprintf(expected, sizeof(expected), x.expected_read,
		passwd?passwd->pw_name:"");

	fail_unless(rlen==strlen(expected));
	fail_unless(!memcmp(expected, retrieved, rlen));

	free_w(&retrieved);
	tear_down();
}

START_TEST(test_acls)
{
	FOREACH(x)
	{
		test_acl(x[i]);
	}
}
END_TEST

START_TEST(test_set_default_acl_on_file)
{
	const char *path=NULL;
	const char *myfile=BASE "/myfile";
	enum cmd cmd;
	const char *acl="u::rwx,g::rwx,o::r-x";

	fail_unless(recursive_delete(BASE)==0);
	build_file(myfile, NULL);

	cmd=CMD_FILE;
	path=myfile;

	fail_unless(has_acl(path, cmd)==0);

	fail_unless(set_acl(
		NULL, // asfd
		path,
		acl,
		META_DEFAULT_ACL,
		NULL // cntr
	)==-1);
	tear_down();
}
END_TEST

START_TEST(test_set_acl_bad_type)
{
	const char *acl="u::rwx,g::rwx,o::r-x";
	fail_unless(set_acl(
		NULL, // asfd
		BASE,
		acl,
		CMD_ERROR,
		NULL // cntr
	)==-1);
	tear_down();
}
END_TEST

START_TEST(test_set_acl_acl_from_text_fail)
{
	const char *acl="blahblahblah";
	fail_unless(set_acl(
		NULL, // asfd
		BASE,
		acl,
		META_DEFAULT_ACL,
		NULL // cntr
	)==-1);
	tear_down();
}
END_TEST

Suite *suite_client_acl(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("client_acl");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_acls);
	tcase_add_test(tc_core, test_set_default_acl_on_file);
	tcase_add_test(tc_core, test_set_acl_bad_type);
	tcase_add_test(tc_core, test_set_acl_acl_from_text_fail);

	suite_add_tcase(s, tc_core);

	return s;
}

#endif
#endif
