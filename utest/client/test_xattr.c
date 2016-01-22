#include "../test.h"
#include "../builders/build_file.h"
#include "../../src/alloc.h"
#include "../../src/cmd.h"
#include "../../src/fsops.h"
#include "../../src/client/extrameta.h"
#include "../../src/client/xattr.h"

#define BASE		"utest_xattr"

static void tear_down(void)
{
	fail_unless(recursive_delete(BASE)==0);
	alloc_check();
}

struct xattrdata
{
	int do_dir;
        const char *write;
        const char *expected_read;
};

static struct xattrdata x[] = {
	{
		// File - A single xattr
		0,
		"0000000Cuser.comment00000002cd",
		"X0000001E0000000Cuser.comment00000002cd" },
	{
		// File - A single xattr with empty value.
		0,
		"0000000Cuser.comment00000000",
		"X0000001C0000000Cuser.comment00000000" },
	{
		// Directory - A single xattr
		1,
		"0000000Cuser.comment00000002cd",
		"X0000001E0000000Cuser.comment00000002cd" },
	{
		// Directory - A single xattr with empty value.
		1,
		"0000000Cuser.comment00000000",
		"X0000001C0000000Cuser.comment00000000" },
	{
		// File - Multiple xattrs
		0,
		"0000000Cuser.comment00000002cd0000000Cuser.abcdefg00000002xy",
		"X0000003C0000000Cuser.comment00000002cd0000000Cuser.abcdefg00000002xy" },
	{
		// File - Multiple xattrs, an empty value
		0,
		"0000000Cuser.comment000000000000000Cuser.abcdefg00000002xy",
		"X0000003A0000000Cuser.comment000000000000000Cuser.abcdefg00000002xy" },
	{
		// Directory - Multiple xattrs
		1,
		"0000000Cuser.comment00000002cd0000000Cuser.abcdefg00000002xy",
		"X0000003C0000000Cuser.comment00000002cd0000000Cuser.abcdefg00000002xy" },
	{
		// Directory - Multiple xattrs, an empty value
		1,
		"0000000Cuser.comment000000000000000Cuser.abcdefg00000002xy",
		"X0000003A0000000Cuser.comment000000000000000Cuser.abcdefg00000002xy" },
};

static void test_xattr(struct xattrdata x)
{
	size_t rlen=0;
	char metasymbol=META_XATTR;
	char *retrieved=NULL;
	const char *path=NULL;
	const char *myfile=BASE "/myfile";
	char expected[256];

	fail_unless(recursive_delete(BASE)==0);
	build_file(myfile, NULL);

	if(x.do_dir) path=BASE;
	else path=myfile;

#if defined(HAVE_FREEBSD_OS) || defined(HAVE_NETBSD_OS)
	metasymbol=META_XATTR_BSD;
#endif
#if defined(HAVE_DARWIN_OS)
	metasymbol=META_XATTR_OSX;
#endif
#if defined(HAVE_LINUX_OS)
	metasymbol=META_XATTR;
#endif
	snprintf(expected, sizeof(expected), "%s", x.expected_read);
	expected[0]=metasymbol;

	fail_unless(has_xattr(path)==0);
	fail_unless(!set_xattr(
		NULL, // asfd
		path,
		x.write,
		strlen(x.write),
		metasymbol,
		NULL // cntr
	));
	fail_unless(!get_xattr(
		NULL, // asfd
		path,
		&retrieved,
		&rlen,
		NULL // cntr
	));
	fail_unless(rlen==strlen(expected));
	fail_unless(!memcmp(expected, retrieved, rlen));
	free_w(&retrieved);
	tear_down();
}

START_TEST(test_xattrs)
{
	FOREACH(x)
	{
		test_xattr(x[i]);
	}
}
END_TEST

Suite *suite_client_xattr(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("client_xattr");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_xattrs);
	suite_add_tcase(s, tc_core);

	return s;
}
