#include "../test.h"
#include "../builders/build_file.h"
#include "../../src/alloc.h"
#include "../../src/cmd.h"
#include "../../src/fsops.h"
#include "../../src/client/extrameta.h"
#include "../../src/client/xattr.h"

#ifdef HAVE_XATTR

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
	{
		// Directory - Multiple xattrs, different ordering.
		// This is to test this test.
		1,
		"0000000Cuser.abcdefg00000002xy0000000Cuser.comment00000002cd",
		"X0000003C0000000Cuser.comment00000002cd0000000Cuser.abcdefg00000002xy" },
};

// Some operating systems return the xattrs in a different order, so we need
// to do some extra fiddling to check that each piece was included in the
// returned string.
void assert_xattr(const char *expected,
	const char *retrieved, size_t rlen)
{
	size_t r;
	char *retr=NULL;

	// First 9 bytes represent the length of the whole string.
	fail_unless(!memcmp(expected, retrieved, 9));

	retr=(char *)retrieved+9;
	r=rlen-9;
	while(r>0)
	{
		size_t e;
		uint32_t xlen=0;
		char *rval=NULL;
		char *expe=NULL;
		int found=0;

		fail_unless((rval=get_next_xattr_str(NULL,
			&retr, &r, NULL, &xlen, NULL))!=NULL);

		expe=(char *)expected+9;
		e=strlen(expected)-9;
		while(e>0)
		{
			char *eval=NULL;
			uint32_t elen=0;
			fail_unless((eval=get_next_xattr_str(NULL,
				&expe, &e, NULL, &elen, NULL))!=NULL);
			if(xlen==elen
			  && !memcmp(rval, eval, xlen))
			{
				found++;
				free_w(&eval);
				break;
			}
			free_w(&eval);
		}
		free_w(&rval);
		fail_unless(found==1);
	}
}

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

#if defined(HAVE_FREEBSD_OS) || \
    defined(HAVE_NETBSD_OS)
	metasymbol=META_XATTR_BSD;
#endif
#if defined(HAVE_LINUX_OS) || \
    defined(HAVE_DARWIN_OS)
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

	assert_xattr(expected, retrieved, rlen);

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

	if(!fs_supports_xattr())
		return s;

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_xattrs);

	suite_add_tcase(s, tc_core);

	return s;
}

#endif
