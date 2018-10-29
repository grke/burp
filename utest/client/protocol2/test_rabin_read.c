#include "../../test.h"
#include "../../builders/build_file.h"
#include "../../../src/alloc.h"
#include "../../../src/cmd.h"
#include "../../../src/fsops.h"
#include "../../../src/client/extrameta.h"
#include "../../../src/client/protocol2/rabin_read.h"
#include "../../../src/client/xattr.h"

#define BASE		"utest_client_protocol2_rabin_read"

#ifdef HAVE_XATTR

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
		// Directory - Multiple xattrs
		1,
		"0000000Cuser.comment00000002cd0000000Cuser.abcdefg00000002xy",
		"X0000003C0000000Cuser.comment00000002cd0000000Cuser.abcdefg00000002xy" },
	{
		// Directory - Multiple xattrs, different ordering.
		1,
		"0000000Cuser.abcdefg00000002xy0000000Cuser.comment00000002cd",
		"X0000003C0000000Cuser.comment00000002cd0000000Cuser.abcdefg00000002xy" },
};

static void assert_bfd_mode(struct sbuf *sb, enum bf_mode mode)
{
	fail_unless(sb->protocol2->bfd.mode==mode);
}

static void do_test_rabin_read(struct xattrdata x)
{
	size_t rlen=0;
	char metasymbol=META_XATTR;
	char *path=NULL;
	const char *myfile=BASE "/myfile";
	char expected[256];
	struct conf **confs=NULL;
	struct sbuf *sb=NULL;
	char buf[5];
	char retrieved[256];
	size_t bytes=0;

	fail_unless(recursive_delete(BASE)==0);
	build_file(myfile, NULL);

	if(x.do_dir)
		fail_unless((path=strdup_w(BASE, __func__))!=NULL);
	else
		fail_unless((path=strdup_w(myfile, __func__))!=NULL);
	fail_unless((sb=sbuf_alloc(PROTO_2))!=NULL);
	iobuf_from_str(&sb->path, CMD_METADATA, path);

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

	fail_unless(has_xattr(sb->path.buf)==0);
	fail_unless(!set_xattr(
		NULL, // asfd
		sb->path.buf,
		x.write,
		strlen(x.write),
		metasymbol,
		NULL // cntr
	));

	fail_unless((confs=confs_alloc())!=NULL);
	fail_unless(!confs_init(confs));

	assert_bfd_mode(sb, BF_CLOSED);
	fail_unless(rabin_open_file(
		sb,
		NULL, // asfd
		NULL, // cntr
		confs
	)==1);
	assert_bfd_mode(sb, BF_READ);

	rlen=0;
	while((bytes=rabin_read(sb, buf, sizeof(buf))))
	{
		snprintf(retrieved+rlen, bytes+1, "%s", buf);
		rlen+=bytes;
	}

	assert_bfd_mode(sb, BF_READ);

	fail_unless(!rabin_close_file(
		sb,
		NULL // asfd
	));
	assert_bfd_mode(sb, BF_CLOSED);

	assert_xattr(expected, retrieved, rlen);

	confs_free(&confs);
	sbuf_free(&sb);
	tear_down();
}

START_TEST(test_rabin_read)
{
	FOREACH(x)
	{
		do_test_rabin_read(x[i]);
	}
}
END_TEST

Suite *suite_client_protocol2_rabin_read(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("client_protocol2_rabin_read");

	if(!fs_supports_xattr())
		return s;

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_rabin_read);

	suite_add_tcase(s, tc_core);

	return s;
}

#endif
