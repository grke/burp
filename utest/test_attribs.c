#include <check.h>
#include "../src/config.h"
#include "test.h"
#include "prng.h"
#include "../src/alloc.h"
#include "../src/attribs.h"
#include "../src/base64.h"
#include "../src/sbuf.h"

static void tear_down(void)
{
	alloc_check();
}

static void memcpy_a(void *dest, size_t s)
{
	static uint64_t u;
	u=prng_next64();
	memcpy(dest, &u, s);
}

static struct sbuf *sbuf_builder(enum protocol protocol)
{
	struct sbuf *sbuf;
	struct stat *statp;
	fail_unless((sbuf=sbuf_alloc_protocol(protocol))!=NULL);
	statp=&sbuf->statp;
	memcpy_a(&statp->st_dev, sizeof(statp->st_dev));
	memcpy_a(&statp->st_ino, sizeof(statp->st_ino));
	memcpy_a(&statp->st_mode, sizeof(statp->st_mode));
	memcpy_a(&statp->st_nlink, sizeof(statp->st_nlink));
	memcpy_a(&statp->st_uid, sizeof(statp->st_uid));
	memcpy_a(&statp->st_gid, sizeof(statp->st_gid));
	memcpy_a(&statp->st_rdev, sizeof(statp->st_rdev));
	memcpy_a(&statp->st_size, sizeof(statp->st_size));
	memcpy_a(&statp->st_blksize, sizeof(statp->st_blksize));
	memcpy_a(&statp->st_blocks, sizeof(statp->st_blocks));
	memcpy_a(&statp->st_atime, sizeof(statp->st_atime));
	memcpy_a(&statp->st_mtime, sizeof(statp->st_mtime));
	memcpy_a(&statp->st_ctime, sizeof(statp->st_ctime));
#ifdef HAVE_CHFLAGS
	memcpy_a(&statp->st_flags, sizeof(statp->st_flags));
#endif
	memcpy_a(&sbuf->winattr, sizeof(sbuf->winattr));
	memcpy_a(&sbuf->compression, sizeof(sbuf->compression));
	if(protocol==PROTO_2)
	{
		memcpy_a(&sbuf->protocol2->index,
			sizeof(sbuf->protocol2->index));
		memcpy_a(&sbuf->protocol2->encryption,
			sizeof(sbuf->protocol2->encryption));
	}
	return sbuf;
}

static void assert_attribs(struct sbuf *a, struct sbuf *b,
	enum protocol protocol)
{
	fail_unless(!memcmp(&a->statp, &b->statp, sizeof(struct stat)));
	fail_unless(a->winattr==b->winattr);
	fail_unless(a->compression==b->compression);
	if(protocol==PROTO_1)
		fail_unless(a->protocol1 && b->protocol1);
	else if(protocol==PROTO_2)
	{
		fail_unless(a->protocol2 && b->protocol2);
		fail_unless(a->protocol2->index==b->protocol2->index);
		fail_unless(a->protocol2->encryption==b->protocol2->encryption);
	}
}

static void test_attribs(enum protocol protocol)
{
	int i=0;
	prng_init(0);
	base64_init();
	for(i=0; i<10000; i++)
	{
		struct sbuf *encode;
		struct sbuf *decode;
		encode=sbuf_builder(protocol);
		decode=sbuf_alloc_protocol(protocol);

		fail_unless(!attribs_encode(encode));
		free_w(&decode->attr.buf);
		fail_unless((decode->attr.buf
			=strdup_w(encode->attr.buf, __func__))!=NULL);
		attribs_decode(decode);
		assert_attribs(encode, decode, protocol);
		sbuf_free(&encode);
		sbuf_free(&decode);
	}
	tear_down();
}

START_TEST(test_attribs_protocol1)
{
	test_attribs(PROTO_1);
}
END_TEST

START_TEST(test_attribs_protocol2)
{
	test_attribs(PROTO_2);
}
END_TEST

Suite *suite_attribs(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("attribs");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_attribs_protocol1);
	tcase_add_test(tc_core, test_attribs_protocol2);
	suite_add_tcase(s, tc_core);

	return s;
}
