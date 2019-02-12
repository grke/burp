#include "test.h"
#include "prng.h"
#include "../src/alloc.h"
#include "../src/attribs.h"
#include "../src/base64.h"
#include "../src/sbuf.h"
#include "builders/build.h"

static void tear_down(void)
{
	alloc_check();
}

void assert_iobuf(struct iobuf *a, struct iobuf *b)
{
	fail_unless(!iobuf_pathcmp(a, b));
	fail_unless(a->cmd==b->cmd);
	fail_unless(a->len==b->len);
}

void assert_sbuf(struct sbuf *a, struct sbuf *b, enum protocol protocol)
{
	assert_iobuf(&a->path, &b->path);
	assert_iobuf(&a->attr, &b->attr);
	assert_iobuf(&a->link, &b->link);
	fail_unless(!memcmp(&a->statp, &b->statp, sizeof(struct stat)));
	fail_unless(a->winattr==b->winattr);
	fail_unless(a->compression==b->compression);
	fail_unless(a->encryption==b->encryption);
	if(protocol==PROTO_1)
	{
		fail_unless(a->protocol1 && b->protocol1);
		assert_iobuf(&a->protocol1->datapth, &b->protocol1->datapth);
		assert_iobuf(&a->endfile, &b->endfile);
		assert_iobuf(&a->attr, &b->attr);
	}
	else if(protocol==PROTO_2)
	{
		fail_unless(a->protocol2 && b->protocol2);
		// In protocol2, the first component (index) gets stripped off
		// of the attributes, so it is not preserved.
		//fail_unless(a->protocol2->index==b->protocol2->index);
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
		encode=build_attribs(protocol);
		decode=sbuf_alloc(protocol);

		fail_unless(!attribs_encode(encode));
		free_w(&decode->attr.buf);
		fail_unless((decode->attr.buf
			=strdup_w(encode->attr.buf, __func__))!=NULL);
		decode->attr.len=encode->attr.len;
		attribs_decode(decode);
		assert_sbuf(encode, decode, protocol);
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

static void test_attribs_bad_decode(enum protocol protocol)
{
	const char *bad_attr="bad attr";
	struct sbuf *decode;

	base64_init();
	decode=sbuf_alloc(protocol);
	fail_unless((decode->attr.buf=strdup_w(bad_attr, __func__))!=NULL);
	decode->attr.len=strlen(bad_attr);
	attribs_decode(decode);
	sbuf_free(&decode);
	tear_down();
}

START_TEST(test_attribs_bad_decode_protocol1)
{
	test_attribs_bad_decode(PROTO_1);
}
END_TEST

START_TEST(test_attribs_bad_decode_protocol2)
{
	test_attribs_bad_decode(PROTO_2);
}
END_TEST

Suite *suite_attribs(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("attribs");

	tc_core=tcase_create("Core");

	tcase_set_timeout(tc_core, 10);

	tcase_add_test(tc_core, test_attribs_protocol1);
	tcase_add_test(tc_core, test_attribs_protocol2);
	tcase_add_test(tc_core, test_attribs_bad_decode_protocol1);
	tcase_add_test(tc_core, test_attribs_bad_decode_protocol2);
	suite_add_tcase(s, tc_core);

	return s;
}
