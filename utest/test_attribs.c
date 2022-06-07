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

void assert_sbuf(struct sbuf *a, struct sbuf *b)
{
	assert_iobuf(&a->path, &b->path);
	assert_iobuf(&a->attr, &b->attr);
	assert_iobuf(&a->link, &b->link);
	fail_unless(!memcmp(&a->statp, &b->statp, sizeof(struct stat)));
	fail_unless(a->winattr==b->winattr);
	fail_unless(a->compression==b->compression);
	fail_unless(a->encryption==b->encryption);
	assert_iobuf(&a->datapth, &b->datapth);
	assert_iobuf(&a->endfile, &b->endfile);
	assert_iobuf(&a->attr, &b->attr);
}

START_TEST(test_attribs)
{
	int i=0;
	prng_init(0);
	base64_init();
	for(i=0; i<10000; i++)
	{
		struct sbuf *encode;
		struct sbuf *decode;
		encode=build_attribs();
		decode=sbuf_alloc();

		fail_unless(!attribs_encode(encode));
		free_w(&decode->attr.buf);
		fail_unless((decode->attr.buf
			=strdup_w(encode->attr.buf, __func__))!=NULL);
		decode->attr.len=encode->attr.len;
		attribs_decode(decode);
		assert_sbuf(encode, decode);
		sbuf_free(&encode);
		sbuf_free(&decode);
	}
	tear_down();
}
END_TEST

START_TEST(test_attribs_bad_decode)
{
	const char *bad_attr="bad attr";
	struct sbuf *decode;

	base64_init();
	decode=sbuf_alloc();
	fail_unless((decode->attr.buf=strdup_w(bad_attr, __func__))!=NULL);
	decode->attr.len=strlen(bad_attr);
	attribs_decode(decode);
	sbuf_free(&decode);
	tear_down();
}
END_TEST

Suite *suite_attribs(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("attribs");

	tc_core=tcase_create("Core");

	tcase_set_timeout(tc_core, 20);

	tcase_add_test(tc_core, test_attribs);
	tcase_add_test(tc_core, test_attribs_bad_decode);
	suite_add_tcase(s, tc_core);

	return s;
}
