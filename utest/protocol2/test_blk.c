#include "../test.h"
#include "../../src/alloc.h"
#include "../../src/hexmap.h"
#include "../../src/iobuf.h"
#include "../../src/protocol2/blk.h"
#include "../../src/protocol2/rabin/rabin.h"

struct bdata
{
	int unchar;
	uint64_t fingerprint;
	const char *md5str;
	int expected_result;
};

static struct bdata b[] = {
	{ 243, 0x00000000000000F3, "6334c2ae05c2421c687f516772b817da", 1 },
	{ 243, 0x00000000000000F2, "6334c2ae05c2421c687f516772b817da", 0 },
	{ 243, 0x00000000000000F3, "6334c2ae05c2421c686f516772b817da", 0 },
};

START_TEST(test_protocol2_blk)
{
	struct blk *blk;
	alloc_check_init();
	hexmap_init();
	blks_generate_init();
	fail_unless((blk=blk_alloc_with_data(1))!=NULL);
	FOREACH(b)
	{
		char x=(unsigned char)b[i].unchar;
		blk->fingerprint=b[i].fingerprint;
		md5str_to_bytes(b[i].md5str, blk->md5sum);
		blk->length=1;
		memcpy(blk->data, &x, blk->length);
		fail_unless(blk_verify(blk->fingerprint, blk->md5sum,
			blk->data, blk->length)==b[i].expected_result);
	}
	blk_free(&blk);
	blks_generate_free();
	alloc_check();
}
END_TEST

START_TEST(test_protocol2_blk_length_errors)
{
	struct iobuf iobuf;
	struct blk blk;
	alloc_check_init();
	iobuf.len=0;
	fail_unless(blk_set_from_iobuf_sig_and_savepath(&blk, &iobuf)==-1);
	fail_unless(blk_set_from_iobuf_fingerprint(&blk, &iobuf)==-1);
	fail_unless(blk_set_from_iobuf_savepath(&blk, &iobuf)==-1);
	fail_unless(blk_set_from_iobuf_wrap_up(&blk, &iobuf)==-1);
	fail_unless(blk_set_from_iobuf_index_and_savepath(&blk, &iobuf)==-1);
	alloc_check();
}
END_TEST

START_TEST(test_protocol2_blk_alloc_error)
{
	alloc_check_init();
	alloc_errors=1;
	fail_unless(blk_alloc_with_data(1)==NULL);
	alloc_errors=2;
	fail_unless(blk_alloc_with_data(1)==NULL);
	alloc_check();
}
END_TEST

Suite *suite_protocol2_blk(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("protocol2_blk");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_protocol2_blk);
	tcase_add_test(tc_core, test_protocol2_blk_length_errors);
	tcase_add_test(tc_core, test_protocol2_blk_alloc_error);
	suite_add_tcase(s, tc_core);

	return s;
}
