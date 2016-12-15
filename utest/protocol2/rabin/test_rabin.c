#include "../../test.h"
#include "../../../src/alloc.h"
#include "../../../src/hexmap.h"
#include "../../../src/protocol2/blk.h"
#include "../../../src/protocol2/rabin/rabin.h"

struct bdata
{
	int unchar;
	uint64_t fingerprint;
	int expected_result;
};

// There was once a problem with signed chars instead of unsigned chars in the
// blk_read() code. It resulted in the fingerprints being too high.
static struct bdata b[] = {
	{ 255, 0x00000000000000FF, 1 },
	{ 243, 0x00000000000000F3, 1 },
	{ 243, 0x00000000000000F2, 0 },
	{  10, 0x000000000000000A, 1 },
	{   0, 0x0000000000000000, 1 },
	{   0, 0x000000000000000A, 0 },
};

START_TEST(test_rabin_blk_verify_fingerprint)
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
		blk->length=1;
		memcpy(blk->data, &x, blk->length);
		fail_unless(blk_verify_fingerprint(blk->fingerprint,
			blk->data, blk->length)==b[i].expected_result);
	}
	blk_free(&blk);
	blks_generate_free();
	alloc_check();
}
END_TEST

Suite *suite_protocol2_rabin_rabin(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("protocol2_rabin_rabin");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_rabin_blk_verify_fingerprint);
	suite_add_tcase(s, tc_core);

	return s;
}
