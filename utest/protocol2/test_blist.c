#include "utest/test.h"
#include "utest/prng.h"
#include "utest/builders/build.h"
#include "burp.h"
#include "alloc.h"
#include "base64.h"
#include "hexmap.h"
#include "protocol2/blist.h"

#include <check.h>

static void tear_down(void)
{
	alloc_check();
}

START_TEST(test_protocol2_blist)
{
	struct blk *blk;
	struct blist *blist;
	base64_init();
	hexmap_init();
	blist=build_blist(1000);
	for(blk=blist->head; blk; blk=blk->next)
	{
		// Builder is currently only generating md5sums without
		// matching data, so it will not verify for now.
		// fail_unless(blk_verify(blk)==1);
	}
	blist_free(&blist);
	tear_down();
}
END_TEST

Suite *suite_protocol2_blist(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("protocol2_blist");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_protocol2_blist);
	suite_add_tcase(s, tc_core);

	return s;
}
