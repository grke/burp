#include "utest/test.h"
#include "burp.h"
#include "alloc.h"
#include "protocol2/rabin/rconf.h"

#include <check.h>

static void tear_down(void)
{
	alloc_check();
}

START_TEST(test_rconf_init)
{
	struct rconf rconf;
	rconf_init(&rconf);

	fail_unless(rconf.win_size >= rconf.win_min);
	fail_unless(rconf.win_size <= rconf.win_max);
	fail_unless(rconf.blk_min  <  rconf.blk_max);
	fail_unless(rconf.blk_avg  >= rconf.blk_min);
	fail_unless(rconf.blk_avg  <= rconf.blk_max);

	tear_down();
}
END_TEST

Suite *suite_protocol2_rabin_rconf(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("protocol2_rabin_rconf");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_rconf_init);
	suite_add_tcase(s, tc_core);

	return s;
}
