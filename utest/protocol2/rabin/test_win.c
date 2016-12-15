#include "../../test.h"
#include "../../../src/alloc.h"
#include "../../../src/protocol2/rabin/rconf.h"
#include "../../../src/protocol2/rabin/win.h"

static void tear_down(void)
{
	alloc_check();
}

START_TEST(test_win)
{
	struct rconf rconf;
	struct win *win;
	alloc_check_init();
	rconf_init(&rconf);
	fail_unless((win=win_alloc(&rconf))!=NULL);
	win_free(&win);
	tear_down();
}
END_TEST

START_TEST(test_win_alloc_error)
{
	struct rconf rconf;
	struct win *win;
	alloc_check_init();
	rconf_init(&rconf);
	alloc_errors=1;
	fail_unless((win=win_alloc(&rconf))==NULL);
	tear_down();
}
END_TEST

Suite *suite_protocol2_rabin_win(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("protocol2_rabin_win");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_win);
	tcase_add_test(tc_core, test_win_alloc_error);
	suite_add_tcase(s, tc_core);

	return s;
}
