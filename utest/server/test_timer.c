#include "../test.h"
#include "../../src/server/timer.h"

START_TEST(test_timer)
{
}
END_TEST

Suite *suite_server_timer(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_timer");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_timer);

	suite_add_tcase(s, tc_core);

	return s;
}
