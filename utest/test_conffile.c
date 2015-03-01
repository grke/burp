#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include "../src/alloc.h"
#include "../src/conf.h"

START_TEST(test_conffile)
{
	// FIX THIS
}
END_TEST

Suite *suite_conffile(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("conffile");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_conffile);
	suite_add_tcase(s, tc_core);

	return s;
}
