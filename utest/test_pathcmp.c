#include <check.h>
#include <stdlib.h>
#include "../src/pathcmp.h"

START_TEST(test_pathcmp)
{
	ck_assert_int_eq(pathcmp("/", "/"), 0);
	ck_assert_int_eq(pathcmp("a", "b"), -1);
	ck_assert_int_eq(pathcmp("b", "a"), 1);
}
END_TEST

Suite *pathcmp_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("pathcmp");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_pathcmp);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	int number_failed;
	Suite *s;
	SRunner *sr;

	s=pathcmp_suite();
	sr=srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return number_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
