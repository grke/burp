#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "test.h"
#include "../src/sbuf.h"

START_TEST(test_sbuf)
{
	printf("in sbuf test\n");
}
END_TEST

Suite *suite_sbuf(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("sbuf");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_sbuf);
	suite_add_tcase(s, tc_core);

	return s;
}
