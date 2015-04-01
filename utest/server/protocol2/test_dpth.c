#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "../../test.h"
#include "../../../src/alloc.h"
#include "../../../src/server/protocol2/dpth.h"

static const char *lockpath="utest_dpth";

START_TEST(test_server_protocol2_dpth)
{
	struct dpth *dpth;
	fail_unless((dpth=dpth_alloc(lockpath))!=NULL);
	dpth_free(&dpth);
	fail_unless(free_count==alloc_count);
}
END_TEST

Suite *suite_server_protocol2_dpth(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_protocol2_dpth");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_server_protocol2_dpth);
	suite_add_tcase(s, tc_core);

	return s;
}
