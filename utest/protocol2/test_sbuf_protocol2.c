#include "../test.h"
#include "../../src/alloc.h"
#include "../../src/protocol2/sbuf_protocol2.h"

START_TEST(test_sbuf_protocol2_alloc_error)
{
	alloc_errors=1;
	fail_unless(sbuf_protocol2_alloc()==NULL);
	alloc_check();
}
END_TEST

Suite *suite_protocol2_sbuf_protocol2(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("sbuf_protocol2");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_sbuf_protocol2_alloc_error);
	suite_add_tcase(s, tc_core);

	return s;
}
