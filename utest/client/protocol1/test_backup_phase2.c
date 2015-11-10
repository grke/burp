#include "../../test.h"
#include "../../../src/client/protocol1/backup_phase2.h"

START_TEST(test_phase2)
{
	fail_unless(backup_phase2_client_protocol1(
		NULL, // asfd
		NULL, // confs
		0 // resume
	)==-1);
	alloc_check();
}
END_TEST

Suite *suite_client_protocol1_backup_phase2(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("client_protocol1_backup_phase2");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_phase2);
	suite_add_tcase(s, tc_core);

	return s;
}
