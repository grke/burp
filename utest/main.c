#include <check.h>
#include <stdlib.h>
#include "test.h"

int main(void)
{
	int number_failed;
	SRunner *sr;

	sr=srunner_create(NULL);
	srunner_add_suite(sr, suite_alloc());
	srunner_add_suite(sr, suite_base64());
	srunner_add_suite(sr, suite_cmd());
	srunner_add_suite(sr, suite_conf());
	srunner_add_suite(sr, suite_conffile());
	srunner_add_suite(sr, suite_fzp());
	srunner_add_suite(sr, suite_hexmap());
	srunner_add_suite(sr, suite_pathcmp());
	srunner_add_suite(sr, suite_server_sdirs());
	srunner_add_suite(sr, suite_server_protocol1_dpth());
	srunner_add_suite(sr, suite_server_protocol1_fdirs());
	// Do these last, as they have slight delays.
	srunner_add_suite(sr, suite_server_protocol2_dpth());
	srunner_add_suite(sr, suite_lock());

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return number_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
