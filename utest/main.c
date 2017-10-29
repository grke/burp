#include <check.h>
#include <stdlib.h>
#include "test.h"

#if defined(HAVE_WIN32)
#define main UtestMain
#endif
int main(void)
{
	int number_failed;
	SRunner *sr;

	sr=srunner_create(NULL);

	srunner_add_suite(sr, suite_client_protocol1_backup_phase2());

	srunner_run_all(sr, CK_ENV);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return number_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
