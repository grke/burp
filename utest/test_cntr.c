#include "test.h"
#include "../src/alloc.h"
#include "../src/cntr.h"

static void do_test_extract_client_pid_bno(char *buf,
	const char *expected_cname, int expected_pid, int expected_bno)
{
	int bno=0;
	int pid=-1;
	char b[32]="";
	char *cname=NULL;
	snprintf(b, sizeof(b), "%s", buf);
	fail_unless(!extract_client_pid_bno(b, &cname, &pid, &bno));
	fail_unless(!strcmp(cname, expected_cname));
	fail_unless(pid==expected_pid);
	fail_unless(pid==expected_bno);
	free_w(&cname);
	alloc_check();
}

START_TEST(test_extract_client_pid_bno)
{
	do_test_extract_client_pid_bno("", "", -1, 0);
	do_test_extract_client_pid_bno("cliX.12345", "cliX", 12345, 0);
	do_test_extract_client_pid_bno("cliX.12345\tblah", "cliX", 12345, 0);
	do_test_extract_client_pid_bno("cliX", "cliX", -1, 0);
	do_test_extract_client_pid_bno("cliX.12345.11", "cliX", 12345, 11);
	do_test_extract_client_pid_bno("cliX.12345.11\t", "cliX", 12345, 11);
}
END_TEST

Suite *suite_cntr(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("cntr");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_extract_client_pid_bno);

	suite_add_tcase(s, tc_core);

	return s;
}
