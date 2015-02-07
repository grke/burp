#include <check.h>
#include <stdlib.h>
#include "../src/cmd.h"

START_TEST(test_cmd)
{
	enum cmd cmd;
	for(int i=0; i<256; i++)
	{
		int expected_is_link=0;
		int expected_is_endfile=0;
		int expected_is_filedata=0;
		cmd=(enum cmd)i;
		if(cmd==CMD_SOFT_LINK
		  || cmd==CMD_HARD_LINK)
			expected_is_link=1;
		if(cmd==CMD_END_FILE)
			expected_is_endfile=1;
		if(cmd==CMD_FILE
		  || cmd==CMD_ENC_FILE
		  || cmd==CMD_METADATA
		  || cmd==CMD_ENC_METADATA
		  || cmd==CMD_VSS
		  || cmd==CMD_ENC_VSS
		  || cmd==CMD_VSS_T
		  || cmd==CMD_ENC_VSS_T
		  || cmd==CMD_EFS_FILE)
			expected_is_filedata=1;

		ck_assert_int_eq(cmd_is_link(cmd), expected_is_link);
		ck_assert_int_eq(cmd_is_endfile(cmd), expected_is_endfile);
		ck_assert_int_eq(cmd_is_filedata(cmd), expected_is_filedata);
	}
}
END_TEST

Suite *cmd_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("cmd");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_cmd);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	int number_failed;
	Suite *s;
	SRunner *sr;

	s=cmd_suite();
	sr=srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return number_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
