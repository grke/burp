#include <check.h>
#include <stdlib.h>
#include "../src/cmd.h"
#include "test.h"

START_TEST(test_cmd)
{
	enum cmd cmd;
	for(int i=0; i<256; i++)
	{
		int expected_is_link=0;
		int expected_is_endfile=0;
		int expected_is_filedata=0;
		int expected_is_encrypted=0;
		int expected_is_vssdata=0;
		int expected_is_metadata=0;
		int expected_is_estimatable=0;
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
		  || cmd==CMD_EFS_FILE)
			expected_is_filedata=1;
		if(cmd==CMD_VSS
		  || cmd==CMD_ENC_VSS
		  || cmd==CMD_VSS_T
		  || cmd==CMD_ENC_VSS_T)
			expected_is_vssdata=1;
		if (cmd==CMD_ENC_FILE
		  || cmd==CMD_ENC_METADATA
		  || cmd==CMD_ENC_VSS
		  || cmd==CMD_ENC_VSS_T
		  || cmd==CMD_EFS_FILE)
			expected_is_encrypted=1;
		if ( cmd==CMD_METADATA
		  || cmd==CMD_ENC_METADATA
		  || cmd==CMD_VSS
		  || cmd==CMD_VSS_T
		  || cmd==CMD_ENC_VSS
		  || cmd==CMD_ENC_VSS_T)
			expected_is_metadata=1;
		if(cmd==CMD_FILE
		  || cmd==CMD_ENC_FILE
		  || cmd==CMD_EFS_FILE)
			expected_is_estimatable=1;

		fail_unless(cmd_is_link(cmd)==expected_is_link);
		fail_unless(cmd_is_endfile(cmd)==expected_is_endfile);
		fail_unless(cmd_is_filedata(cmd)==expected_is_filedata);
		fail_unless(cmd_is_vssdata(cmd)==expected_is_vssdata);
		fail_unless(cmd_is_encrypted(cmd)==expected_is_encrypted);
		fail_unless(cmd_is_metadata(cmd)==expected_is_metadata);
		fail_unless(cmd_is_estimatable(cmd)==expected_is_estimatable);
	}
}
END_TEST

START_TEST(test_cmd_print_all)
{
	// Just for code coverage.
#ifndef HAVE_WIN32
	close(1); // Close stdout, to keep test output clean.
#endif
	cmd_print_all();
}
END_TEST

Suite *suite_cmd(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("cmd");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_cmd);
	tcase_add_test(tc_core, test_cmd_print_all);
	suite_add_tcase(s, tc_core);

	return s;
}
