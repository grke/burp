#include <check.h>
#include <stdlib.h>
#include "test.h"

#if defined(HAVE_WIN32)
#define main UtestMain
#endif
int main(int argc, char *argv[], char *envp[])
{
	int number_failed;
	SRunner *sr;
#ifdef HAVE_NCURSES
	int valgrind=0;

	for(char **env=envp; *env; env++)
	{
		if(strstr(*env, "valgrind"))
		{
			valgrind=1;
			break;
		}
	}
#endif

	sr=srunner_create(NULL);

	srunner_add_suite(sr, suite_alloc());
	srunner_add_suite(sr, suite_base64());
#ifdef HAVE_ACL
#ifndef HAVE_DARWIN_OS
	srunner_add_suite(sr, suite_client_acl());
#endif
#endif
	srunner_add_suite(sr, suite_client_auth());
#ifdef HAVE_ACL
	srunner_add_suite(sr, suite_client_extra_comms());
#ifdef HAVE_XATTR
	srunner_add_suite(sr, suite_client_extrameta());
#endif
#endif
	srunner_add_suite(sr, suite_client_monitor_lline());
#ifdef HAVE_XATTR
	srunner_add_suite(sr, suite_client_xattr());
#endif
	srunner_add_suite(sr, suite_cmd());
	srunner_add_suite(sr, suite_conf());
	srunner_add_suite(sr, suite_fzp());
	srunner_add_suite(sr, suite_hexmap());
	srunner_add_suite(sr, suite_pathcmp());
	srunner_add_suite(sr, suite_protocol1_handy());
	srunner_add_suite(sr, suite_protocol1_rs_buf());
	srunner_add_suite(sr, suite_slist());
	srunner_add_suite(sr, suite_times());

#ifndef HAVE_WIN32
	// These do not compile for Windows.
	srunner_add_suite(sr, suite_client_delete());
	srunner_add_suite(sr, suite_client_find());
#ifdef HAVE_NCURSES
	if(!valgrind)
	{
		// These tests are unstable with valgrind. I think it is a
		// race condition revealed by valgrind slowing things down.
		srunner_add_suite(sr, suite_client_monitor_status_client_ncurses());
	}
#endif
	srunner_add_suite(sr, suite_client_monitor_json_input());
	srunner_add_suite(sr, suite_lock());

	// These compile for Windows, but do not run correctly and the whole
	// utest process crashes out.
	srunner_add_suite(sr, suite_asfd());
	srunner_add_suite(sr, suite_client_monitor());
	srunner_add_suite(sr, suite_client_protocol1_backup_phase2());
	srunner_add_suite(sr, suite_client_restore());

	// These compile for Windows, but have an error.
	srunner_add_suite(sr, suite_attribs());
	srunner_add_suite(sr, suite_conffile());

	// These are server side only, so do not want to run them on Windows.
	srunner_add_suite(sr, suite_server_auth());
	srunner_add_suite(sr, suite_server_autoupgrade());
	srunner_add_suite(sr, suite_server_ca());
	srunner_add_suite(sr, suite_server_backup_phase3());
	srunner_add_suite(sr, suite_server_bu_get());
	srunner_add_suite(sr, suite_server_delete());
	srunner_add_suite(sr, suite_server_extra_comms());
	srunner_add_suite(sr, suite_server_list());
	srunner_add_suite(sr, suite_server_manio());
	srunner_add_suite(sr, suite_server_monitor_browse());
	srunner_add_suite(sr, suite_server_monitor_cache());
	srunner_add_suite(sr, suite_server_monitor_cstat());
	srunner_add_suite(sr, suite_server_monitor_json_output());
	srunner_add_suite(sr, suite_server_monitor_status_server());
	srunner_add_suite(sr, suite_server_protocol1_backup_phase2());
	srunner_add_suite(sr, suite_server_protocol1_backup_phase4());
	srunner_add_suite(sr, suite_server_protocol1_bedup());
	srunner_add_suite(sr, suite_server_protocol1_blocklen());
	srunner_add_suite(sr, suite_server_protocol1_dpth());
	srunner_add_suite(sr, suite_server_protocol1_fdirs());
	srunner_add_suite(sr, suite_server_protocol1_restore());
	srunner_add_suite(sr, suite_server_restore());
	srunner_add_suite(sr, suite_server_resume());
	srunner_add_suite(sr, suite_server_run_action());
	srunner_add_suite(sr, suite_server_sdirs());
	srunner_add_suite(sr, suite_server_timer());
#endif

	srunner_run_all(sr, CK_ENV);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return number_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
