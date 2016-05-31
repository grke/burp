#include <check.h>
#include <stdlib.h>
#include "test.h"

int main(void)
{
	int number_failed;
	SRunner *sr;

	sr=srunner_create(NULL);

	srunner_add_suite(sr, suite_alloc());
	srunner_add_suite(sr, suite_asfd());
	srunner_add_suite(sr, suite_attribs());
	srunner_add_suite(sr, suite_base64());
#ifdef HAVE_ACL
#ifndef HAVE_DARWIN_OS
	srunner_add_suite(sr, suite_client_acl());
#endif
#endif
	srunner_add_suite(sr, suite_client_auth());
#ifdef HAVE_ACL
#ifdef HAVE_XATTR
	srunner_add_suite(sr, suite_client_extrameta());
#endif
#endif
	srunner_add_suite(sr, suite_client_find());
	srunner_add_suite(sr, suite_client_monitor());
	srunner_add_suite(sr, suite_client_monitor_json_input());
	srunner_add_suite(sr, suite_client_monitor_lline());
	srunner_add_suite(sr, suite_client_monitor_status_client_ncurses());
	srunner_add_suite(sr, suite_client_protocol1_backup_phase2());
	srunner_add_suite(sr, suite_client_protocol2_backup_phase2());
	srunner_add_suite(sr, suite_client_protocol2_rabin_read());
	srunner_add_suite(sr, suite_client_restore());
#ifdef HAVE_XATTR
	srunner_add_suite(sr, suite_client_xattr());
#endif
	srunner_add_suite(sr, suite_cmd());
	srunner_add_suite(sr, suite_conf());
	srunner_add_suite(sr, suite_conffile());
	srunner_add_suite(sr, suite_fzp());
	srunner_add_suite(sr, suite_hexmap());
	srunner_add_suite(sr, suite_lock());
	srunner_add_suite(sr, suite_pathcmp());
	srunner_add_suite(sr, suite_protocol1_handy());
	srunner_add_suite(sr, suite_protocol1_rs_buf());
	srunner_add_suite(sr, suite_protocol2_blist());
	srunner_add_suite(sr, suite_protocol2_blk());
	srunner_add_suite(sr, suite_protocol2_rabin_rabin());
	srunner_add_suite(sr, suite_protocol2_rabin_rconf());
	srunner_add_suite(sr, suite_protocol2_rabin_win());
	srunner_add_suite(sr, suite_protocol2_sbuf_protocol2());
	srunner_add_suite(sr, suite_server_auth());
	srunner_add_suite(sr, suite_server_ca());
	srunner_add_suite(sr, suite_server_backup_phase3());
	srunner_add_suite(sr, suite_server_bu_get());
	srunner_add_suite(sr, suite_server_delete());
	srunner_add_suite(sr, suite_server_list());
	srunner_add_suite(sr, suite_server_manio());
	srunner_add_suite(sr, suite_server_monitor_browse());
	srunner_add_suite(sr, suite_server_monitor_cstat());
	srunner_add_suite(sr, suite_server_monitor_json_output());
	srunner_add_suite(sr, suite_server_protocol1_backup_phase2());
	srunner_add_suite(sr, suite_server_protocol1_bedup());
	srunner_add_suite(sr, suite_server_protocol1_blocklen());
	srunner_add_suite(sr, suite_server_protocol1_dpth());
	srunner_add_suite(sr, suite_server_protocol1_fdirs());
	srunner_add_suite(sr, suite_server_protocol2_backup_phase2());
	srunner_add_suite(sr, suite_server_protocol2_backup_phase4());
	srunner_add_suite(sr, suite_server_protocol2_champ_chooser_champ_chooser());
	srunner_add_suite(sr,
		suite_server_protocol2_champ_chooser_champ_server());
	srunner_add_suite(sr, suite_server_protocol2_champ_chooser_dindex());
	srunner_add_suite(sr, suite_server_protocol2_champ_chooser_hash());
	srunner_add_suite(sr, suite_server_protocol2_champ_chooser_scores());
	srunner_add_suite(sr, suite_server_protocol2_champ_chooser_sparse());
	srunner_add_suite(sr, suite_server_protocol2_dpth());
	srunner_add_suite(sr, suite_server_restore());
	srunner_add_suite(sr, suite_server_resume());
	srunner_add_suite(sr, suite_server_run_action());
	srunner_add_suite(sr, suite_server_sdirs());
	srunner_add_suite(sr, suite_slist());

	srunner_run_all(sr, CK_ENV);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return number_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
