#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include "test.h"
#include "../src/alloc.h"
#include "../src/conf.h"

static void check_default(struct conf **c, enum conf_opt o)
{
	switch(o)
	{
		case OPT_BURP_MODE:
			fail_unless(get_e_burp_mode(c[o])==BURP_MODE_UNSET);
			break;
		case OPT_LOCKFILE:
		case OPT_PIDFILE:
		case OPT_SSL_CERT_CA:
		case OPT_SSL_CERT:
		case OPT_SSL_KEY:
		case OPT_SSL_KEY_PASSWORD:
		case OPT_SSL_PEER_CN:
		case OPT_SSL_CIPHERS:
		case OPT_SSL_DHFILE:
		case OPT_CA_CONF:
		case OPT_CA_NAME:
		case OPT_CA_SERVER_NAME:
		case OPT_CA_BURP_CA:
		case OPT_CA_CSR_DIR:
		case OPT_CA_CRL:
		case OPT_PEER_VERSION:
		case OPT_CLIENT_LOCKDIR:
		case OPT_MONITOR_LOGFILE:
		case OPT_CNAME:
		case OPT_PASSWORD:
		case OPT_PASSWD:
		case OPT_SERVER:
		case OPT_ENCRYPTION_PASSWORD:
		case OPT_AUTOUPGRADE_OS:
		case OPT_AUTOUPGRADE_DIR:
		case OPT_BACKUP:
		case OPT_BACKUP2:
		case OPT_RESTOREPREFIX:
		case OPT_STRIP_FROM_PATH:
		case OPT_BROWSEFILE:
		case OPT_BROWSEDIR:
		case OPT_B_SCRIPT_PRE:
		case OPT_B_SCRIPT_POST:
		case OPT_R_SCRIPT_PRE:
		case OPT_R_SCRIPT_POST:
		case OPT_B_SCRIPT:
		case OPT_R_SCRIPT:
		case OPT_RESTORE_PATH:
		case OPT_ORIG_CLIENT:
		case OPT_CONNECT_CLIENT:
		case OPT_CONFFILE:
		case OPT_USER:
		case OPT_GROUP:
		case OPT_DIRECTORY:
		case OPT_TIMESTAMP_FORMAT:
		case OPT_CLIENTCONFDIR:
		case OPT_S_SCRIPT_PRE:
		case OPT_S_SCRIPT_POST:
		case OPT_MANUAL_DELETE:
		case OPT_S_SCRIPT:
		case OPT_TIMER_SCRIPT:
		case OPT_N_SUCCESS_SCRIPT:
		case OPT_N_FAILURE_SCRIPT:
		case OPT_DEDUP_GROUP:
		case OPT_VSS_DRIVES:
		case OPT_REGEX:
		case OPT_SUPER_CLIENT:
		case OPT_MONITOR_EXE:
		case OPT_SEED_SRC:
		case OPT_SEED_DST:
		case OPT_RESTORE_LIST:
		case OPT_ALLOW:
		case OPT_ALLOW_STATUS:
		case OPT_CLIENT_ALLOW:
			fail_unless(get_string(c[o])==NULL);
			break;
		case OPT_RATELIMIT:
			fail_unless(get_float(c[o])==0);
			break;
		case OPT_CLIENT_IS_WINDOWS:
		case OPT_RANDOMISE:
		case OPT_B_SCRIPT_POST_RUN_ON_FAIL:
		case OPT_R_SCRIPT_POST_RUN_ON_FAIL:
		case OPT_SEND_CLIENT_CNTR:
		case OPT_READALL:
		case OPT_BREAKPOINT:
		case OPT_SYSLOG:
		case OPT_PROGRESS_COUNTER:
		case OPT_MONITOR_BROWSE_CACHE:
		case OPT_S_SCRIPT_PRE_NOTIFY:
		case OPT_S_SCRIPT_POST_RUN_ON_FAIL:
		case OPT_S_SCRIPT_POST_NOTIFY:
		case OPT_S_SCRIPT_NOTIFY:
		case OPT_HARDLINKED_ARCHIVE:
		case OPT_N_SUCCESS_WARNINGS_ONLY:
		case OPT_N_SUCCESS_CHANGES_ONLY:
		case OPT_CROSS_ALL_FILESYSTEMS:
		case OPT_READ_ALL_FIFOS:
		case OPT_READ_ALL_BLOCKDEVS:
		case OPT_SPLIT_VSS:
		case OPT_STRIP_VSS:
		case OPT_ATIME:
		case OPT_SCAN_PROBLEM_RAISES_ERROR:
		case OPT_OVERWRITE:
		case OPT_CNAME_LOWERCASE:
		case OPT_STRIP:
		case OPT_MESSAGE:
		case OPT_CA_CRL_CHECK:
		case OPT_PORT_BACKUP:
		case OPT_PORT_RESTORE:
		case OPT_PORT_VERIFY:
		case OPT_PORT_LIST:
		case OPT_PORT_DELETE:
		case OPT_MAX_RESUME_ATTEMPTS:
		case OPT_FAIL_ON_WARNING:
		case OPT_SSL_VERIFY_PEER_EARLY:
		case OPT_FAILOVER_ON_BACKUP_ERROR:
		case OPT_BACKUP_FAILOVERS_LEFT:
		case OPT_N_FAILURE_BACKUP_WORKING_DELETION:
		case OPT_MAX_PARALLEL_BACKUPS:
		case OPT_TIMER_REPEAT_INTERVAL:
		case OPT_REGEX_CASE_INSENSITIVE:
			fail_unless(get_int(c[o])==0);
			break;
		case OPT_VSS_RESTORE:
			fail_unless(get_int(c[o])==VSS_RESTORE_ON);
			break;
		case OPT_DAEMON:
		case OPT_STDOUT:
		case OPT_FORK:
		case OPT_ENABLED:
		case OPT_DIRECTORY_TREE:
		case OPT_PASSWORD_CHECK:
		case OPT_LIBRSYNC:
		case OPT_VERSION_WARN:
		case OPT_PATH_LENGTH_WARN:
		case OPT_CNAME_FQDN:
		case OPT_CLIENT_CAN_DELETE:
		case OPT_CLIENT_CAN_DIFF:
		case OPT_CLIENT_CAN_FORCE_BACKUP:
		case OPT_CLIENT_CAN_LIST:
		case OPT_CLIENT_CAN_MONITOR:
		case OPT_CLIENT_CAN_RESTORE:
		case OPT_CLIENT_CAN_VERIFY:
		case OPT_SERVER_CAN_RESTORE:
		case OPT_SERVER_CAN_OVERRIDE_INCLUDES:
		case OPT_B_SCRIPT_RESERVED_ARGS:
		case OPT_R_SCRIPT_RESERVED_ARGS:
		case OPT_GLOB_AFTER_SCRIPT_PRE:
		case OPT_ACL:
		case OPT_XATTR:
		case OPT_N_FAILURE_BACKUP_FAILOVERS_LEFT:
			fail_unless(get_int(c[o])==1);
			break;
		case OPT_NETWORK_TIMEOUT:
			fail_unless(get_int(c[o])==60*60*2);
			break;
		case OPT_SSL_COMPRESSION:
			fail_unless(get_int(c[o])==5);
			break;
        	case OPT_COMPRESSION:
			fail_unless(get_int(c[o])==9);
			break;
		case OPT_MAX_STORAGE_SUBDIRS:
			fail_unless(get_int(c[o])==30000);
			break;
		case OPT_MAX_HARDLINKS:
			fail_unless(get_int(c[o])==10000);
			break;
		case OPT_UMASK:
			fail_unless(get_mode_t(c[o])==0022);
			break;
		case OPT_STARTDIR:
		case OPT_B_SCRIPT_PRE_ARG:
		case OPT_B_SCRIPT_POST_ARG:
		case OPT_R_SCRIPT_PRE_ARG:
		case OPT_R_SCRIPT_POST_ARG:
		case OPT_B_SCRIPT_ARG:
		case OPT_R_SCRIPT_ARG:
		case OPT_S_SCRIPT_PRE_ARG:
		case OPT_S_SCRIPT_POST_ARG:
		case OPT_S_SCRIPT_ARG:
		case OPT_TIMER_ARG:
		case OPT_N_SUCCESS_ARG:
		case OPT_N_FAILURE_ARG:
		case OPT_RESTORE_CLIENTS:
		case OPT_SUPER_CLIENTS:
		case OPT_KEEP:
		case OPT_INCEXCDIR:
		case OPT_INCLUDE:
		case OPT_EXCLUDE:
		case OPT_FSCHGDIR:
		case OPT_NOBACKUP:
		case OPT_INCEXT:
		case OPT_EXCEXT:
		case OPT_INCREG:
		case OPT_EXCREG:
		case OPT_INCLOGIC:
		case OPT_EXCLOGIC:
		case OPT_EXCFS:
		case OPT_INCFS:
		case OPT_EXCOM:
		case OPT_INCGLOB:
		case OPT_FIFOS:
		case OPT_BLOCKDEVS:
		case OPT_LABEL:
		case OPT_PORT:
		case OPT_STATUS_PORT:
		case OPT_LISTEN:
		case OPT_LISTEN_STATUS:
		case OPT_MAX_CHILDREN:
		case OPT_MAX_STATUS_CHILDREN:
		case OPT_SERVER_FAILOVER:
			fail_unless(get_strlist(c[o])==NULL);
			break;
		case OPT_PROTOCOL:
			fail_unless(get_e_protocol(c[o])==PROTO_AUTO);
			break;
		case OPT_HARD_QUOTA:
		case OPT_SOFT_QUOTA:
		case OPT_MIN_FILE_SIZE:
		case OPT_MAX_FILE_SIZE:
		case OPT_LIBRSYNC_MAX_SIZE:
			fail_unless(get_uint64_t(c[o])==0);
			break;
		case OPT_RBLK_MEMORY_MAX:
			fail_unless(get_uint64_t(c[o])==256*1024*1024);
			break;
		case OPT_SPARSE_SIZE_MAX:
			fail_unless(get_uint64_t(c[o])==256*1024*1024);
			break;
		case OPT_WORKING_DIR_RECOVERY_METHOD:
			fail_unless(get_e_recovery_method(c[o])==
				RECOVERY_METHOD_DELETE);
			break;
		case OPT_RSHASH:
			fail_unless(get_e_rshash(c[o])==RSHASH_UNSET);
			break;
		case OPT_CNTR:
			fail_unless(get_cntr(c)==NULL);
			break;
		case OPT_MAX:
			break;
		// No default, so we get compiler warnings if something was
		// missed.
	}
}

START_TEST(test_conf_defaults)
{
	int i=0;
	struct conf **confs=NULL;
	fail_unless((confs=confs_alloc())!=NULL);
	confs_init(confs);
	for(i=0; i<OPT_MAX; i++)
		check_default(confs, (enum conf_opt)i);
	confs_free(&confs);
	fail_unless(confs==NULL);
	alloc_check();
}
END_TEST

Suite *suite_conf(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("conf");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_conf_defaults);
	suite_add_tcase(s, tc_core);

	return s;
}
