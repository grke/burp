/* Experiment to start the sanitising of conf.c, so that we can eventually do
   things like dumping the current configuration. */

#include <stdio.h>
#include <malloc.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "conf_nextgen.h"
#include "strlist.h"

static char *get_string(struct conf *conf)
{
	assert(conf->conf_type==CT_STRING);
	return conf->data.s;
}

static int get_int(struct conf *conf)
{
	assert(conf->conf_type==CT_UINT);
	return conf->data.i;
}

static float get_float(struct conf *conf)
{
	assert(conf->conf_type==CT_FLOAT);
	return conf->data.f;
}

static void set_int(struct conf *conf, unsigned int i)
{
	assert(conf->conf_type==CT_UINT);
	conf->data.i=i;
}

static char *set_string(struct conf *conf, const char *s)
{
	assert(conf->conf_type==CT_STRING);
	if(conf->data.s) free(conf->data.s);
	if(s) conf->data.s=strdup(s);
	return conf->data.s;
}

static void set_strlist(struct conf *conf, struct strlist *s)
{
	assert(conf->conf_type==CT_STRLIST);
	if(conf->data.sl) strlists_free(&conf->data.sl);
	conf->data.sl=s;
}

static void set_float(struct conf *conf, float f)
{
	assert(conf->conf_type==CT_FLOAT);
	conf->data.f=f;
}

static void set_e_burp_mode(struct conf *conf, enum burp_mode bm)
{
	assert(conf->conf_type==CT_E_BURP_MODE);
	conf->data.burp_mode=bm;
}

static void set_e_protocol(struct conf *conf, enum protocol p)
{
	assert(conf->conf_type==CT_E_PROTOCOL);
	conf->data.protocol=p;
}

static void set_mode_t(struct conf *conf, mode_t m)
{
	assert(conf->conf_type==CT_MODE_T);
	conf->data.mode=m;
}

static void set_ssize_t(struct conf *conf, ssize_t s)
{
	assert(conf->conf_type==CT_SSIZE_T);
	conf->data.ssizet=s;
}

void conf_free_content(struct conf *c)
{
	int i=0;
	if(!c) return;
	for(i=0; i<OPT_MAX; i++) switch(c[i].conf_type)
	{
		case CT_STRING:
			if(c[i].data.s)
			{
				free(c[i].data.s);
				c[i].data.s=NULL;
			}
			break;
		case CT_STRLIST:
			// FIX THIS.
			//strlists_free(&c.data.sl);
			break;
		case CT_FLOAT:
			break;
		case CT_E_BURP_MODE:
		case CT_E_PROTOCOL:
		case CT_UINT:
			break;
		case CT_MODE_T:
		case CT_SSIZE_T:
			break;
	}
}

/* Free only stuff related to includes/excludes.
   This is so that the server can override them all on the client. */
// FIX THIS: Maybe have this as a substructure of a struct conf.
// Could then just memset them all to zero here.
static void free_incexcs(struct conf *c)
{
/* FIX THIS
	strlists_free(&c[OPT_STARTDIR]);
	strlists_free(&c[OPT_INCEXCDIR]);
	strlists_free(&c[OPT_FSCHGDIR]);
	strlists_free(&c[OPT_NOBACKUP]);
	strlists_free(&c[OPT_INCEXT]); // include extensions
	strlists_free(&c[OPT_EXCEXT]); // exclude extensions
	strlists_free(&c[OPT_INCREG]); // include (regular expression)
	strlists_free(&c[OPT_EXCREG]); // exclude (regular expression)
	strlists_free(&c[OPT_EXCFS]); // exclude filesystems
	strlists_free(&c[OPT_EXCOM]); // exclude from compression
	strlists_free(&c[OPT_INCGLOB]); // include (glob)
	strlists_free(&c[OPT_FIFOS]);
	strlists_free(&c[OPT_BLOCKDEVS]);
	free_w(&c[OPT_BACKUP]);
	free_w(&c[OPT_RESTOREPREFIX]);
	free_w(&c[OPT_REGEX]);
	free_w(&c[OPT_VSS_DRIVES]);
*/

	set_int(&c[OPT_SPLIT_VSS], 0);
	set_int(&c[OPT_STRIP_VSS], 0);
	set_int(&c[OPT_ATIME], 0);
	set_int(&c[OPT_OVERWRITE], 0);
	set_int(&c[OPT_STRIP], 0);
}

static void sc(struct conf *conf, int cc_override,
	enum conf_type conf_type, const char *field)
{
	conf->conf_type=conf_type;
	conf->field=field;
	conf->clientconfdir_override=cc_override;
	memset(&conf->data, '\0', sizeof(conf->data));
}

static void sc_str(struct conf *conf, const char *def,
	int cc_override, const char *field)
{
	sc(conf, cc_override, CT_STRING, field);
	set_string(conf, def);
}

static void sc_int(struct conf *conf, unsigned int def,
	int cc_override, const char *field)
{
	sc(conf, cc_override, CT_UINT, field);
	set_int(conf, def);
}

static void sc_lst(struct conf *conf, struct strlist *def,
	int cc_override, const char *field)
{
	sc(conf, cc_override, CT_STRLIST, field);
	set_strlist(conf, def);
}

static void sc_flt(struct conf *conf, float def,
	int cc_override, const char *field)
{
	sc(conf, cc_override, CT_FLOAT, field);
	set_float(conf, def);
}

static void sc_ebm(struct conf *conf, enum burp_mode def,
	int cc_override, const char *field)
{
	sc(conf, cc_override, CT_E_BURP_MODE, field);
	set_e_burp_mode(conf, def);
}

static void sc_epr(struct conf *conf, enum protocol def,
	int cc_override, const char *field)
{
	sc(conf, cc_override, CT_E_PROTOCOL, field);
	set_e_protocol(conf, def);
}

static void sc_mod(struct conf *conf, mode_t def,
	int cc_override, const char *field)
{
	sc(conf, cc_override, CT_MODE_T, field);
	set_mode_t(conf, def);
}

static void sc_szt(struct conf *conf, ssize_t def,
	int cc_override, const char *field)
{
	sc(conf, cc_override, CT_SSIZE_T, field);
	set_ssize_t(conf, def);
}

static void do_set_conf(struct conf *c, enum conf_opt o)
{
	// Do this with a switch statement, so that we get compiler warnings
	// if anything is missed.
	switch(o)
	{
	case OPT_CONFFILE:		return sc_str(&c[o], 0, 1, "conffile");
	case OPT_MODE:			return sc_ebm(&c[o], 0, 0, "mode");
	case OPT_LOCKFILE:		return sc_str(&c[o], 0, 0, "lockfile"); // FIX THIS: synonym: pidfile
	case OPT_SYSLOG:		return sc_int(&c[o], 0, 1, "syslog");
	case OPT_STDOUT:		return sc_int(&c[o], 1, 1, "stdout");
	case OPT_PROGRESS_COUNTER:	return sc_int(&c[o], 0, 1, "progress_counter");
	case OPT_SSL_CERT_CA:		return sc_str(&c[o], 0, 0, "ssl_cert_ca");
	case OPT_SSL_CERT:		return sc_str(&c[o], 0, 0, "ssl_cert");
	case OPT_SSL_KEY:		return sc_str(&c[o], 0, 0, "ssl_key");
	case OPT_SSL_KEY_PASSWORD:	return sc_str(&c[o], 0, 0, "ssl_key_password"); // FIX THIS: synonym: ssl_cert_password
	case OPT_SSL_PEER_CN:		return sc_str(&c[o], 0, 0, "ssl_peer_cn");
	case OPT_SSL_CIPHERS:		return sc_str(&c[o], 0, 0, "ssl_ciphers");
	case OPT_SSL_COMPRESSION:	return sc_int(&c[o], 5, 0, "ssl_compression");
	case OPT_USER:			return sc_str(&c[o], 0, 1, "user");
	case OPT_GROUP:			return sc_str(&c[o], 0, 1, "group");
	case OPT_RATELIMIT:		return sc_flt(&c[o], 0, 0, "ratelimit");
	// Two hours.
	case OPT_NETWORK_TIMEOUT:	return sc_int(&c[o], 60*60*2, 0, "network_timeout");
	case OPT_CLIENT_IS_WINDOWS:	return sc_int(&c[o], 0, 0, "client_is_windows");
	case OPT_PEER_VERSION:		return sc_str(&c[o], 0, 0, "peer_version");
	case OPT_PROTOCOL:		return sc_epr(&c[o], 0, 1, "protocol");
	case OPT_ADDRESS:		return sc_str(&c[o], 0, 0, "address");
	case OPT_PORT:			return sc_str(&c[o], 0, 0, "port");
	case OPT_STATUS_ADDRESS:	return sc_str(&c[o], 0, 0, "status_address");
	case OPT_STATUS_PORT:		return sc_str(&c[o], 0, 0, "status_port");
	case OPT_DIRECTORY:		return sc_str(&c[o], 0, 1, "directory");
	case OPT_TIMESTAMP_FORMAT:	return sc_str(&c[o], 0, 1, "timestamp_format");
	case OPT_CLIENTCONFDIR:		return sc_str(&c[o], 0, 1, "clientconfdir");
	case OPT_SSL_DHFILE:		return sc_str(&c[o], 0, 0, "ssl_dhfile");
	case OPT_MAX_CHILDREN:		return sc_int(&c[o], 0, 0, "max_children");
	case OPT_MAX_STATUS_CHILDREN:	return sc_int(&c[o], 0, 0, "max_status_children");
	case OPT_CLIENT_LOCKDIR:	return sc_str(&c[o], 0, 0, "client_lockdir");
	case OPT_UMASK:			return sc_mod(&c[o], 0022, 0, "umask");
	case OPT_MAX_HARDLINKS:		return sc_int(&c[o], 1, 0, "max_hardlinks");
	// ext3 maximum number of subdirs is 32000, so leave a little room.
	case OPT_MAX_STORAGE_SUBDIRS:	return sc_int(&c[o], 30000, 0, "max_storage_subdirs");
	case OPT_FORK:			return sc_int(&c[o], 1, 1, "fork");
	case OPT_DAEMON:		return sc_int(&c[o], 1, 0, "daemon");
	case OPT_DIRECTORY_TREE:	return sc_int(&c[o], 1, 1, "directory_tree");
	case OPT_CA_CONF:		return sc_str(&c[o], 0, 0, "ca_conf");
	case OPT_CA_NAME:		return sc_str(&c[o], 0, 0, "ca_name");
	case OPT_CA_SERVER_NAME:	return sc_str(&c[o], 0, 0, "ca_server_name");
	case OPT_CA_BURP_CA:		return sc_str(&c[o], 0, 0, "ca_burp_ca");
	case OPT_PASSWORD_CHECK:	return sc_int(&c[o], 1, 1, "password_check");
	case OPT_MANUAL_DELETE:		return sc_str(&c[o], 0, 1, "manual_delete");
	case OPT_MONITOR_LOGFILE:	return sc_str(&c[o], 0, 0, "monitor_logfile");
	case OPT_MONITOR_BROWSE_CACHE:	return sc_int(&c[o], 0, 1, "monitor_browse_cache");
	case OPT_CNAME:			return sc_str(&c[o], 0, 0, "cname");
	case OPT_PASSWORD:		return sc_str(&c[o], 0, 0, "password");
	case OPT_PASSWD:		return sc_str(&c[o], 0, 0, "passwd");
	case OPT_SERVER:		return sc_str(&c[o], 0, 0, "server");
	case OPT_ENCRYPTION_PASSWORD:	return sc_str(&c[o], 0, 0, "encryption_password");
	case OPT_AUTOUPGRADE_OS:	return sc_str(&c[o], 0, 0, "autoupgrade_os");
	case OPT_AUTOUPGRADE_DIR:	return sc_str(&c[o], 0, 0, "autoupgrade_dir");
	case OPT_CA_CSR_DIR:		return sc_str(&c[o], 0, 0, "ca_csr_dir");
	case OPT_RANDOMISE:		return sc_int(&c[o], 0, 0, "randomise");
	case OPT_STARTDIR:		return sc_lst(&c[o], 0, 0, "startdir");
	case OPT_INCEXCDIR:		return sc_lst(&c[o], 0, 0, "include"); // FIX THIS: Also need "exclude" in the same option.
	case OPT_FSCHGDIR:		return sc_lst(&c[o], 0, 0, "cross_filesystem");
	case OPT_NOBACKUP:		return sc_lst(&c[o], 0, 0, "nobackup");
	case OPT_INCEXT:		return sc_lst(&c[o], 0, 0, "include_ext");
	case OPT_EXCEXT:		return sc_lst(&c[o], 0, 0, "exclude_ext");
	case OPT_INCREG:		return sc_lst(&c[o], 0, 0, "include_regex");
	case OPT_EXCREG:		return sc_lst(&c[o], 0, 0, "exclude_regex");
	case OPT_EXCFS:			return sc_lst(&c[o], 0, 0, "exclude_fs");
	case OPT_EXCOM:			return sc_lst(&c[o], 0, 0, "exclude_comp");
	case OPT_INCGLOB:		return sc_lst(&c[o], 0, 0, "include_glob");
	case OPT_CROSS_ALL_FILESYSTEMS:	return sc_int(&c[o], 0, 0, "cross_all_filesystems");
	case OPT_READ_ALL_FIFOS:	return sc_int(&c[o], 0, 0, "read_all_fifos");
	case OPT_FIFOS:			return sc_lst(&c[o], 0, 0, "read_fifo");
	case OPT_READ_ALL_BLOCKDEVS:	return sc_int(&c[o], 0, 0, "read_all_blockdevs");
	case OPT_BLOCKDEVS:		return sc_lst(&c[o], 0, 0, "read_blockdev");
	case OPT_MIN_FILE_SIZE:		return sc_szt(&c[o], 0, 0, "min_file_size");
	case OPT_MAX_FILE_SIZE:		return sc_szt(&c[o], 0, 0, "max_file_size");
	case OPT_SPLIT_VSS:		return sc_int(&c[o], 0, 0, "split_vss");
	case OPT_STRIP_VSS:		return sc_int(&c[o], 0, 0, "strip_vss");
	case OPT_VSS_DRIVES:		return sc_str(&c[o], 0, 0, "vss_drives");
	case OPT_ATIME:			return sc_int(&c[o], 0, 0, "atime");
	case OPT_OVERWRITE:		return sc_int(&c[o], 0, 0, "overwrite");
	case OPT_STRIP:			return sc_int(&c[o], 0, 0, "strip");
	case OPT_BACKUP:		return sc_str(&c[o], 0, 0, "backup");
	case OPT_BACKUP2:		return sc_str(&c[o], 0, 0, "backup2");
	case OPT_RESTOREPREFIX:		return sc_str(&c[o], 0, 0, "restoreprefix");
	case OPT_REGEX:			return sc_str(&c[o], 0, 0, "regex");
	case OPT_RESTORE_SPOOL:		return sc_str(&c[o], 0, 0, "restore_spool");
	case OPT_BROWSEFILE:		return sc_str(&c[o], 0, 0, "browsefile");
	case OPT_BROWSEDIR:		return sc_str(&c[o], 0, 0, "browsedir");
	case OPT_B_SCRIPT_PRE:		return sc_str(&c[o], 0, 0, "backup_script_pre");
	case OPT_B_SCRIPT_PRE_ARG:	return sc_lst(&c[o], 0, 0, "backup_script_pre_arg");
	case OPT_B_SCRIPT_POST:		return sc_str(&c[o], 0, 0, "backup_script_post");
	case OPT_B_SCRIPT_POST_ARG:	return sc_lst(&c[o], 0, 0, "backup_script_post_arg");
	case OPT_B_SCRIPT_POST_RUN_ON_FAIL: return sc_int(&c[o], 0, 0, "backup_script_post_run_on_fail");
	case OPT_R_SCRIPT_PRE:		return sc_str(&c[o], 0, 0, "restore_script_pre");
	case OPT_R_SCRIPT_PRE_ARG:	return sc_lst(&c[o], 0, 0, "restore_script_pre_arg");
	case OPT_R_SCRIPT_POST:		return sc_str(&c[o], 0, 0, "restore_script_post");
	case OPT_R_SCRIPT_POST_ARG:	return sc_lst(&c[o], 0, 0, "restore_script_post_arg");
	case OPT_R_SCRIPT_POST_RUN_ON_FAIL: return sc_int(&c[o], 0, 0, "restore_script_run_on_fail");
	case OPT_S_SCRIPT_PRE:		return sc_str(&c[o], 0, 1, "server_script_pre");
	case OPT_S_SCRIPT_PRE_ARG:	return sc_lst(&c[o], 0, 1, "server_script_pre_arg");
	case OPT_S_SCRIPT_PRE_NOTIFY:	return sc_int(&c[o], 0, 1, "server_script_pre_notify");
	case OPT_S_SCRIPT_POST:		return sc_str(&c[o], 0, 1, "server_script_post");
	case OPT_S_SCRIPT_POST_ARG:	return sc_lst(&c[o], 0, 1, "server_script_post_arg");
	case OPT_S_SCRIPT_POST_RUN_ON_FAIL: return sc_int(&c[o], 0, 1, "server_script_post_run_on_fail");
	case OPT_S_SCRIPT_POST_NOTIFY:	return sc_int(&c[o], 0, 1, "server_script_post_notify");
	case OPT_B_SCRIPT:		return sc_str(&c[o], 0, 0, "backup_script");
	case OPT_B_SCRIPT_ARG:		return sc_lst(&c[o], 0, 0, "backup_script_arg");
	case OPT_R_SCRIPT:		return sc_str(&c[o], 0, 0, "restore_script");
	case OPT_R_SCRIPT_ARG:		return sc_lst(&c[o], 0, 0, "restore_script_arg");
	case OPT_S_SCRIPT:		return sc_str(&c[o], 0, 1, "server_script");
	case OPT_S_SCRIPT_ARG:		return sc_lst(&c[o], 0, 1, "server_script_arg");
	case OPT_S_SCRIPT_NOTIFY:	return sc_int(&c[o], 0, 1, "server_script_notify");
	case OPT_HARDLINKED_ARCHIVE:	return sc_int(&c[o], 0, 1, "hardlinked_archive");
	case OPT_KEEP:			return sc_lst(&c[o], 0, 1, "keep");
	case OPT_WORKING_DIR_RECOVERY_METHOD: return sc_str(&c[o], 0, 1, "working_dir_recovery_method");
	case OPT_LIBRSYNC:		return sc_int(&c[o], 1, 1, "librsync");
	case OPT_COMPRESSION:		return sc_int(&c[o], 9, 1, "compression");
	case OPT_VERSION_WARN:		return sc_int(&c[o], 1, 1, "version_warn");
	case OPT_PATH_LENGTH_WARN:	return sc_int(&c[o], 1, 1, "path_length_warn");
	case OPT_HARD_QUOTA:		return sc_szt(&c[o], 0, 1, "hard_quota");
	case OPT_SOFT_QUOTA:		return sc_szt(&c[o], 0, 1, "soft_quota");
	case OPT_TIMER_SCRIPT:		return sc_str(&c[o], 0, 1, "timer_script");
	case OPT_TIMER_ARG:		return sc_lst(&c[o], 0, 1, "timer_arg");
	case OPT_N_SUCCESS_SCRIPT:	return sc_str(&c[o], 0, 1, "notify_success_script");
	case OPT_N_SUCCESS_ARG:		return sc_lst(&c[o], 0, 1, "notify_success_arg");
	case OPT_N_SUCCESS_WARNINGS_ONLY: return sc_int(&c[o], 0, 1, "notify_success_warnings_only");
	case OPT_N_SUCCESS_CHANGES_ONLY: return sc_int(&c[o], 0, 1, "notify_success_changes_only");
	case OPT_N_FAILURE_SCRIPT:	return sc_str(&c[o], 0, 1, "notify_failure_script");
	case OPT_N_FAILURE_ARG:		return sc_lst(&c[o], 0, 1, "notify_failure_arg");
	case OPT_RESTORE_CLIENTS:	return sc_lst(&c[o], 0, 1, "restore_clients");
	case OPT_DEDUP_GROUP:		return sc_str(&c[o], 0, 1, "dedup_group");
	case OPT_CLIENT_CAN_DELETE:	return sc_int(&c[o], 1, 1, "client_can_delete");
	case OPT_CLIENT_CAN_DIFF:	return sc_int(&c[o], 1, 1, "client_can_diff");
	case OPT_CLIENT_CAN_FORCE_BACKUP: return sc_int(&c[o], 1, 1, "client_can_force_backup");
	case OPT_CLIENT_CAN_LIST:	return sc_int(&c[o], 1, 1, "client_can_list");
	case OPT_CLIENT_CAN_RESTORE:	return sc_int(&c[o], 1, 1, "client_can_restore");
	case OPT_CLIENT_CAN_VERIFY:	return sc_int(&c[o], 1, 1, "client_can_verify");
	case OPT_SERVER_CAN_RESTORE:	return sc_int(&c[o], 1, 1, "server_can_restore");
	case OPT_SEND_CLIENT_CNTR:	return sc_int(&c[o], 0, 0, "send_client_cntr");
	case OPT_RESTORE_CLIENT:	return sc_str(&c[o], 0, 0, "restore_client");
	case OPT_RESTORE_PATH:		return sc_str(&c[o], 0, 0, "restore_path");
	case OPT_ORIG_CLIENT:		return sc_str(&c[o], 0, 0, "orig_client");
	case OPT_CNTR:			return sc_str(&c[o], 0, 0, "cntr");
	case OPT_BREAKPOINT:		return sc_int(&c[o], 0, 1, "breakpoint");
	case OPT_MAX:			return;
	// No default, so we get compiler warnings if something was missed.
	}
}

static void conf_init(struct conf *c)
{
	int i=0;
	for(i=0; i<OPT_MAX; i++) do_set_conf(c, i);
}

static char *conf_data_to_str(struct conf *conf)
{
	static char ret[256]="";
	*ret='\0';
	switch(conf->conf_type)
	{
		case CT_STRING:
			snprintf(ret, sizeof(ret), "%s",
				get_string(conf)?get_string(conf):"");
			break;
		case CT_FLOAT:
			snprintf(ret, sizeof(ret), "%g", get_float(conf));
			break;
		case CT_E_BURP_MODE:
			break;
		case CT_E_PROTOCOL:
			break;
		case CT_UINT:
			snprintf(ret, sizeof(ret), "%u", get_int(conf));
			break;
		case CT_STRLIST:
			break;
		case CT_MODE_T:
		case CT_SSIZE_T:
			break;
	}
	return ret;

}

static int dump_conf(struct conf *conf)
{
	int i=0;
	for(i=0; i<OPT_MAX; i++)
	{
		printf("%32s: %s\n", conf[i].field, conf_data_to_str(&conf[i]));
	}
	return 0;
}

struct conf *conf_alloc(void)
{
	return (struct conf *)calloc(1, sizeof(struct conf)*OPT_MAX);
};

int main(int argc, char *argv[])
{
	struct conf *conf=NULL;
	conf=conf_alloc();
	conf_init(conf);

	dump_conf(conf);
	free(conf);
	return 0;
}
