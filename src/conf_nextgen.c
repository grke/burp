/* Experiment to start the sanitising of conf.c, so that we can eventually do
   things like dumping the current configuration. */

#include <stdio.h>
#include <malloc.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

enum burp_mode
{
	MODE_UNSET=0,
	MODE_SERVER,
	MODE_CLIENT
};

enum protocol
{
	PROTO_AUTO=0,
	PROTO_1,
	PROTO_2
};

enum conf_type
{
	CT_STRING=0,
	CT_INT,
	CT_FLOAT,
	CT_MODE_T,
	CT_SSIZE_T,
	CT_E_BURP_MODE,
	CT_E_PROTOCOL,
	CT_STRLIST,
	CT_RCONF,
};

struct conf
{
        enum conf_type conf_type;
        const char *field;
	union
	{
		char *s;
		float f;
		enum burp_mode burp_mode;
		enum protocol protocol;
		mode_t mode;
		ssize_t ssizet;
		uint64_t i;
		struct strlist *sl;
		struct rconf *rconf;
		struct cntr *cntr;
	};
	int clientconfdir_override;
	int overridden;
};

enum conf_opt
{
	OPT_CONFFILE=0,
	OPT_MODE,
	OPT_LOCKFILE,
	OPT_SYSLOG,
	OPT_STDOUT,
	OPT_PROGRESS_COUNTER,
	OPT_SSL_CERT_CA,
	OPT_SSL_CERT,
	OPT_SSL_KEY,
	OPT_SSL_KEY_PASSWORD,
	OPT_SSL_PEER_CN,
	OPT_SSL_CIPHERS,
	OPT_SSL_COMPRESSION,
	OPT_USER,
	OPT_GROUP,
	OPT_RATELIMIT,
	OPT_NETWORK_TIMEOUT,
	OPT_CLIENT_IS_WINDOWS,
	OPT_PEER_VERSION,
	OPT_PROTOCOL,

	// Server options.
	OPT_ADDRESS,
	OPT_PORT,
	OPT_STATUS_ADDRESS,
	OPT_STATUS_PORT,
	OPT_DIRECTORY,
	OPT_TIMESTAMP_FORMAT,
	OPT_CLIENTCONFDIR,
	OPT_SSL_DHFILE,
	OPT_MAX_CHILDREN,
	OPT_MAX_STATUS_CHILDREN,
	OPT_CLIENT_LOCKDIR,
	OPT_UMASK,
	OPT_MAX_HARDLINKS,
	OPT_MAX_STORAGE_SUBDIRS,
	OPT_FORK,
	OPT_DAEMON,
	OPT_DIRECTORY_TREE,
	OPT_CA_CONF,
	OPT_CA_NAME,
	OPT_CA_SERVER_NAME,
	OPT_CA_BURP_CA,
	OPT_PASSWORD_CHECK,
	OPT_MANUAL_DELETE,
	OPT_MONITOR_LOGFILE, // An ncurses client option, from command line.
	OPT_MONITOR_BROWSE_CACHE,

	// Client options.
	OPT_CNAME, // set on the server when client connects
	OPT_PASSWORD, // also a clientconfdir option
	OPT_PASSWD, // also a clientconfdir option
	OPT_SERVER,
	OPT_ENCRYPTION_PASSWORD,
	OPT_AUTOUPGRADE_OS,
	OPT_AUTOUPGRADE_DIR, // also a server option
	OPT_CA_CSR_DIR,
	OPT_RANDOMISE,

	// This block of client stuff is all to do with what files to backup.
	OPT_STARTDIR,
	OPT_INCEXCDIR,
	OPT_FSCHGDIR,
	OPT_NOBACKUP,
	OPT_INCEXT, // include extensions
	OPT_EXCEXT, // exclude extensions
	OPT_INCREG, // include (regular expression)
	OPT_EXCREG, // exclude (regular expression)
	OPT_EXCFS, // exclude filesystems
	OPT_EXCOM, // exclude from compression
	OPT_INCGLOB, // include (glob expression)
	OPT_CROSS_ALL_FILESYSTEMS,
	OPT_READ_ALL_FIFOS,
	OPT_FIFOS,
	OPT_READ_ALL_BLOCKDEVS,
	OPT_BLOCKDEVS,
	OPT_MIN_FILE_SIZE,
	OPT_MAX_FILE_SIZE,
	OPT_SPLIT_VSS,
	OPT_STRIP_VSS,
	OPT_VSS_DRIVES,
	OPT_ATIME,
	// These are to do with restore.
	OPT_OVERWRITE,
	OPT_STRIP,
	OPT_BACKUP,
	OPT_BACKUP2, // For diffs.
	OPT_RESTOREPREFIX,
	OPT_REGEX,
	OPT_RESTORE_SPOOL,
	// To do with listing.
	OPT_BROWSEFILE,
	OPT_BROWSEDIR,

	// Backup scripts.
	OPT_B_SCRIPT_PRE,
	OPT_B_SCRIPT_PRE_ARG,
	OPT_B_SCRIPT_POST,
	OPT_B_SCRIPT_POST_ARG,
	OPT_B_SCRIPT_POST_RUN_ON_FAIL,
	OPT_R_SCRIPT_PRE,
	OPT_R_SCRIPT_PRE_ARG,
	OPT_R_SCRIPT_POST,
	OPT_R_SCRIPT_POST_ARG,
	OPT_R_SCRIPT_POST_RUN_ON_FAIL,

	// Server scripts.
	OPT_S_SCRIPT_PRE,
	OPT_S_SCRIPT_PRE_ARG,
	OPT_S_SCRIPT_PRE_NOTIFY,
	OPT_S_SCRIPT_POST,
	OPT_S_SCRIPT_POST_ARG,
	OPT_S_SCRIPT_POST_RUN_ON_FAIL,
	OPT_S_SCRIPT_POST_NOTIFY,

	// Rabin conf
	OPT_RCONF,

	// Use these when you want to give the same args to both post and pre
	// scripts.
	OPT_B_SCRIPT,
	OPT_B_SCRIPT_ARG,
	OPT_R_SCRIPT,
	OPT_R_SCRIPT_ARG,

	OPT_S_SCRIPT,
	OPT_S_SCRIPT_ARG,
	OPT_S_SCRIPT_NOTIFY,

	// Client options on the server.
	// They can be set globally in the server config, or for each client.
	OPT_HARDLINKED_ARCHIVE,

	OPT_KEEP,

	OPT_WORKING_DIR_RECOVERY_METHOD,
	OPT_LIBRSYNC,

	OPT_COMPRESSION,
	OPT_VERSION_WARN,
	OPT_PATH_LENGTH_WARN,
	OPT_HARD_QUOTA,
	OPT_SOFT_QUOTA,

	OPT_TIMER_SCRIPT,
	OPT_TIMER_ARG,

	// Notify scripts
	OPT_N_SUCCESS_SCRIPT,
	OPT_N_SUCCESS_ARG,
	OPT_N_SUCCESS_WARNINGS_ONLY,
	OPT_N_SUCCESS_CHANGES_ONLY,

	OPT_N_FAILURE_SCRIPT,
	OPT_N_FAILURE_ARG,
	// List of clients that are permitted to restore the files from our client.
	OPT_RESTORE_CLIENTS,

	OPT_DEDUP_GROUP,

	OPT_CLIENT_CAN, // Things the client is allowed to do.
	OPT_SERVER_CAN, // Things the server is allowed to do.

	// Set to 1 on both client and server when the server is able to send
	// counters on resume/verify/restore.
	OPT_SEND_CLIENT_CNTR,

	// Set on the server to the restore client name (the one that you
	// connected with) when the client has switched to a different set of
	// client backups.
	OPT_RESTORE_CLIENT,
	// Path to the server initiated restore file.
	OPT_RESTORE_PATH,

	// Original client that backed up. Used when doing a server initiated
	// restore to an alternative client,
	OPT_ORIG_CLIENT,

	OPT_CNTR,

	// For testing.
	OPT_BREAKPOINT,

	OPT_MAX
};

static void sc(struct conf *conf, int cc_override,
	enum conf_type conf_type, const char *field)
{
	conf->conf_type=conf_type;
	conf->field=field;
	conf->clientconfdir_override=cc_override;
}

static void sc_str(struct conf *conf, int cc_override, const char *field)
{
	sc(conf, cc_override, CT_STRING, field);
}

static void sc_int(struct conf *conf, int cc_override, const char *field)
{
	sc(conf, cc_override, CT_INT, field);
}

static void sc_lst(struct conf *conf, int cc_override, const char *field)
{
	sc(conf, cc_override, CT_STRLIST, field);
}

static void sc_flt(struct conf *conf, int cc_override, const char *field)
{
	sc(conf, cc_override, CT_FLOAT, field);
}

static void sc_ebm(struct conf *conf, int cc_override, const char *field)
{
	sc(conf, cc_override, CT_E_BURP_MODE, field);
}

static void sc_epr(struct conf *conf, int cc_override, const char *field)
{
	sc(conf, cc_override, CT_E_PROTOCOL, field);
}

static void sc_mod(struct conf *conf, int cc_override, const char *field)
{
	sc(conf, cc_override, CT_MODE_T, field);
}

static void sc_szt(struct conf *conf, int cc_override, const char *field)
{
	sc(conf, cc_override, CT_SSIZE_T, field);
}

static void sc_rcf(struct conf *conf, int cc_override, const char *field)
{
	sc(conf, cc_override, CT_RCONF, field);
}

static void do_set_conf(struct conf *c, enum conf_opt o)
{
	// Do this with a switch statement, so that we get compiler warnings
	// if anything is missed.
	switch(o)
	{
	case OPT_CONFFILE:		return sc_str(&c[o], 1, "conffile");
	case OPT_MODE:			return sc_ebm(&c[o], 0, "mode");
	case OPT_LOCKFILE:		return sc_str(&c[o], 0, "lockfile"); // synonym: pidfile
	case OPT_SYSLOG:		return sc_int(&c[o], 1, "syslog");
	case OPT_STDOUT:		return sc_int(&c[o], 1, "stdout");
	case OPT_PROGRESS_COUNTER:	return sc_int(&c[o], 1, "progress_counter");
	case OPT_SSL_CERT_CA:		return sc_str(&c[o], 0, "ssl_cert_ca");
	case OPT_SSL_CERT:		return sc_str(&c[o], 0, "ssl_cert");
	case OPT_SSL_KEY:		return sc_str(&c[o], 0, "ssl_key");
	case OPT_SSL_KEY_PASSWORD:	return sc_str(&c[o], 0, "ssl_key_password"); // synonym: ssl_cert_password
	case OPT_SSL_PEER_CN:		return sc_str(&c[o], 0, "ssl_peer_cn");
	case OPT_SSL_CIPHERS:		return sc_str(&c[o], 0, "ssl_ciphers");
	case OPT_SSL_COMPRESSION:	return sc_int(&c[o], 0, "ssl_compression");
	case OPT_USER:			return sc_str(&c[o], 1, "user");
	case OPT_GROUP:			return sc_str(&c[o], 1, "group");
	case OPT_RATELIMIT:		return sc_flt(&c[o], 0, "ratelimit");
	case OPT_NETWORK_TIMEOUT:	return sc_int(&c[o], 0, "network_timeout");
	case OPT_CLIENT_IS_WINDOWS:	return sc_int(&c[o], 0, "client_is_windows");
	case OPT_PEER_VERSION:		return sc_str(&c[o], 0, "peer_version");
	case OPT_PROTOCOL:		return sc_epr(&c[o], 1, "protocol");
	case OPT_ADDRESS:		return sc_str(&c[o], 0, "address");
	case OPT_PORT:			return sc_str(&c[o], 0, "port");
	case OPT_STATUS_ADDRESS:	return sc_str(&c[o], 0, "status_address");
	case OPT_STATUS_PORT:		return sc_str(&c[o], 0, "status_port");
	case OPT_DIRECTORY:		return sc_str(&c[o], 1, "directory");
	case OPT_TIMESTAMP_FORMAT:	return sc_str(&c[o], 1, "timestamp_format");
	case OPT_CLIENTCONFDIR:		return sc_str(&c[o], 1, "clientconfdir");
	case OPT_SSL_DHFILE:		return sc_str(&c[o], 0, "ssl_dhfile");
	case OPT_MAX_CHILDREN:		return sc_int(&c[o], 0, "max_children");
	case OPT_MAX_STATUS_CHILDREN:	return sc_int(&c[o], 0, "max_status_children");
	case OPT_CLIENT_LOCKDIR:	return sc_str(&c[o], 0, "client_lockdir");
	case OPT_UMASK:			return sc_mod(&c[o], 0, "umask");
	case OPT_MAX_HARDLINKS:		return sc_int(&c[o], 0, "max_hardlinks");
	case OPT_MAX_STORAGE_SUBDIRS:	return sc_int(&c[o], 0, "max_storage_subdirs");
	case OPT_FORK:			return sc_int(&c[o], 1, "fork");
	case OPT_DAEMON:		return sc_int(&c[o], 0, "daemon");
	case OPT_DIRECTORY_TREE:	return sc_int(&c[o], 1, "directory_tree");
	case OPT_CA_CONF:		return sc_str(&c[o], 0, "ca_conf");
	case OPT_CA_NAME:		return sc_str(&c[o], 0, "ca_name");
	case OPT_CA_SERVER_NAME:	return sc_str(&c[o], 0, "ca_server_name");
	case OPT_CA_BURP_CA:		return sc_str(&c[o], 0, "ca_burp_ca");
	case OPT_PASSWORD_CHECK:	return sc_int(&c[o], 1, "password_check");
	case OPT_MANUAL_DELETE:		return sc_str(&c[o], 1, "manual_delete");
	case OPT_MONITOR_LOGFILE:	return sc_str(&c[o], 0, "monitor_logfile");
	case OPT_MONITOR_BROWSE_CACHE:	return sc_int(&c[o], 1, "monitor_browse_cache");
	case OPT_CNAME:			return sc_str(&c[o], 0, "cname");
	case OPT_PASSWORD:		return sc_str(&c[o], 0, "password");
	case OPT_PASSWD:		return sc_str(&c[o], 0, "passwd");
	case OPT_SERVER:		return sc_str(&c[o], 0, "server");
	case OPT_ENCRYPTION_PASSWORD:	return sc_str(&c[o], 0, "encryption_password");
	case OPT_AUTOUPGRADE_OS:	return sc_str(&c[o], 0, "autoupgrade_os");
	case OPT_AUTOUPGRADE_DIR:	return sc_str(&c[o], 0, "autoupgrade_dir");
	case OPT_CA_CSR_DIR:		return sc_str(&c[o], 0, "ca_csr_dir");
	case OPT_RANDOMISE:		return sc_int(&c[o], 0, "randomise");
	case OPT_STARTDIR:		return sc_lst(&c[o], 0, "startdir");
	case OPT_INCEXCDIR:		return sc_lst(&c[o], 0, "include"); // Also need "exclude" in the same option.
	case OPT_FSCHGDIR:		return sc_lst(&c[o], 0, "cross_filesystem");
	case OPT_NOBACKUP:		return sc_lst(&c[o], 0, "nobackup");
	case OPT_INCEXT:		return sc_lst(&c[o], 0, "include_ext");
	case OPT_EXCEXT:		return sc_lst(&c[o], 0, "exclude_ext");
	case OPT_INCREG:		return sc_lst(&c[o], 0, "include_regex");
	case OPT_EXCREG:		return sc_lst(&c[o], 0, "exclude_regex");
	case OPT_EXCFS:			return sc_lst(&c[o], 0, "exclude_fs");
	case OPT_EXCOM:			return sc_lst(&c[o], 0, "exclude_comp");
	case OPT_INCGLOB:		return sc_lst(&c[o], 0, "include_glob");
	case OPT_CROSS_ALL_FILESYSTEMS:	return sc_int(&c[o], 0, "cross_all_filesystems");
	case OPT_READ_ALL_FIFOS:	return sc_int(&c[o], 0, "read_all_fifos");
	case OPT_FIFOS:			return sc_lst(&c[o], 0, "read_fifo");
	case OPT_READ_ALL_BLOCKDEVS:	return sc_int(&c[o], 0, "read_all_blockdevs");
	case OPT_BLOCKDEVS:		return sc_lst(&c[o], 0, "read_blockdev");
	case OPT_MIN_FILE_SIZE:		return sc_szt(&c[o], 0, "min_file_size");
	case OPT_MAX_FILE_SIZE:		return sc_szt(&c[o], 0, "max_file_size");
	case OPT_SPLIT_VSS:		return sc_int(&c[o], 0, "split_vss");
	case OPT_STRIP_VSS:		return sc_int(&c[o], 0, "strip_vss");
	case OPT_VSS_DRIVES:		return sc_str(&c[o], 0, "vss_drives");
	case OPT_ATIME:			return sc_int(&c[o], 0, "atime");
	case OPT_OVERWRITE:		return sc_int(&c[o], 0, "overwrite");
	case OPT_STRIP:			return sc_int(&c[o], 0, "strip");
	case OPT_BACKUP:		return sc_str(&c[o], 0, "backup");
	case OPT_BACKUP2:		return sc_str(&c[o], 0, "backup2");
	case OPT_RESTOREPREFIX:		return sc_str(&c[o], 0, "restoreprefix");
	case OPT_REGEX:			return sc_str(&c[o], 0, "regex");
	case OPT_RESTORE_SPOOL:		return sc_str(&c[o], 0, "restore_spool");
	case OPT_BROWSEFILE:		return sc_str(&c[o], 0, "browsefile");
	case OPT_BROWSEDIR:		return sc_str(&c[o], 0, "browsedir");
	case OPT_B_SCRIPT_PRE:		return sc_str(&c[o], 0, "backup_script_pre");
	case OPT_B_SCRIPT_PRE_ARG:	return sc_lst(&c[o], 0, "backup_script_pre_arg");
	case OPT_B_SCRIPT_POST:		return sc_str(&c[o], 0, "backup_script_post");
	case OPT_B_SCRIPT_POST_ARG:	return sc_lst(&c[o], 0, "backup_script_post_arg");
	case OPT_B_SCRIPT_POST_RUN_ON_FAIL: return sc_int(&c[o], 0, "backup_script_post_run_on_fail");
	case OPT_R_SCRIPT_PRE:		return sc_str(&c[o], 0, "restore_script_pre");
	case OPT_R_SCRIPT_PRE_ARG:	return sc_lst(&c[o], 0, "restore_script_pre_arg");
	case OPT_R_SCRIPT_POST:		return sc_str(&c[o], 0, "restore_script_post");
	case OPT_R_SCRIPT_POST_ARG:	return sc_lst(&c[o], 0, "restore_script_post_arg");
	case OPT_R_SCRIPT_POST_RUN_ON_FAIL: return sc_int(&c[o], 0, "restore_script_run_on_fail");
	case OPT_S_SCRIPT_PRE:		return sc_str(&c[o], 1, "server_script_pre");
	case OPT_S_SCRIPT_PRE_ARG:	return sc_lst(&c[o], 1, "server_script_pre_arg");
	case OPT_S_SCRIPT_PRE_NOTIFY:	return sc_int(&c[o], 1, "server_script_pre_notify");
	case OPT_S_SCRIPT_POST:		return sc_str(&c[o], 1, "server_script_post");
	case OPT_S_SCRIPT_POST_ARG:	return sc_lst(&c[o], 1, "server_script_post_arg");
	case OPT_S_SCRIPT_POST_RUN_ON_FAIL: return sc_int(&c[o], 1, "server_script_post_run_on_fail");
	case OPT_S_SCRIPT_POST_NOTIFY:	return sc_int(&c[o], 1, "server_script_post_notify");
	case OPT_RCONF:			return sc_rcf(&c[o], 0, "rconf");
	case OPT_B_SCRIPT:		return sc_str(&c[o], 0, "backup_script");
	case OPT_B_SCRIPT_ARG:		return sc_lst(&c[o], 0, "backup_script_arg");
	case OPT_R_SCRIPT:		return sc_str(&c[o], 0, "restore_script");
	case OPT_R_SCRIPT_ARG:		return sc_lst(&c[o], 0, "restore_script_arg");
	case OPT_S_SCRIPT:		return sc_str(&c[o], 1, "server_script");
	case OPT_S_SCRIPT_ARG:		return sc_lst(&c[o], 1, "server_script_arg");
	case OPT_S_SCRIPT_NOTIFY:	return sc_int(&c[o], 1, "server_script_notify");
	case OPT_HARDLINKED_ARCHIVE:	return sc_int(&c[o], 1, "hardlinked_archive");
	case OPT_KEEP:			return sc_lst(&c[o], 1, "keep");
	case OPT_WORKING_DIR_RECOVERY_METHOD: return sc_str(&c[o], 1, "working_dir_recovery_method");
	case OPT_LIBRSYNC:		return sc_int(&c[o], 1, "librsync");
	case OPT_COMPRESSION:		return sc_int(&c[o], 1, "compression");
	case OPT_VERSION_WARN:		return sc_int(&c[o], 1, "version_warn");
	case OPT_PATH_LENGTH_WARN:	return sc_int(&c[o], 1, "path_length_warn");
	case OPT_HARD_QUOTA:		return sc_szt(&c[o], 1, "hard_quota");
	case OPT_SOFT_QUOTA:		return sc_szt(&c[o], 1, "soft_quota");
	case OPT_TIMER_SCRIPT:		return sc_str(&c[o], 1, "timer_script");
	case OPT_TIMER_ARG:		return sc_lst(&c[o], 1, "timer_arg");
	case OPT_N_SUCCESS_SCRIPT:	return sc_str(&c[o], 1, "notify_success_script");
	case OPT_N_SUCCESS_ARG:		return sc_lst(&c[o], 1, "notify_success_arg");
	case OPT_N_SUCCESS_WARNINGS_ONLY: return sc_int(&c[o], 1, "notify_success_warnings_only");
	case OPT_N_SUCCESS_CHANGES_ONLY: return sc_int(&c[o], 1, "notify_success_changes_only");
	case OPT_N_FAILURE_SCRIPT:	return sc_str(&c[o], 1, "notify_failure_script");
	case OPT_N_FAILURE_ARG:		return sc_lst(&c[o], 1, "notify_failure_arg");
	case OPT_RESTORE_CLIENTS:	return sc_lst(&c[o], 1, "restore_clients");
	case OPT_DEDUP_GROUP:		return sc_str(&c[o], 1, "dedup_group");
	case OPT_CLIENT_CAN:		return sc_int(&c[o], 1, "client_can");
	case OPT_SERVER_CAN:		return sc_int(&c[o], 1, "server_can");
	case OPT_SEND_CLIENT_CNTR:	return sc_int(&c[o], 0, "send_client_cntr");
	case OPT_RESTORE_CLIENT:	return sc_str(&c[o], 0, "restore_client");
	case OPT_RESTORE_PATH:		return sc_str(&c[o], 0, "restore_path");
	case OPT_ORIG_CLIENT:		return sc_str(&c[o], 0, "orig_client");
	case OPT_CNTR:			return sc_str(&c[o], 0, "cntr");
	case OPT_BREAKPOINT:		return sc_int(&c[o], 1, "breakpoint");
	case OPT_MAX:			return;
	// No default, so we get compiler warnings if something was missed.
	}
/* What about these?
        gcv_bit(f, v, "client_can_delete",
                &(c->client_can), CLIENT_CAN_DELETE);
        gcv_bit(f, v, "client_can_diff",
                &(c->client_can), CLIENT_CAN_DIFF);
        gcv_bit(f, v, "client_can_force_backup",
                &(c->client_can), CLIENT_CAN_FORCE_BACKUP);
        gcv_bit(f, v, "client_can_list",
                &(c->client_can), CLIENT_CAN_LIST);
        gcv_bit(f, v, "client_can_restore",
                &(c->client_can), CLIENT_CAN_RESTORE);
        gcv_bit(f, v, "client_can_verify",
                &(c->client_can), CLIENT_CAN_VERIFY);
        gcv_bit(f, v, "server_can_restore",
                &(c->server_can), SERVER_CAN_RESTORE);
*/
}

static void init_conf(struct conf *c)
{
	int i=0;
	for(i=0; i<OPT_MAX; i++) do_set_conf(c, i);
}

static void set_int(struct conf *conf, int i)
{
	conf->i=i;
}

static char *get_string(struct conf *conf)
{
	return conf->s;
}

static uint64_t get_int(struct conf *conf)
{
	return conf->i;
}

static float get_float(struct conf *conf)
{
	return conf->f;
}

static char *set_string(struct conf *conf, const char *s)
{
	if(conf->s) free(conf->s);
	conf->s=strdup(s);
	return conf->s;
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
		case CT_E_PROTOCOL:
		case CT_INT:
			snprintf(ret, sizeof(ret), "%lX", get_int(conf));
			break;
		case CT_STRLIST:
			break;
		case CT_MODE_T:
		case CT_SSIZE_T:
		case CT_RCONF:
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

int main(int argc, char *argv[])
{
	struct conf *conf=NULL;
	conf=calloc(1, sizeof(struct conf)*OPT_MAX);
	init_conf(conf);
	set_int(&conf[OPT_MODE], 10);
	set_string(&conf[OPT_LOCKFILE], "adffsd");
	set_string(&conf[OPT_LOCKFILE], "kljdf");

	dump_conf(conf);
	free(conf);
	return 0;
}
