#ifndef _CONF_H
#define _CONF_H

#define CONF_FLAG_CC_OVERRIDE		0x01
#define CONF_FLAG_INCEXC		0x02
#define CONF_FLAG_INCEXC_RESTORE	0x04
#define CONF_FLAG_STRLIST_SORTED	0x08
#define CONF_FLAG_STRLIST_REPLACE	0x10

enum burp_mode
{
	BURP_MODE_UNSET=0,
	BURP_MODE_SERVER,
	BURP_MODE_CLIENT
};

enum protocol
{
	PROTO_AUTO=0,
	PROTO_1,
	PROTO_2
};

enum recovery_method
{
	RECOVERY_METHOD_UNSET=0,
	RECOVERY_METHOD_DELETE,
	RECOVERY_METHOD_RESUME
};

enum rshash
{
	RSHASH_UNSET=0,
	RSHASH_MD4,
	RSHASH_BLAKE2
};

enum vss_restore
{
	VSS_RESTORE_OFF=0,
	VSS_RESTORE_OFF_STRIP,
	VSS_RESTORE_ON
};

enum conf_type
{
	CT_STRING=0,
	CT_UINT,
	CT_FLOAT,
	CT_MODE_T,
	CT_SSIZE_T,
	CT_E_BURP_MODE,
	CT_E_PROTOCOL,
	CT_E_RECOVERY_METHOD,
	CT_E_RSHASH,
	CT_STRLIST,
	CT_CNTR,
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
		enum recovery_method recovery_method;
		enum protocol protocol;
		enum rshash rshash;
		mode_t mode;
		uint64_t uint64;
		unsigned int i;
		struct strlist *sl;
		struct cntr *cntr;
	} data;
	int flags;
};

enum conf_opt
{
	OPT_CONFFILE=0,
	OPT_BURP_MODE,
	OPT_LOCKFILE,
	OPT_PIDFILE,
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
	OPT_SSL_VERIFY_PEER_EARLY,
	OPT_USER,
	OPT_GROUP,
	OPT_RATELIMIT,
	OPT_NETWORK_TIMEOUT,
	OPT_CLIENT_IS_WINDOWS,
	OPT_PEER_VERSION,
	OPT_PROTOCOL,
	OPT_RSHASH,
	OPT_MESSAGE,
	OPT_CNAME_LOWERCASE, // force lowercase cname, client or server option
	OPT_CNAME_FQDN, // use fqdn cname, client or server option
	OPT_VSS_RESTORE,

	// Server options.
	OPT_LISTEN,
	OPT_LISTEN_STATUS,
	OPT_DIRECTORY,
	OPT_TIMESTAMP_FORMAT,
	OPT_CLIENTCONFDIR,
	OPT_SSL_DHFILE,
	OPT_MAX_CHILDREN,
	OPT_MAX_STATUS_CHILDREN,
	OPT_MAX_PARALLEL_BACKUPS,
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
	OPT_CA_CRL_CHECK,
	OPT_CA_CRL,
	OPT_PASSWORD_CHECK,
	OPT_MANUAL_DELETE,
	OPT_RBLK_MEMORY_MAX,
	OPT_SPARSE_SIZE_MAX,
	OPT_MONITOR_LOGFILE, // An ncurses client option, from command line.
	OPT_MONITOR_BROWSE_CACHE,
	OPT_MONITOR_EXE,
	OPT_BACKUP_FAILOVERS_LEFT,

	// Client options.
	OPT_CNAME, // set on the server when client connects
	OPT_PORT,
	OPT_STATUS_PORT,
	OPT_PORT_BACKUP,
	OPT_PORT_RESTORE,
	OPT_PORT_VERIFY,
	OPT_PORT_LIST,
	OPT_PORT_DELETE,
	OPT_PASSWORD, // also a clientconfdir option
	OPT_PASSWD, // also a clientconfdir option
	OPT_ENABLED, // also a clientconfdir option
	OPT_SERVER,
	OPT_SERVER_FAILOVER,
	OPT_FAILOVER_ON_BACKUP_ERROR,
	OPT_ENCRYPTION_PASSWORD,
	OPT_AUTOUPGRADE_OS,
	OPT_AUTOUPGRADE_DIR, // also a server option
	OPT_CA_CSR_DIR,
	OPT_RANDOMISE,
	OPT_SERVER_CAN_OVERRIDE_INCLUDES,
	OPT_RESTORE_LIST,

	// This block of client stuff is all to do with what files to backup.
	OPT_STARTDIR,
	OPT_INCEXCDIR,
	OPT_INCLUDE,
	OPT_EXCLUDE,
	OPT_FSCHGDIR,
	OPT_NOBACKUP,
	OPT_INCEXT, // include extensions
	OPT_EXCEXT, // exclude extensions
	OPT_INCREG, // include (regular expression)
	OPT_EXCREG, // exclude (regular expression)
	OPT_INCLOGIC, // include logic expression
	OPT_EXCLOGIC, // exclude logic expression
	OPT_EXCFS, // exclude filesystems
	OPT_INCFS, // include filesystems
	OPT_EXCOM, // exclude from compression
	OPT_INCGLOB, // include (glob expression)
	OPT_SEED_SRC,
	OPT_SEED_DST,
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
	OPT_ACL,
	OPT_XATTR,
	OPT_ATIME,
	OPT_SCAN_PROBLEM_RAISES_ERROR,
	// These are to do with restore.
	OPT_OVERWRITE,
	OPT_STRIP,
	OPT_STRIP_FROM_PATH,
	OPT_BACKUP,
	OPT_BACKUP2, // For diffs.
	OPT_RESTOREPREFIX,
	OPT_REGEX,
	OPT_REGEX_CASE_INSENSITIVE,
	// To do with listing.
	OPT_BROWSEFILE,
	OPT_BROWSEDIR,

	// Backup/restore client scripts.
	OPT_B_SCRIPT_PRE,
	OPT_B_SCRIPT_PRE_ARG,
	OPT_B_SCRIPT_POST,
	OPT_B_SCRIPT_POST_ARG,
	OPT_B_SCRIPT_POST_RUN_ON_FAIL,
	OPT_B_SCRIPT_RESERVED_ARGS,
	OPT_R_SCRIPT_PRE,
	OPT_R_SCRIPT_PRE_ARG,
	OPT_R_SCRIPT_POST,
	OPT_R_SCRIPT_POST_ARG,
	OPT_R_SCRIPT_POST_RUN_ON_FAIL,
	OPT_R_SCRIPT_RESERVED_ARGS,

	// eval glob after script pre.
	OPT_GLOB_AFTER_SCRIPT_PRE,

	// Server scripts.
	OPT_S_SCRIPT_PRE,
	OPT_S_SCRIPT_PRE_ARG,
	OPT_S_SCRIPT_PRE_NOTIFY,
	OPT_S_SCRIPT_POST,
	OPT_S_SCRIPT_POST_ARG,
	OPT_S_SCRIPT_POST_RUN_ON_FAIL,
	OPT_S_SCRIPT_POST_NOTIFY,

	// Use these when you want to give the same args to both post and pre
	// scripts.
	// Backup/restore client scripts.
	OPT_B_SCRIPT,
	OPT_B_SCRIPT_ARG,
	OPT_R_SCRIPT,
	OPT_R_SCRIPT_ARG,
	// Server scripts.
	OPT_S_SCRIPT,
	OPT_S_SCRIPT_ARG,
	OPT_S_SCRIPT_NOTIFY,

	// Client options on the server.
	// They can be set globally in the server config, or for each client.
	OPT_HARDLINKED_ARCHIVE,

	OPT_KEEP,

	OPT_WORKING_DIR_RECOVERY_METHOD,
	OPT_FAIL_ON_WARNING,
	OPT_MAX_RESUME_ATTEMPTS,
	OPT_LIBRSYNC,
	OPT_LIBRSYNC_MAX_SIZE,

	OPT_COMPRESSION,
	OPT_VERSION_WARN,
	OPT_PATH_LENGTH_WARN,
	OPT_HARD_QUOTA,
	OPT_SOFT_QUOTA,

	OPT_TIMER_SCRIPT,
	OPT_TIMER_ARG,
	OPT_TIMER_REPEAT_INTERVAL,

	OPT_LABEL,

	// Notify scripts
	OPT_N_SUCCESS_SCRIPT,
	OPT_N_SUCCESS_ARG,
	OPT_N_SUCCESS_WARNINGS_ONLY,
	OPT_N_SUCCESS_CHANGES_ONLY,

	OPT_N_FAILURE_SCRIPT,
	OPT_N_FAILURE_ARG,
	OPT_N_FAILURE_BACKUP_FAILOVERS_LEFT,
	OPT_N_FAILURE_BACKUP_WORKING_DELETION,

	OPT_RESTORE_CLIENTS,
	OPT_SUPER_CLIENTS,

	OPT_DEDUP_GROUP,

	OPT_CLIENT_CAN_DELETE,
	OPT_CLIENT_CAN_DIFF,
	OPT_CLIENT_CAN_FORCE_BACKUP,
	OPT_CLIENT_CAN_LIST,
	OPT_CLIENT_CAN_MONITOR,
	OPT_CLIENT_CAN_RESTORE,
	OPT_CLIENT_CAN_VERIFY,
	OPT_SERVER_CAN_RESTORE,

	// Set to 1 on both client and server when the server is able to send
	// counters on resume/verify/restore.
	OPT_SEND_CLIENT_CNTR,

	// Set on the server to the super client name (the one that you
	// connected with) when the client has switched to a different set of
	// client backups.
	OPT_SUPER_CLIENT,
	// Path to the server initiated restore file.
	OPT_RESTORE_PATH,

	// Original client that backed up. Used when doing a server initiated
	// restore to an alternative client,
	OPT_ORIG_CLIENT,
	// The client that connected.
	OPT_CONNECT_CLIENT,

	OPT_CNTR,

	// For testing.
	OPT_BREAKPOINT,

	// readall capability
	OPT_READALL,

	OPT_MAX
};

extern struct conf **confs_alloc(void);
extern void confs_free(struct conf ***confs);
extern void confs_free_content(struct conf **confs);
extern int confs_init(struct conf **confs);
extern void conf_free_content(struct conf *c);
extern void confs_free_content(struct conf **confs);
extern void confs_null(struct conf **confs);
extern void confs_memcpy(struct conf **dst, struct conf **src);

extern void free_incexcs(struct conf **confs);
extern int conf_set(struct conf **confs, const char *field, const char *value);
extern int confs_dump(struct conf **confs, int flags);

extern struct strlist *get_strlist(struct conf *conf);
extern char *get_string(struct conf *conf);
extern int get_int(struct conf *conf);
extern float get_float(struct conf *conf);
extern uint64_t get_uint64_t(struct conf *conf);
extern mode_t get_mode_t(struct conf *conf);
extern enum burp_mode get_e_burp_mode(struct conf *conf);
extern enum protocol get_e_protocol(struct conf *conf);
extern enum protocol get_protocol(struct conf **confs);
extern enum recovery_method get_e_recovery_method(struct conf *conf);
extern enum rshash get_e_rshash(struct conf *conf);
extern struct cntr *get_cntr(struct conf **confs);

extern int set_cntr(struct conf *conf, struct cntr *cntr);
extern int set_string(struct conf *conf, const char *s);
extern int set_strlist(struct conf *conf, struct strlist *s);
extern int set_int(struct conf *conf, unsigned int i);
extern int set_e_burp_mode(struct conf *conf, enum burp_mode bm);
extern int set_e_protocol(struct conf *conf, enum protocol p);
extern int set_protocol(struct conf **confs, enum protocol p);
extern int set_e_rshash(struct conf *conf, enum rshash r);
extern int set_mode_t(struct conf *conf, mode_t m);
extern int set_float(struct conf *conf, float f);
extern int set_uint64_t(struct conf *conf, uint64_t s);
extern int add_to_strlist(struct conf *conf, const char *value, int include);
extern int add_to_strlist_include_uniq(struct conf *conf, const char *value);

extern enum burp_mode str_to_burp_mode(const char *str);
extern enum protocol str_to_protocol(const char *str);
extern const char *recovery_method_to_str(enum recovery_method r);
extern enum recovery_method str_to_recovery_method(const char *str);
extern int set_e_recovery_method(struct conf *conf, enum recovery_method r);
extern const char *rshash_to_str(enum rshash r);

#endif
