#ifndef _CONF_FILE_H
#define _CONF_FILE_H

#include "cntr.h"
#include "strlist.h"
#include "burp2/rabin/rconf.h"

enum burp_mode
{
	MODE_UNSET=0,
	MODE_SERVER,
	MODE_CLIENT
};

enum protocol
{
	PROTO_AUTO=0,
	PROTO_BURP1,
	PROTO_BURP2
};

struct conf
{
	char *conffile;
	char *port;
	char *status_port;
	enum burp_mode mode;
	char *lockfile;
	uint8_t log_to_syslog;
	uint8_t log_to_stdout;
	uint8_t progress_counter;
	char *ssl_cert_ca;
	char *ssl_cert;
	char *ssl_key;
	char *ssl_key_password;
	char *ssl_peer_cn;
	char *ssl_ciphers;
	char *user;
	char *group;
	float ratelimit;
	int network_timeout;

  // If the client tells us it is windows, this is set on the server side.
	uint8_t client_is_windows;

	char *peer_version;

  // Whether to run in burp1, or burp2 style, or to choose automatically.
	enum protocol protocol;

// Server options.
	char *directory;
	char *timestamp_format;
	char *clientconfdir;
	char *ssl_dhfile;
	int max_children;
	int max_status_children;
	char *client_lockdir;
	mode_t umask;
	int max_hardlinks;
	int max_storage_subdirs;
	uint8_t forking;
	uint8_t daemon;
	uint8_t directory_tree;
	char *ca_conf;
	char *ca_name;
	char *ca_server_name;
	char *ca_burp_ca;
	uint8_t password_check;
	char *manual_delete;

// Client options.
	char *cname; // set on the server when client connects
	char *password; // also a clientconfdir option
	char *passwd; // also a clientconfdir option
	char *server;
	char *encryption_password;
	char *autoupgrade_os;
	char *autoupgrade_dir; // also a server option
	char *ca_csr_dir;

  // This block of client stuff is all to do with what files to backup.
	struct strlist *startdir;
	struct strlist *incexcdir;
	struct strlist *fschgdir;
	struct strlist *nobackup;
	struct strlist *incext; // include extensions
	struct strlist *excext; // exclude extensions
	struct strlist *increg; // include (regular expression)
	struct strlist *excreg; // exclude (regular expression)
	struct strlist *excfs; // exclude filesystems
	struct strlist *excom; // exclude from compression
	struct strlist *incglob; // include (glob expression)
	uint8_t cross_all_filesystems;
	uint8_t read_all_fifos;
	struct strlist *fifos;
	uint8_t read_all_blockdevs;
	struct strlist *blockdevs;
	ssize_t min_file_size;
	ssize_t max_file_size;
	int split_vss;
	int strip_vss;
	char *vss_drives;
  // These are to do with restore.
	uint8_t overwrite;
	int strip;
	char *backup;
	char *restoreprefix;
	char *regex;
	char *restore_spool;
  // To do with listing.
	char *browsefile;
	char *browsedir;

  // Backup scripts.
	char *b_script_pre;
	struct strlist *b_script_pre_arg;
	char *b_script_post;
	struct strlist *b_script_post_arg;
	uint8_t b_script_post_run_on_fail;
	char *r_script_pre;
	struct strlist *r_script_pre_arg;
	char *r_script_post;
	struct strlist *r_script_post_arg;
	uint8_t r_script_post_run_on_fail;

  // Server scripts.
	char *s_script_pre;
	struct strlist *s_script_pre_arg;
	uint8_t s_script_pre_notify;
	char *s_script_post;
	struct strlist *s_script_post_arg;
	uint8_t s_script_post_run_on_fail;
	uint8_t s_script_post_notify;

  // Rabin conf
	struct rconf rconf;

  // Use these when you want to give the same args to both post and pre
  // scripts.
	char *b_script;
	struct strlist *b_script_arg;
	char *r_script;
	struct strlist *r_script_arg;

	char *s_script;
	struct strlist *s_script_arg;
	uint8_t s_script_notify;

// Client options on the server.
// They can be set globally in the server config, or for each client.
	uint8_t hardlinked_archive;

	struct strlist *keep;

	char *recovery_method;
	uint8_t librsync;

	uint8_t compression;
	uint8_t version_warn;
	uint8_t resume_partial;

	char *timer_script;
	struct strlist *timer_arg;

  // Notify scripts
	char *n_success_script;
	struct strlist *n_success_arg;
	uint8_t n_success_warnings_only;
	uint8_t n_success_changes_only;

	char *n_failure_script;
	struct strlist *n_failure_arg;
  // List of clients that are permitted to restore the files from our client.
	struct strlist *rclients;

	char *dedup_group;

	uint8_t client_can_delete;
	uint8_t client_can_force_backup;
	uint8_t client_can_list;
	uint8_t client_can_restore;
	uint8_t client_can_verify;

	uint8_t server_can_restore;

// Set to 1 on both client and server when the server is able to send counters
// on resume/verify/restore.
	uint8_t send_client_cntr;

// Set on the server to the restore client name (the one that you connected
// with) when the client has switched to a different set of client backups.
	char *restore_client;
// Path to the server initiated restore file.
	char *restore_path;

// Original client that backed up. Used when doing a server initiated restore
// to an alternative client;
	char *orig_client;

	struct cntr *p1cntr;
	struct cntr *cntr;
};

extern struct conf *conf_alloc(void);
extern void conf_init(struct conf *c);
extern void conf_free_content(struct conf *c);
extern void conf_free(struct conf *c);

extern int conf_load(const char *conf_path, struct conf *c,
	uint8_t loadall);
extern int conf_set_client_global(struct conf *c, struct conf *cc);

extern int is_subdir(const char *dir, const char *sub);
extern int pathcmp(const char *a, const char *b);
extern int conf_get_pair(char buf[], char **field, char **value);
extern int parse_incexcs_buf(struct conf *c, const char *incexc);
extern int log_incexcs_buf(const char *incexc);
extern int parse_incexcs_path(struct conf *c, const char *path);
extern int conf_load_client(struct conf *c, struct conf *cc);
extern int conf_val_reset(const char *src, char **dest);

#ifdef HAVE_WIN32
extern void convert_backslashes(char **path);
#endif

#endif
