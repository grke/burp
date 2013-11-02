#ifndef _CONF_FILE_H
#define _CONF_FILE_H

#include "counter.h"
#include "strlist.h"
#include "rabin/rconf.h"

enum burp_mode
{
	MODE_UNSET=0,
	MODE_SERVER,
	MODE_CLIENT
};

struct config
{
	char *configfile;
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

// server options
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

// client options
	char *cname;
	char *password; // also a clientconfdir option
	char *passwd; // also a clientconfdir option
	char *server;
	char *encryption_password;
	char *autoupgrade_os;
	char *autoupgrade_dir; // also a server option
	char *ca_csr_dir;

  // This block of client stuff is all to do with what files to backup.
	int sdcount; struct strlist **startdir;
	int iecount; struct strlist **incexcdir;
	int fscount; struct strlist **fschgdir;
	int nbcount; struct strlist **nobackup;
	int incount; struct strlist **incext; // include extensions
	int excount; struct strlist **excext; // exclude extensions
	int ircount; struct strlist **increg; // include (regular expression)
	int ercount; struct strlist **excreg; // exclude (regular expression)
	int exfscount; struct strlist **excfs; // exclude filesystems
	int excmcount; struct strlist **excom; // exclude from compression
	uint8_t cross_all_filesystems;
	uint8_t read_all_fifos;
	struct strlist **fifos;
	int ffcount;
	uint8_t read_all_blockdevs;
	struct strlist **blockdevs;
	int bdcount;
	ssize_t min_file_size;
	ssize_t max_file_size;
	char *vss_drives;
  // These are to do with restore.
	uint8_t overwrite;
	int strip;
	char *backup;
	char *restoreprefix;
	char *regex;
  // To do with listing.
	char *browsefile;
	char *browsedir;

	char *backup_script_pre;
	struct strlist **backup_script_pre_arg;
	int bprecount;
	char *backup_script_post;
	struct strlist **backup_script_post_arg;
	int bpostcount;
	uint8_t backup_script_post_run_on_fail;
	char *restore_script_pre;
	struct strlist **restore_script_pre_arg;
	int rprecount;
	char *restore_script_post;
	struct strlist **restore_script_post_arg;
	int rpostcount;
	uint8_t restore_script_post_run_on_fail;

	char *server_script_pre;
	struct strlist **server_script_pre_arg;
	int sprecount;
	uint8_t server_script_pre_notify;
	char *server_script_post;
	struct strlist **server_script_post_arg;
	int spostcount;
	uint8_t server_script_post_run_on_fail;
	uint8_t server_script_post_notify;

	// Rabin conf
	struct rconf rconf;

	// Use these when you want to give the same args to both post and pre
	// scripts.
	char *backup_script;
	struct strlist **backup_script_arg;
	int bscount;
	char *restore_script;
	struct strlist **restore_script_arg;
	int rscount;

	char *server_script;
	struct strlist **server_script_arg;
	int sscount;
	uint8_t server_script_notify;

// Client options on the server.
// They can be set globally in the server config, or for each client.
	uint8_t hardlinked_archive;

	int kpcount;
	struct strlist **keep;

	uint8_t compression;
	uint8_t version_warn;

	char *timer_script;
	struct strlist **timer_arg;
	int tacount;

	char *notify_success_script;
	struct strlist **notify_success_arg;
	int nscount;
	uint8_t notify_success_warnings_only;
	uint8_t notify_success_changes_only;

	char *notify_failure_script;
	struct strlist **notify_failure_arg;
	int nfcount;

// List of clients that are permitted to restore the files from our client.
	struct strlist **rclients;
	int rccount;

	char *dedup_group;

	uint8_t client_can_delete;
	uint8_t client_can_force_backup;
	uint8_t client_can_list;
	uint8_t client_can_restore;
	uint8_t client_can_verify;

	uint8_t server_can_restore;

// Set to 1 on both client and server when the server is able to send counters
// on resume/verify/restore.
	uint8_t send_client_counters;

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

extern void init_config(struct config *conf);
extern int load_config(const char *config_path, struct config *conf, bool loadall);
extern void free_config(struct config *conf);
extern int set_client_global_config(struct config *conf, struct config *cconf, const char *client);
extern int is_subdir(const char *dir, const char *sub);
extern int pathcmp(const char *a, const char *b);
extern int config_get_pair(char buf[], char **field, char **value);
extern int parse_incexcs_buf(struct config *conf, const char *incexc);
extern int log_incexcs_buf(const char *incexc);
extern int parse_incexcs_path(struct config *conf, const char *path);
extern int load_client_config(struct config *conf, struct config *cconf, const char *client);

#endif
