#ifndef _CONF_FILE_H
#define _CONF_FILE_H

#include "strlist.h"

enum burp_mode
{
	MODE_UNSET=0,
	MODE_SERVER,
	MODE_CLIENT
};

struct config
{
	char *port;
	char *status_port;
	enum burp_mode mode;
	char *lockfile;
	char *logfile;
	char *ssl_cert_ca;
	char *ssl_cert;
	char *ssl_key;
	char *ssl_key_password;
	char *ssl_peer_cn;
	char *user;
	char *group;
	float ratelimit;
	int network_timeout;

// server options
	char *directory;
	char *clientconfdir;
	char *ssl_dhfile;
	int max_children;
	char *client_lockdir;
	mode_t umask;
	int max_hardlinks;
	int max_storage_subdirs;

// client options
	char *cname;
	char *password; // also a clientconfdir option
	char *passwd; // also a clientconfdir option
	char *server;
	char *encryption_password;
	char *autoupgrade_os;
	char *autoupgrade_dir; // also a server option

  // This block of client stuff is all to do with what files to backup.
	struct strlist **startdir;
	struct strlist **incexcdir;
	struct strlist **fschgdir;
	struct strlist **nobackup;
	struct strlist **excext;
	struct strlist **excfs;
	int sdcount;
	int iecount;
	int fscount;
	int nbcount;
	int excount;
	int exfscount;
	int cross_all_filesystems;
	int read_all_fifos;
	struct strlist **fifos;
	int ffcount;
	unsigned long min_file_size;
	unsigned long max_file_size;

	char *backup_script_pre;
	struct strlist **backup_script_pre_arg;
	int bprecount;
	char *backup_script_post;
	struct strlist **backup_script_post_arg;
	int bpostcount;
	int   backup_script_post_run_on_fail;
	char *restore_script_pre;
	struct strlist **restore_script_pre_arg;
	int rprecount;
	char *restore_script_post;
	struct strlist **restore_script_post_arg;
	int rpostcount;
	int   restore_script_post_run_on_fail;

	char *server_script_pre;
	struct strlist **server_script_pre_arg;
	int sprecount;
	char *server_script_post;
	struct strlist **server_script_post_arg;
	int spostcount;
	int   server_script_post_run_on_fail;

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

// Client options on the server.
// They can be set globally in the server config, or for each client.
	int hardlinked_archive;

	int kpcount;
	struct strlist **keep;

	char *working_dir_recovery_method;
	int librsync;
	int compression;

	char *timer_script;
	struct strlist **timer_arg;
	int tacount;

	char *notify_success_script;
	struct strlist **notify_success_arg;
	int nscount;
	int notify_success_warnings_only;

	char *notify_failure_script;
	struct strlist **notify_failure_arg;
	int nfcount;

	char *dedup_group;
};

extern void init_config(struct config *conf);
extern int load_config(const char *config_path, struct config *conf, bool loadall);
extern void free_config(struct config *conf);
extern int set_client_global_config(struct config *conf, struct config *cconf);
extern int is_subdir(const char *dir, const char *sub);
extern int pathcmp(const char *a, const char *b);

extern int send_incexc_client(struct config *conf, struct cntr *p1cntr);
extern int recv_incexc_server(struct config *conf, struct cntr *p1cntr);

#endif
