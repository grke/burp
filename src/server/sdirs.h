#ifndef __SDIRS_H
#define __SDIRS_H

#define TREE_DIR	"t"
#define DATA_DIR	"data"

#include "../conf.h"

// Server directories.
struct sdirs
{
	enum protocol protocol;

	char *base;
	char *dedup;
	char *champlock;
	char *champsock;
	char *champlog;
	char *champ_dindex_lock;
	char *data;
	char *clients;
	char *client;
	char *created;
	char *command;

	char *working; // Symlink.
	char *rworking; // Real.
	char *finishing; // Symlink.
	char *current; // Symlink.
	char *currenttmp; // Temporary symlink.
	char *deleteme;
	char *dindex;
	char *dfiles;
	char *cfiles; // For tracking data files created by backups.
	char *global_sparse;

	char *timestamp;
	char *changed;
	char *unchanged;
	char *counters_d; // file data entries
	char *counters_n; // non file data entries
	char *manifest; // Path to manifest (via working).
	char *rmanifest; // Path to manifest (real).
	char *cmanifest; // Path to current (previous) manifest.
	char *phase1data;

	char *restore_list; // For restore file lists from the client.

	char *lockdir;
	// For backup/delete, lock all storage directories for other
	// backups/deletes.
	struct lock *lock_storage_for_write;

	// Protocol1 directories.
	char *currentdata;
	char *datadirtmp;
	char *cincexc;
	char *deltmppath;
	char *treepath;
	char *relink;
};

extern struct sdirs *sdirs_alloc(void);
extern int sdirs_init_from_confs(struct sdirs *sdirs, struct conf **confs);
extern int sdirs_init_from_confs_plus_cname(
        struct sdirs *sdirs,
        struct conf **confs,
        const char *cname
);

extern int sdirs_init(struct sdirs *sdirs, enum protocol protocol,
	const char *directory, const char *cname, const char *conf_lockdir,
	const char *dedup_group, const char *manual_delete);
extern void sdirs_free_content(struct sdirs *sdirs);
extern void sdirs_free(struct sdirs **sdirs);

extern int sdirs_get_real_manifest(struct sdirs *sdirs, enum protocol protocol);
extern int sdirs_create_real_working(struct sdirs *sdirs, uint64_t bno,
	const char *timestamp_format);
extern int sdirs_get_real_working_from_symlink(struct sdirs *sdirs);

#endif
