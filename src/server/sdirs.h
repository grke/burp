#ifndef __SDIRS_H
#define __SDIRS_H

#define TREE_DIR	"t"
#define DATA_DIR	"data"

#include "conf.h"

// Server directories.
struct sdirs
{
	enum protocol protocol;

	char *base;
	char *dedup;
	char *champlock;
	char *champsock;
	char *champlog;
	char *data;
	char *clients;
	char *client;

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
	char *manifest; // Path to manifest (via working).
	char *rmanifest; // Path to manifest (real).
	char *cmanifest; // Path to current (previous) manifest.
	char *phase1data;

	char *lockdir;
	struct lock *lock;

	// Protocol1 directories.
	char *currentdata;
	char *datadirtmp;
	char *cincexc;
	char *deltmppath;
	char *treepath;
};

extern struct sdirs *sdirs_alloc(void);
extern int sdirs_init_from_confs(struct sdirs *sdirs, struct conf **confs);
extern int sdirs_init(struct sdirs *sdirs, enum protocol protocol,
	const char *directory, const char *cname, const char *conf_lockdir,
	const char *dedup_group, const char *manual_delete);
extern void sdirs_free_content(struct sdirs *sdirs);
extern void sdirs_free(struct sdirs **sdirs);

extern int sdirs_get_real_manifest(struct sdirs *sdirs, enum protocol protocol);
extern int sdirs_create_real_working(struct sdirs *sdirs,
	const char *timestamp_format);
extern int sdirs_get_real_working_from_symlink(struct sdirs *sdirs);

#endif
