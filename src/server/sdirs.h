#ifndef __SDIRS_H
#define __SDIRS_H

// Server directories.
struct sdirs
{
	char *base;
	char *dedup;
	char *data;
	char *clients;
	char *client;

	char *working;
	char *finishing;
	char *current;

	char *timestamp;
	char *changed;
	char *unchanged;
	char *cmanifest;

	char *lock;
	char *lockfile;
};

extern struct sdirs *sdirs_alloc(void);
extern int sdirs_init(struct sdirs *sdirs,
	struct config *conf, const char *client);
extern void sdirs_free(struct sdirs *sdirs);

#endif
