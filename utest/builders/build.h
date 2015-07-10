#ifndef _BUILDERS_H
#define _BUILDERS_H

#include "../../src/conf.h"

extern char **build_paths(int wanted);
extern struct sbuf *build_attribs(enum protocol protocol);
extern struct sbuf *build_attribs_reduce(enum protocol protocol);
extern struct slist *build_manifest(const char *path,
        enum protocol protocol, int entries, int phase);

extern struct blist *build_blist(int wanted);
extern void build_blks(struct blist *blist, int wanted);


extern void build_manifest_phase2_from_slist(const char *path,
	struct slist *slist, enum protocol protocol);

#endif
