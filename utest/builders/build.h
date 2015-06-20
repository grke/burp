#ifndef _BUILDERS_H
#define _BUILDERS_H

#include "../../src/conf.h"

extern char **build_paths(int wanted);
extern struct sbuf *build_attribs(enum protocol protocol);
extern struct sbuf *build_attribs_reduce(enum protocol protocol);
extern struct slist *build_manifest(const char *path,
        enum protocol protocol, int entries, int phase);

#endif
