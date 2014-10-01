#ifndef _CACHE_H
#define _CACHE_H

#include "include.h"

extern int cache_loaded(struct cstat *cstat, struct bu *bu);
extern int cache_load(struct asfd *srfd, struct manio *manio, struct sbuf *sb,
	struct cstat *cstat, struct bu *bu);
extern int cache_lookup(const char *browse);

#endif
