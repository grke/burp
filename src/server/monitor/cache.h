#ifndef _CACHE_H
#define _CACHE_H

#include "include.h"

extern int cache_loaded(void);
extern int cache_load(struct asfd *srfd, struct manio *manio, struct sbuf *sb);
extern int cache_lookup(const char *browse);

#endif
