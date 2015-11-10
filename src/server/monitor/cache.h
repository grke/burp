#ifndef _CACHE_H
#define _CACHE_H

extern int cache_loaded(struct cstat *cstat, struct bu *bu);
extern int cache_load(struct asfd *srfd, struct manio *manio, struct sbuf *sb,
	struct cstat *cstat, struct bu *bu);
extern int cache_lookup(const char *browse);
extern void cache_free(void);

#endif
