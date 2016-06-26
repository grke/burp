#ifndef _CACHE_H
#define _CACHE_H

extern int cache_loaded(const char *cname, unsigned long bno);
extern int cache_load(struct manio *manio, struct sbuf *sb,
	const char *cname, unsigned long bno);
extern int cache_lookup(const char *browse);
extern void cache_free(void);

#endif
