#ifndef _TIMESTAMP_H
#define _TIMESTAMP_H

extern int timestamp_read(const char *path, char buf[], size_t len);
extern int timestamp_write(const char *path, const char *tstmp);
extern int timestamp_get_new(struct asfd *asfd,
	struct sdirs *sdirs, struct conf *cconf, char *buf, size_t s);

#endif
