#ifndef _TIMESTAMP_H
#define _TIMESTAMP_H

#define DEFAULT_TIMESTAMP_FORMAT	"%Y-%m-%d %H:%M:%S"

struct sdirs;

extern int timestamp_read(const char *path, char buf[], size_t len);
extern int timestamp_write(const char *path, const char *tstmp);
extern int timestamp_get_new(uint64_t index,
	char *buf, size_t s, char *bufforfile, size_t bs, const char *format);

#endif
