#ifndef _TIMESTAMP_H
#define _TIMESTAMP_H

struct sdirs;

extern int timestamp_read(const char *path, char buf[], size_t len);
extern int timestamp_write(const char *path, const char *tstmp);
extern int timestamp_get_new(uint64_t index,
	char *buf, size_t s, char *bufforfile, size_t bs, const char *format);
extern long timestamp_to_long(const char *buf);

#ifdef UTEST
extern void timestamp_write_to_buf(char *buf, size_t s,
	uint64_t index, const char *format, time_t *t);
#endif

#endif
