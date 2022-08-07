#ifndef _BURP_TIMES_H
#define _BURP_TIMES_H

#define DEFAULT_TIMESTAMP_FORMAT_OLD	"%Y-%m-%d %H:%M:%S"

#ifdef __GLIBC__
#define DEFAULT_TIMESTAMP_FORMAT	"%Y-%m-%d %H:%M:%S %z"
#else
// Only glibc supports %z in strptime.
#define DEFAULT_TIMESTAMP_FORMAT DEFAULT_TIMESTAMP_FORMAT_OLD
#endif

extern const char *getdatestr(const time_t t);
extern const char *gettimenow(void);
extern const char *time_taken(time_t d);
extern char *encode_time(time_t utime, char *buf);

#endif
