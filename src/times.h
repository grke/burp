#ifndef _BURP_TIMES_H
#define _BURP_TIMES_H

#define DEFAULT_TIMESTAMP_FORMAT_OLD	"%Y-%m-%d %H:%M:%S"

// Windows does not seem to support %z.
#ifdef HAVE_WIN32
#define DEFAULT_TIMESTAMP_FORMAT DEFAULT_TIMESTAMP_FORMAT_OLD
#else
#define DEFAULT_TIMESTAMP_FORMAT	"%Y-%m-%d %H:%M:%S %z"
#endif

extern const char *getdatestr(const time_t t);
extern const char *gettimenow(void);
extern const char *time_taken(time_t d);
extern char *encode_time(time_t utime, char *buf);

#endif
