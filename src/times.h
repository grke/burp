#ifndef _BURP_TIMES_H
#define _BURP_TIMES_H

#define DEFAULT_TIMESTAMP_FORMAT	"%Y-%m-%d %H:%M:%S %z"
#define DEFAULT_TIMESTAMP_FORMAT_OLD	"%Y-%m-%d %H:%M:%S"

extern const char *getdatestr(const time_t t);
extern const char *gettimenow(void);
extern const char *time_taken(time_t d);
extern char *encode_time(time_t utime, char *buf);

#endif
