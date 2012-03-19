#ifndef _LOG_ROUTINES
#define _LOG_ROUTINES

extern void init_log(char *progname);
extern void logp(const char *fmt, ...);
extern void logc(const char *fmt, ...);
extern const char *progname(void);
extern int set_logfp(FILE *fp, struct config *conf);
extern FILE *get_logfp(void);
extern int open_logfile(const char *logfile, struct config *conf);

#endif
