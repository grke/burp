#ifndef _LOG_ROUTINES
#define _LOG_ROUTINES

extern void init_log(char *progname);
extern void logp(const char *fmt, ...);
extern void logc(const char *fmt, ...);
extern const char *progname(void);
extern int set_logfp(const char *path, struct conf *conf);
extern FILE *get_logfp(void);
extern void log_out_of_memory(const char *function);
extern void log_restore_settings(struct conf *cconf, int srestore);
extern int logw(struct async *as, struct conf *conf, const char *fmt, ...);
extern void log_and_send(struct async *as, const char *msg);
extern void log_and_send_oom(struct async *as, const char *function);

#endif
