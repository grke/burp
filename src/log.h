#ifndef _LOG_ROUTINES
#define _LOG_ROUTINES

extern const char *prog;

extern void init_log(char *progname);
extern void logp(const char *fmt, ...);
extern void logp_ssl_err(const char *fmt, ...);
extern void logc(const char *fmt, ...);
extern const char *progname(void);
extern int set_logfzp(const char *path, struct conf **confs);
extern void set_logfzp_direct(struct fzp *fzp);
extern struct fzp *get_logfzp(void);
extern void log_out_of_memory(const char *function);
extern void log_restore_settings(struct conf **cconfs, int srestore);
extern int logm(struct asfd *asfd, struct conf **confs, const char *fmt, ...);
extern int logw(struct asfd *asfd, struct conf **confs, const char *fmt, ...);
extern void log_and_send(struct asfd *asfd, const char *msg);
extern void log_and_send_oom(struct asfd *asfd, const char *function);
extern void log_set_json(int value);
extern void log_oom_w(const char *func, const char *orig_func);
extern int log_incexcs_buf(const char *incexc);
extern void log_recvd(struct iobuf *iobuf, struct conf **confs, int print);

#endif
