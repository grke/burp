#include "../src/burp.h"
#include "../src/cntr.h"
#include "../src/server/monitor/cstat.h"
void logp(const char *fmt, ...)
{
/*
	char buf[512]="";
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	fprintf(stdout, "%s", buf);
*/
}
void logc(const char *fmt, ...) { }
void log_oom_w(const char *func, const char *orig_func) { }
void log_out_of_memory(const char *function) { }
void log_recvd(struct iobuf *, struct cntr *, int) { }
void log_and_send(struct asfd *asfd, const char *msg) { }
void log_and_send_oom(struct asfd *asfd, const char *function) { }
int logw(struct asfd *asfd, struct cntr *cntr, const char *fmt, ...)
	{ return 0; }
int log_fzp_set(const char *path, struct conf **confs) { return 0; }
void logp_ssl_err(const char *fmt, ...) { };

const char *progname(void) { return "utest"; }

void berrno_init(struct berrno *b) { }
const char *berrno_bstrerror(struct berrno *b, int errnum) { return ""; }

int rblk_retrieve_data(const char *datpath, struct blk *blk) { return 0; }

int write_status(enum cntr_status cntr_status,
        const char *path, struct cntr *cntr) { return 0; }
