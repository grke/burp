#include <stdio.h>
#include <stdarg.h>
#include <time.h>
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
void log_recvd(struct iobuf *, struct conf **, int) { }
const char *getdatestr(time_t t) { return ""; }
const char *time_taken(time_t d) { return ""; }
const char *progname(void) { return "utest"; }
size_t fzp_write(struct fzp *fzp, const void *ptr, size_t nmemb) { return 0; }
int fzp_printf(struct fzp *fzp, const char *format, ...) { return 0; }

int blk_read_verify(struct blk *blk_to_verify, struct conf **confs)
	{ return 0; }
