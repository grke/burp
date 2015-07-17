#include "../src/burp.h"
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
void log_and_send(struct asfd *asfd, const char *msg) { }
void log_and_send_oom(struct asfd *asfd, const char *function) { }
int logw(struct asfd *asfd, struct conf **confs, const char *fmt, ...)
	{ return 0; }

const char *progname(void) { return "utest"; }

void berrno_init(struct berrno *b) { }
const char *berrno_bstrerror(struct berrno *b, int errnum) { return ""; }

int blk_read_verify(struct blk *blk_to_verify, struct conf **confs)
	{ return 0; }


int rblk_retrieve_data(const char *datpath, struct blk *blk) { return 0; }

int is_hook(uint64_t fingerprint) { return 0; }
