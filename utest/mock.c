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
const char *getdatestr(time_t t) { return ""; }
const char *time_taken(time_t d) { return ""; }
const char *progname(void) { return "utest"; }
FILE *open_file(const char *fname, const char *mode) { return NULL; }

int timestamp_write(const char *path, const char *tstmp) { return 0; }
int timestamp_get_new(struct sdirs *sdirs,
        char *buf, size_t s, char *bufforfile, size_t bs, struct conf **cconfs)
		{ return 0; }
