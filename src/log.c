#include "burp.h"
#include "log.h"

static const char *prog="unknown";

static FILE *logfp=NULL;

void init_log(char *progname)
{
	if((prog=strrchr(progname, '/'))) prog++;
	else prog=progname;
}

static char *gettm(void)
{
        time_t t=0;
        const struct tm *ctm=NULL;
        static char tmbuf[32]="";

        time(&t);
        ctm=localtime(&t);
	// Windows does not like the %T strftime format option - you get
	// complaints under gdb.
        strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", ctm);
	return tmbuf;
}

void logp(const char *fmt, ...)
{
	int pid;
	char buf[512]="";
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	pid=(int)getpid();
	fprintf(logfp?logfp:stdout, "%s: %s[%d] %s", gettm(), prog, pid, buf);
	syslog(LOG_INFO, "%s: %s[%d] %s", gettm(), prog, pid, buf);
	va_end(ap);
}

const char *progname(void)
{
	return prog;
}

int set_logfp(FILE *fp)
{
	if(logfp) fclose(logfp);
	logfp=fp;
	if(logfp) setlinebuf(logfp);
	return 0;
}

FILE *get_logfp(void)
{
	return logfp;
}
