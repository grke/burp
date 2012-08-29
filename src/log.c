#include "burp.h"
#include "conf.h"
#include "log.h"

static const char *prog="unknown";

static FILE *logfp=NULL;
// Start with all logging on, so that something is said when initial startup
// goes wrong - for example, reading the conf file.
static int do_syslog=1;
static int do_stdout=1;
static int do_progress_counter=1;
static int syslog_opened=0;

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
	if(logfp) fprintf(logfp, "%s: %s[%d] %s", gettm(), prog, pid, buf);
	else
	{
		if(do_syslog)
			syslog(LOG_INFO, "%s", buf);
		if(do_stdout)
			fprintf(stdout, "%s: %s[%d] %s",
				gettm(), prog, pid, buf);
	}
	va_end(ap);
}

/* for the counters */
void logc(const char *fmt, ...)
{
	char buf[512]="";
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	if(logfp) fprintf(logfp, "%s", buf); // for the server side
	else
	{
		if(do_progress_counter) fprintf(stdout, "%s", buf);
	}
	va_end(ap);
}

const char *progname(void)
{
	return prog;
}

int set_logfp(FILE *fp, struct config *conf)
{
	if(logfp) fclose(logfp);
	logfp=fp;
#ifndef HAVE_WIN32
	if(logfp) setlinebuf(logfp);
#endif
	do_syslog=conf->syslog;
	do_stdout=conf->stdout;
	do_progress_counter=conf->progress_counter;

	if(syslog_opened)
	{
		closelog();
		syslog_opened=0;
	}
	if(do_syslog)
	{
		openlog(prog, LOG_PID, LOG_USER);
		syslog_opened++;
	}
	return 0;
}

FILE *get_logfp(void)
{
	return logfp;
}
