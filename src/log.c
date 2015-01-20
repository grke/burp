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
	va_end(ap);
	pid=(int)getpid();
	if(logfp)
		fprintf(logfp, "%s: %s[%d] %s", gettm(), prog, pid, buf);
	else
	{
		if(do_syslog)
			syslog(LOG_INFO, "%s", buf);
		if(do_stdout)
			fprintf(stdout, "%s: %s[%d] %s",
				gettm(), prog, pid, buf);
	}
}

// For the counters.
void logc(const char *fmt, ...)
{
	char buf[512]="";
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if(logfp)
		fprintf(logfp, "%s", buf); // for the server side
	else if(do_progress_counter && do_stdout)
		fprintf(stdout, "%s", buf);
}

void logp_ssl_err(const char *fmt, ...)
{
	char buf[512]="";
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	logp("%s", buf);
	if(logfp)
		ERR_print_errors_fp(logfp);
	else if(do_syslog)
	{
		// FIX THIS: How to send to syslog?
		static BIO *bio_err=NULL;
		if(!bio_err) bio_err=BIO_new_fp(stderr, BIO_NOCLOSE);
		ERR_print_errors(bio_err);
	}
	else if(do_stdout)
	{
		static BIO *bio_err=NULL;
		if(!bio_err) bio_err=BIO_new_fp(stdout, BIO_NOCLOSE);
		ERR_print_errors(bio_err);
	}
}

const char *progname(void)
{
	return prog;
}

/* Same as the function in msg.c, which should be in its own file.
   Copying and pasting here because fixing it will cause annoying merge
   problems with burp2. */
static FILE *open_file(const char *fname, const char *mode)
{
	FILE *fp=NULL;

	if(!(fp=fopen(fname, mode)))
	{
		logp("could not open %s: %s\n", fname, strerror(errno));
		return NULL;
	}
	return fp;
}

int set_logfp(const char *path, struct config *conf)
{
	if(logfp) fclose(logfp);
	logfp=NULL;
	if(path)
	{
		logp("Logging to %s\n", path);
		if(!(logfp=open_file(path, "ab"))) return -1;
	}
#ifndef HAVE_WIN32
	if(logfp) setlinebuf(logfp);
#endif
	do_syslog=conf->log_to_syslog;
	do_stdout=conf->log_to_stdout;
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

void log_out_of_memory(const char *function)
{
	if(function) logp("out of memory in %s()\n", function);
	else logp("out of memory in unknown function\n");
}
