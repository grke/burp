#include "include.h"

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

// For the counters.
void logc(const char *fmt, ...)
{
	char buf[512]="";
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	if(logfp) fprintf(logfp, "%s", buf); // for the server side
	else
	{
		if(do_progress_counter
		  && do_stdout)
			fprintf(stdout, "%s", buf);
	}
	va_end(ap);
}

const char *progname(void)
{
	return prog;
}

int set_logfp(const char *path, struct conf *conf)
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

void log_restore_settings(struct conf *cconf, int srestore)
{
	struct strlist *l;
	logp("Restore settings:\n");
	if(cconf->orig_client)
		logp("orig_client = %s\n", cconf->orig_client);
	logp("backup = %s\n", cconf->backup);
	if(srestore)
	{
		// This are unknown unless doing a server initiated restore.
		logp("overwrite = %d\n", cconf->overwrite);
		logp("strip = %d\n", cconf->strip);
	}
	if(cconf->restoreprefix)
		logp("restoreprefix = %s\n", cconf->restoreprefix);
	if(cconf->regex) logp("regex = %s\n", cconf->regex);
	for(l=cconf->incexcdir; l; l=l->next)
		if(l->flag) logp("include = %s\n", l->path);
}

int logw(struct async *as, struct conf *conf, const char *fmt, ...)
{
	int r=0;
	char buf[512]="";
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	if(as && as->doing_estimate) printf("\nWARNING: %s\n", buf);
	else
	{
		if(as) r=as->write_str(as, CMD_WARNING, buf);
		logp("WARNING: %s\n", buf);
	}
	va_end(ap);
	cntr_add(conf->cntr, CMD_WARNING, 1);
	return r;
}

void log_and_send(struct async *as, const char *msg)
{
	logp("%s\n", msg);
	if(as && as->asfd && as->asfd->fd>0)
		as->write_str(as, CMD_ERROR, msg);
}

void log_and_send_oom(struct async *as, const char *function)
{
	char m[256]="";
        snprintf(m, sizeof(m), "out of memory in %s()\n", __func__);
        logp("%s", m);
        if(as && as->asfd && as->asfd->fd>0)
		as->write_str(as, CMD_ERROR, m);
}
