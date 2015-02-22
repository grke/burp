#include "include.h"
#include "cmd.h"

const char *prog="unknown";

static FILE *logfp=NULL;
// Start with all logging on, so that something is said when initial startup
// goes wrong - for example, reading the conf file.
static int do_syslog=1;
static int do_stdout=1;
static int do_progress_counter=1;
static int syslog_opened=0;
static int json=0;

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
		{
			if(json)
			{
				char *cp=NULL;
				if((cp=strrchr(buf, '\n'))) *cp='\0';
				// To help programs parsing the monitor output,
				// log things with simple JSON.
				fprintf(stdout, "{ \"logline\": \"%s\" }\n", buf);
			}
			else
				fprintf(stdout, "%s: %s[%d] %s",
					gettm(), prog, pid, buf);
		}
	}
	va_end(ap);
}

void logp_ssl_err(const char *fmt, ...)
{
	char buf[512]="";
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	logp("%s", buf);
	if(logfp) ERR_print_errors_fp(logfp);
	else
	{
		if(do_syslog)
		{
			// FIX THIS: How to send to syslog?
			static BIO *bio_err=NULL;
			if(!bio_err) bio_err=BIO_new_fp(stderr, BIO_NOCLOSE);
			ERR_print_errors(bio_err);
		}
		if(do_stdout)
		{
			if(!json)
			{
				static BIO *bio_err=NULL;
				if(!bio_err) bio_err=BIO_new_fp(stdout,
					BIO_NOCLOSE);
				ERR_print_errors(bio_err);
			}
		}
	}
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

int set_logfp(const char *path, struct conf **confs)
{
	close_fp(&logfp);
	if(path)
	{
		logp("Logging to %s\n", path);
		if(!(logfp=open_file(path, "ab"))) return -1;
	}
#ifndef HAVE_WIN32
	if(logfp) setlinebuf(logfp);
#endif
	do_syslog=get_int(confs[OPT_SYSLOG]);
	do_stdout=get_int(confs[OPT_STDOUT]);
	do_progress_counter=get_int(confs[OPT_PROGRESS_COUNTER]);

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

void set_logfp_direct(FILE *fp)
{
	close_fp(&logfp);
	logfp=fp;
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

void log_restore_settings(struct conf **cconfs, int srestore)
{
	struct strlist *l;
	logp("Restore settings:\n");
	if(get_string(cconfs[OPT_ORIG_CLIENT]))
		logp("orig_client = %s\n", get_string(cconfs[OPT_ORIG_CLIENT]));
	if(get_string(cconfs[OPT_BACKUP]))
		logp("backup = %s\n", get_string(cconfs[OPT_BACKUP]));
	if(srestore)
	{
		// This are unknown unless doing a server initiated restore.
		logp("overwrite = %d\n", get_int(cconfs[OPT_OVERWRITE]));
		logp("strip = %d\n", get_int(cconfs[OPT_STRIP]));
	}
	if(get_string(cconfs[OPT_RESTOREPREFIX]))
	  logp("restoreprefix = %s\n", get_string(cconfs[OPT_RESTOREPREFIX]));
	if(get_string(cconfs[OPT_REGEX]))
		logp("regex = %s\n", get_string(cconfs[OPT_REGEX]));
	for(l=get_strlist(cconfs[OPT_INCEXCDIR]); l; l=l->next)
		if(l->flag) logp("include = %s\n", l->path);
}

int logw(struct asfd *asfd, struct conf **confs, const char *fmt, ...)
{
	int r=0;
	char buf[512]="";
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	if(asfd && asfd->as->doing_estimate) printf("\nWARNING: %s\n", buf);
	else
	{
		if(asfd) r=asfd->write_str(asfd, CMD_WARNING, buf);
		logp("WARNING: %s\n", buf);
	}
	va_end(ap);
	if(confs) cntr_add(get_cntr(confs[OPT_CNTR]), CMD_WARNING, 1);
	return r;
}

void log_and_send(struct asfd *asfd, const char *msg)
{
	logp("%s\n", msg);
	if(asfd && asfd->fd>0)
		asfd->write_str(asfd, CMD_ERROR, msg);
}

void log_and_send_oom(struct asfd *asfd, const char *function)
{
	char m[256]="";
        snprintf(m, sizeof(m), "out of memory in %s()\n", __func__);
        logp("%s", m);
        if(asfd && asfd->fd>0)
		asfd->write_str(asfd, CMD_ERROR, m);
}

void log_set_json(int value)
{
	json=value;
}

void log_oom_w(const char *func, const char *orig_func)
{
	logp("out of memory in %s, called from %s\n", __func__, func);
}

int log_incexcs_buf(const char *incexc)
{
	char *tok=NULL;
	char *copy=NULL;
	if(!incexc || !*incexc) return 0;
	if(!(copy=strdup_w(incexc, __func__)))
		return -1;
	if(!(tok=strtok(copy, "\n")))
	{
		logp("unable to parse server incexc\n");
		free_w(&copy);
		return -1;
	}
	do
	{
		logp("%s\n", tok);
	} while((tok=strtok(NULL, "\n")));
	free_w(&copy);
	return 0;
}
