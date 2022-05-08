#include "burp.h"
#include "alloc.h"
#include "asfd.h"
#include "async.h"
#include "cmd.h"
#include "cntr.h"
#include "iobuf.h"
#include "log.h"
#include "strlist.h"
#include "times.h"

const char *prog="unknown";
const char *prog_long="unknown";

static struct fzp *logfzp=NULL;
// Start with all logging on, so that something is said when initial startup
// goes wrong - for example, reading the conf file.
static int do_syslog=1;
static int do_stdout=1;
static int do_progress_counter=1;
static int syslog_opened=0;
static int json=0;

void log_init(char *progname)
{
	prog_long=progname;
	if((prog=strrchr(progname, '/'))) prog++;
	else prog=progname;
}

void logp(const char *fmt, ...)
{
#ifndef UTEST
	int pid;
	char buf[512]="";
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	pid=(int)getpid();
	if(logfzp)
		fzp_printf(logfzp, "%s: %s[%d] %s",
			gettimenow(), prog, pid, buf);
	else
	{
		if(do_syslog)
		{
#ifndef HAVE_WIN32
			syslog(LOG_INFO, "%s", buf);
#endif
		}
		if(do_stdout)
		{
			if(json)
			{
				char *cp;
				// To help programs parsing the monitor output,
				// log things with simple JSON.
				// So do simple character substitution to have
				// a better chance of valid JSON.
				for(cp=buf; *cp; cp++)
				{
					if(*cp=='"')
						*cp='\'';
					else if(!isprint(*cp))
						*cp='.';
				}
				fprintf(stdout, "{ \"logline\": \"%s\" }\n", buf);
			}
			else
				fprintf(stdout, "%s: %s[%d] %s",
					gettimenow(), prog, pid, buf);
		}
	}
	va_end(ap);
#endif
}

void logp_ssl_err(const char *fmt, ...)
{
	char buf[512]="";
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	logp("%s", buf);
	if(logfzp) fzp_ERR_print_errors_fp(logfzp);
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
	if(logfzp)
		fzp_printf(logfzp, "%s", buf); // for the server side
	else
	{
		if(do_progress_counter
		  && do_stdout)
			fprintf(stdout, "%s", buf);
	}
	va_end(ap);
}

void logfmt(const char *fmt, ...)
{
#ifndef UTEST
	if(do_stdout)
	{
		char buf[512]="";
		va_list ap;
		va_start(ap, fmt);
		vsnprintf(buf, sizeof(buf), fmt, ap);
		fprintf(stdout, "%s", buf);
	}
#endif
}

const char *progname(void)
{
	return prog;
}

int log_fzp_set(const char *path, struct conf **confs)
{
	fzp_close(&logfzp);
	if(path)
	{
		logp("Logging to %s\n", path);
		if(!(logfzp=fzp_open(path, "ab"))) return -1;
	}
	if(logfzp) fzp_setlinebuf(logfzp);
	do_syslog=get_int(confs[OPT_SYSLOG]);
	do_stdout=get_int(confs[OPT_STDOUT]);
	do_progress_counter=get_int(confs[OPT_PROGRESS_COUNTER]);

	if(syslog_opened)
	{
#ifndef HAVE_WIN32
		closelog();
#endif
		syslog_opened=0;
	}
	if(do_syslog)
	{
#ifndef HAVE_WIN32
		openlog(prog, LOG_PID, LOG_USER);
#endif
		syslog_opened++;
	}
	return 0;
}

void log_fzp_set_direct(struct fzp *fzp)
{
	fzp_close(&logfzp);
	logfzp=fzp;
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
		logp("orig_client = '%s'\n",
			get_string(cconfs[OPT_ORIG_CLIENT]));
	if(get_string(cconfs[OPT_BACKUP]))
		logp("backup = '%s'\n",
			get_string(cconfs[OPT_BACKUP]));
	logp("restore_list = %s\n",
		get_string(cconfs[OPT_RESTORE_LIST])?"true":"false");
	if(srestore)
	{
		// This are unknown unless doing a server initiated restore.
		logp("overwrite = %d\n", get_int(cconfs[OPT_OVERWRITE]));
		logp("strip = %d\n", get_int(cconfs[OPT_STRIP]));
	}
	if(get_string(cconfs[OPT_RESTOREPREFIX]))
		logp("restoreprefix = '%s'\n",
			get_string(cconfs[OPT_RESTOREPREFIX]));
	if(get_string(cconfs[OPT_STRIP_FROM_PATH]))
		logp("stripfrompath = '%s'\n",
			get_string(cconfs[OPT_STRIP_FROM_PATH]));
	if(get_string(cconfs[OPT_REGEX]))
		logp("regex = '%s'\n", get_string(cconfs[OPT_REGEX]));
	for(l=get_strlist(cconfs[OPT_INCLUDE]); l; l=l->next)
		logp("include = '%s'\n", l->path);
}

int logm(struct asfd *asfd, struct conf **confs, const char *fmt, ...)
{
	int r=0;
	char buf[512]="";
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	if(asfd && asfd->as->doing_estimate) printf("\nMESSAGE: %s", buf);
	else
	{
		if(asfd
		  && get_int(confs[OPT_MESSAGE])) // Backwards compatibility
			r=asfd->write_str(asfd, CMD_MESSAGE, buf);
		logp("MESSAGE: %s", buf);
	}
	va_end(ap);
	if(confs) cntr_add(get_cntr(confs), CMD_MESSAGE, 1);
	return r;
}

int logw(struct asfd *asfd, struct cntr *cntr, const char *fmt, ...)
{
	int r=0;
	char buf[512]="";
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	if(asfd
	  && asfd->as
	  && asfd->as->doing_estimate)
		printf("\nWARNING: %s", buf);
	else
	{
		if(asfd)
			r=asfd->write_str(asfd, CMD_WARNING, buf);
		logp("WARNING: %s", buf);
	}
	va_end(ap);
	cntr_add(cntr, CMD_WARNING, 1);
	return r;
}

void log_and_send(struct asfd *asfd, const char *msg)
{
	logp("%s\n", msg);
	if(asfd)
		asfd->write_str(asfd, CMD_ERROR, msg);
}

void log_and_send_oom(struct asfd *asfd)
{
	char m[256]="";
        snprintf(m, sizeof(m), "out of memory in %s()\n", __func__);
        logp("%s", m);
        if(asfd)
		asfd->write_str(asfd, CMD_ERROR, m);
}

void log_set_json(int value)
{
	json=value;
}

void log_oom_w(const char *func, const char *orig_func)
{
	logp("out of memory in %s, called from %s\n", func, orig_func);
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

void log_recvd(struct iobuf *iobuf, struct cntr *cntr, int print)
{
	int l;
	const char *prefix="unset";
	switch(iobuf->cmd)
	{
		case CMD_MESSAGE: prefix="MESSAGE"; break;
		case CMD_WARNING: prefix="WARNING"; break;
		default: break;
	}
	// Strip any trailing newlines.
	for(l=iobuf->len-1; l>=0; l--)
	{
		if(iobuf->buf[l]!='\n')
			break;
		iobuf->buf[l]='\0';
	}
	logp("%s: %s\n", prefix, iobuf->buf);
	cntr_add(cntr, iobuf->cmd, print);
}
