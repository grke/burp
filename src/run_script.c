#include "burp.h"
#include "alloc.h"
#include "asfd.h"
#include "conf.h"
#include "fzp.h"
#include "forkchild.h"
#include "handy.h"
#include "log.h"
#include "strlist.h"
#include "run_script.h"

#ifndef HAVE_WIN32

static int log_script_output(struct asfd *asfd, struct fzp **fzp,
	struct conf **confs,
	int do_logp, int log_remote, int is_stderr, char **logbuf)
{
	char buf[256]="";
	if(!fzp || !*fzp) return 0;
	if(fzp_gets(*fzp, buf, sizeof(buf)))
	{
		if(logbuf && astrcat(logbuf, buf, __func__)) return -1;
		if(log_remote)
		{
			// logm and low will also log to stdout.
			if(is_stderr) logw(asfd, confs?get_cntr(confs):NULL,
				"%s", buf);
			else
				logm(asfd, confs, "%s", buf);
		}
		else
		{
			if(do_logp)
			{
				if(is_stderr)
					logp("WARNING: %s", buf);
				else
					logp("MESSAGE: %s", buf);
			}
			else
			{
				// logc does not print a prefix
				logc("%s", buf);
			}
		}
	}
	if(fzp_eof(*fzp)) fzp_close(fzp);
	return 0;
}

static int got_sigchld=0;
static int run_script_status=-1;

static void run_script_sigchld_handler(__attribute__ ((unused)) int sig)
{
	//printf("in run_script_sigchld_handler\n");
	got_sigchld=1;
	run_script_status=-1;
	waitpid(-1, &run_script_status, 0);
}

static int run_script_select(struct asfd *asfd,
	struct fzp **sout, struct fzp **serr,
	struct conf **confs, int do_logp, int log_remote, char **logbuf)
{
	int mfd=-1;
	fd_set fsr;
	struct timeval tval;
	int soutfd=fzp_fileno(*sout);
	int serrfd=fzp_fileno(*serr);
	// FIX THIS: convert to asfd?
	fzp_setlinebuf(*sout);
	fzp_setlinebuf(*serr);
	set_non_blocking(soutfd);
	set_non_blocking(serrfd);

	while(1)
	{
		mfd=-1;
		FD_ZERO(&fsr);
		if(*sout) add_fd_to_sets(soutfd, &fsr, NULL, NULL, &mfd);
		if(*serr) add_fd_to_sets(serrfd, &fsr, NULL, NULL, &mfd);
		tval.tv_sec=1;
		tval.tv_usec=0;
		if(select(mfd+1, &fsr, NULL, NULL, &tval)<0)
		{
			if(errno!=EAGAIN && errno!=EINTR)
			{
				logp("%s error: %s\n", __func__,
					strerror(errno));
				return -1;
			}
		}
		if(FD_ISSET(soutfd, &fsr))
		{
			if(log_script_output(asfd, sout, confs,
				do_logp, log_remote, 0, logbuf)) return -1;
		}
		if(FD_ISSET(serrfd, &fsr))
		{
			if(log_script_output(asfd, serr, confs,
				do_logp, log_remote, 1, logbuf)) return -1;
		}

		if(!*sout && !*serr && got_sigchld)
		{
			//fclose(*sout); *sout=NULL;
			//fclose(*serr); *serr=NULL;
			got_sigchld=0;
			return 0;
		}
	}

	// Never get here.
	return -1;
}

#endif

int run_script_to_buf(struct asfd *asfd,
	const char **args, struct strlist *userargs, struct conf **confs,
	int do_wait, int do_logp, int log_remote, char **logbuf)
{
	int a=0;
	int l=0;
	pid_t p;
	struct fzp *serr=NULL;
	struct fzp *sout=NULL;
	char *cmd[64]={ NULL };
	const int maxcmd = sizeof(cmd) / sizeof(cmd[0]);
	struct strlist *sl;
#ifndef HAVE_WIN32
	struct cntr *cntr=NULL;
	int s=0;
#endif
	if(!args || !args[0]) return 0;

	for(a=0; args[a] && l < (maxcmd - 1); a++) cmd[l++]=(char *)args[a];
	for(sl=userargs; sl && l < (maxcmd - 1); sl=sl->next) cmd[l++]=sl->path;
	cmd[l++]=NULL;

#ifndef HAVE_WIN32
	setup_signal(SIGCHLD, run_script_sigchld_handler);
#endif

	fflush(stdout); fflush(stderr);
	if(do_wait)
	{
		if((p=forkchild(NULL,
			&sout, &serr, cmd[0], cmd))==-1) return -1;
	}
	else
	{
		if((p=forkchild_no_wait(NULL,
			&sout, &serr, cmd[0], cmd))==-1) return -1;
		return 0;
	}
#ifdef HAVE_WIN32
	// My windows forkchild currently just executes, then returns.
	return 0;
#else
	s=run_script_select(asfd, &sout, &serr,
		confs, do_logp, log_remote, logbuf);

	// Set SIGCHLD back to default.
	setup_signal(SIGCHLD, SIG_DFL);

	if(s) return -1;

	if(confs) cntr=get_cntr(confs);

	if(WIFEXITED(run_script_status))
	{
		int ret=WEXITSTATUS(run_script_status);
		logp("%s returned: %d\n", cmd[0], ret);
		if(log_remote && confs && ret)
			logw(asfd, cntr, "%s returned: %d\n", cmd[0], ret);
		return ret;
	}
	else if(WIFSIGNALED(run_script_status))
	{
		logp("%s terminated on signal %d\n",
			cmd[0], WTERMSIG(run_script_status));
		if(log_remote && confs)
			logw(asfd, cntr, "%s terminated on signal %d\n",
				cmd[0], WTERMSIG(run_script_status));
	}
	else
	{
		logp("Strange return when trying to run %s\n", cmd[0]);
		if(log_remote && confs) logw(asfd, cntr,
			"Strange return when trying to run %s\n", cmd[0]);
	}
	return -1;
#endif
}

int run_script(struct asfd *asfd, const char **args, struct strlist *userargs,
	struct conf **confs, int do_wait, int do_logp, int log_remote)
{
	return run_script_to_buf(asfd, args, userargs, confs, do_wait,
		do_logp, log_remote, NULL /* do not save output to buffer */);
}
