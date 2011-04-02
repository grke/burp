#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "rs_buf.h"
#include "lock.h"
#include "handy.h"
#include "asyncio.h"
#include "counter.h"
#include "client_vss.h"
#include "auth_client.h"
#include "backup_phase1_client.h"
#include "backup_phase2_client.h"
#include "restore_client.h"
#include "list_client.h"
#include "ssl.h"
#include "berrno.h"
#include "forkchild.h"

// Return 0 for OK, -1 for error, 1 for timer conditions not met.
static int maybe_check_timer(const char *phase1str)
{
	char rcmd;
	char *rdst=NULL;
	size_t rlen=0;

        if(async_write_str('c', phase1str)) return -1;

        if(async_read(&rcmd, &rdst, &rlen)) return -1;

        if(rcmd=='c' && !strcmp(rdst, "timer conditions not met"))
        {
                free(rdst);
                logp("Timer conditions not met.\n");
                return 1;
        }
        else if(rcmd!='c' || strcmp(rdst, "ok"))
        {
                logp("unexpected command from server: %c:%s\n", rcmd ,rdst);
                free(rdst);
                return -1;
        }
	return 0;
}

static void log_script_output(const char *str, FILE **fp, struct cntr *cntr)
{
	char buf[256]="";
	if(fp && *fp)
	{
		while(fgets(buf, sizeof(buf), *fp))
		logp("%s%s", str, buf);
		//logw(cntr, "%s%s", str, buf);
		if(feof(*fp))
		{
			fclose(*fp);
			*fp=NULL;
		}
	}
}

static int run_script(const char *script, struct cntr *cntr)
{
	int a=0;
	int l=0;
	pid_t p;
	int pid_status=0;
	FILE *serr=NULL;
	FILE *sout=NULL;
	char *cmd[2]={ NULL };

	logp("run script: %s\n", script);

	if(!script) return 0;

	cmd[l++]=(char *)script;
	cmd[l++]=NULL;

	fflush(stdout); fflush(stderr);
	if((p=forkchild(NULL, &sout, &serr, cmd[0], cmd))==-1) return -1;
#ifdef HAVE_WIN32
	// My windows forkchild currently just executes, then returns.
	return 0;
#endif
	do {
		log_script_output("", &sout, cntr);
		log_script_output("", &serr, cntr);
	} while(!(a=waitpid(p, &pid_status, WNOHANG)));
	log_script_output("", &sout, cntr);
	log_script_output("", &serr, cntr);

	if(a<0)
	{
		logp("%s: waitpid error: %s\n", cmd[0], strerror(errno));
		logw(cntr, "%s: waitpid error: %s\n", cmd[0], strerror(errno));
		return -1;
	}

	if(WIFEXITED(pid_status))
	{
		int ret=WEXITSTATUS(pid_status);
		logp("Script '%s' returned: %d\n", cmd[0], ret);
		if(ret) logw(cntr, "Script '%s' returned: %d\n", cmd[0], ret);
		return ret;
	}
	else if(WIFSIGNALED(pid_status))
	{
		logp("%s terminated on signal %s\n",
			cmd[0], WTERMSIG(pid_status));
		logw(cntr, "%s terminated on signal %s\n",
			cmd[0], WTERMSIG(pid_status));
	}
	else
	{
		logp("%s: strange return\n", cmd[0]);
		logw(cntr, "%s: strange return\n", cmd[0]);
	}

	return -1;
}

// Return 0 for OK, -1 for error, 1 for timer conditions not met.
static int do_backup_client(struct config *conf, const char *phase1str, struct cntr *cntr)
{
	int ret=0;

logp("do backup client\n");

#if defined(HAVE_WIN32)
	win32_enable_backup_privileges(1 /* ignore_errors */);
#endif
#if defined(WIN32_VSS)
	win32_start_vss(conf);
#endif

	// Scan the file system and send the results to the server.
	if(!ret) ret=backup_phase1_client(conf, cntr);

	// Now, the server will be telling us what data we need to send.
	if(!ret) ret=backup_phase2_client(conf, cntr);

#if defined(WIN32_VSS)
	win32_stop_vss();
#endif

	return ret;
}

/*
static void sighandler(int sig)
{
	logp("got signal: %d\n", sig);
	// Close the sockets properly so as to avoid annoying waits during
	// testing when I kill the server with a Ctrl-C and then get
	// 'unable to bind listening socket'.
	async_free();
	logp("exiting\n");
	exit(1);
}
*/

static void setup_signals(void)
{
	// Ignore SIGPIPE - we are careful with read and write return values.
#ifndef HAVE_WIN32
	//signal(SIGABRT, &sighandler);
	//signal(SIGTERM, &sighandler);
	//signal(SIGINT, &sighandler);
#endif
}

static int s_server_session_id_context=1;

int client(struct config *conf, enum action act, const char *backup, const char *restoreprefix, const char *regex, int forceoverwrite)
{
	int ret=0;
	int rfd=-1;
	SSL *ssl=NULL;
	BIO *sbio=NULL;
	SSL_CTX *ctx=NULL;
	struct cntr cntr;

	reset_filecounter(&cntr);

	setup_signals();
//	settimers(0, 100);
	logp("begin client\n");

	ssl_load_globals();
	if(!(ctx=ssl_initialise_ctx(conf)))
	{
		logp("error initialising ssl ctx\n");
		return -1;
	}

	SSL_CTX_set_session_id_context(ctx,
		(const unsigned char *)&s_server_session_id_context,
		sizeof(s_server_session_id_context));

	if((rfd=init_client_socket(conf->server, conf->port))<0) return 1;

	if(!(ssl=SSL_new(ctx))
	  || !(sbio=BIO_new_socket(rfd, BIO_NOCLOSE)))
	{
		logp("There was a problem joining ssl to the socket.\n");
		close_fd(&rfd);
		return 1;
	}
	SSL_set_bio(ssl, sbio, sbio);
	if(SSL_connect(ssl)<=0)
	{
		berr_exit("SSL connect error\n");
		close_fd(&rfd);
		return 1;
	}
	if(ssl_check_cert(ssl, conf))
	{
		logp("check cert failed\n");
		close_fd(&rfd);
		return 1;
	}
	set_non_blocking(rfd);

	if(!(ret=async_init(rfd, ssl))
	 && !(ret=authorise_client(conf)))
	{
		rfd=-1;
		const char *phase1str="backupphase1";
		switch(act)
		{
			case ACTION_BACKUP_TIMED:
				phase1str="backupphase1timed";
			case ACTION_BACKUP:
			{
				if(!(ret=maybe_check_timer(phase1str)))
				{
					if(conf->backup_script_pre
					 && run_script(conf->backup_script_pre,
						 &cntr)) ret=-1;

					if(!ret && do_backup_client(conf,
						"backupphase1", &cntr))
							ret=-1;
	
					if((conf->backup_script_post_run_on_fail
					  || !ret) && conf->backup_script_post)
					{
						if(run_script(
						  conf->backup_script_post,
						  &cntr)) ret=-1;
					}

				}

				if(ret<0) logp("error in backup\n");
				else logp("backup finished ok\n");
				
				break;
			}
			case ACTION_RESTORE:
			case ACTION_VERIFY:
			{
				if(conf->restore_script_pre
				   && run_script(conf->restore_script_pre,
					&cntr)) ret=-1;
				if(!ret && do_restore_client(conf,
					act, backup,
					restoreprefix, regex, forceoverwrite,
					&cntr)) ret=-1;
				if((conf->restore_script_post_run_on_fail
				  || !ret) && conf->restore_script_post)
				{
					if(run_script(
					  conf->restore_script_post, &cntr))
						ret=-1;
				}

				break;
			}
			case ACTION_LIST:
			case ACTION_LONG_LIST:
			default:
				ret=do_list_client(backup, regex, act);
				break;
		}
	}

	rfd=-1;
	async_free();
	ssl_destroy_ctx(ctx);

        //logp("end client\n");
	return ret;
}
