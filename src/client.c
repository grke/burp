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
#include "autoupgrade_client.h"
#include "incexc_send_client.h"

#include <sys/types.h>

// Return 0 for OK, -1 for error, 1 for timer conditions not met.
static int maybe_check_timer(const char *phase1str, struct config *conf, int *resume)
{
	char rcmd;
	char *rdst=NULL;
	size_t rlen=0;
	int complen=0;

        if(async_write_str(CMD_GEN, phase1str)) return -1;

        if(async_read(&rcmd, &rdst, &rlen)) return -1;

        if(rcmd==CMD_GEN && !strcmp(rdst, "timer conditions not met"))
        {
                free(rdst);
                logp("Timer conditions on the server were not met\n");
                return 1;
        }
        else if(rcmd!=CMD_GEN)
        {
                logp("unexpected command from server: %c:%s\n", rcmd ,rdst);
                free(rdst);
                return -1;
        }

	if(!strncmp(rdst, "ok", 2))
		complen=3;
	else if(!strncmp(rdst, "resume", 6))
	{
		complen=7;
		*resume=1;
		logp("server wants to resume previous backup.\n");
	}
	else
	{
                logp("unexpected command from server: %c:%s\n", rcmd ,rdst);
                free(rdst);
                return -1;
	}
        // The server now tells us the compression level in the OK response.
        if(strlen(rdst)>3) conf->compression=atoi(rdst+complen);
        logp("Compression level: %d\n", conf->compression);

	return 0;
}

// Return 0 for OK, -1 for error, 1 for timer conditions not met.
static int do_backup_client(struct config *conf, int resume, int estimate, struct cntr *p1cntr, struct cntr *cntr)
{
	int ret=0;

	if(estimate)
		logp("do estimate client\n");
	else
		logp("do backup client\n");

#if defined(HAVE_WIN32)
	win32_enable_backup_privileges(1 /* ignore_errors */);
#endif
#if defined(WIN32_VSS)
	win32_start_vss(conf);
#endif

	// Scan the file system and send the results to the server.
	// Skip phase1 if the server wanted to resume.
	if(!ret && !resume) ret=backup_phase1_client(conf,
		estimate, p1cntr, cntr);

	// Now, the server will be telling us what data we need to send.
	if(!estimate && !ret)
		ret=backup_phase2_client(conf, p1cntr, resume, cntr);

	if(estimate)
		print_filecounters(p1cntr, cntr, ACTION_ESTIMATE, 1);

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
//	async_free();
	logp("exiting\n");
	exit(1);
}
*/

static void setup_signals_client(void)
{
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
	struct cntr p1cntr;

	reset_filecounter(&p1cntr);
	reset_filecounter(&cntr);

	setup_signals_client();
//	settimers(0, 100);
	logp("begin client\n");

	if(act!=ACTION_ESTIMATE)
	{
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
	}

	ret=async_init(rfd, ssl, conf, act==ACTION_ESTIMATE);

	if(!ret && act!=ACTION_ESTIMATE)
	{
		ret=authorise_client(conf, &p1cntr);

		if(async_write_str(CMD_GEN, "extra_comms_begin")
		  || async_read_expect(CMD_GEN, "extra_comms_begin ok"))
		{
			logp("Problem requesting extra_comms_begin\n");
			ret=-1;
		}

		// Can add extra bits here. The first extra bit is the
		// autoupgrade stuff.

		if(!ret && conf->autoupgrade_dir && conf->autoupgrade_os)
			ret=autoupgrade_client(conf, &p1cntr);

		if(!ret) ret=incexc_send_client(conf, &p1cntr);

		if(async_write_str(CMD_GEN, "extra_comms_end")
		  || async_read_expect(CMD_GEN, "extra_comms_end ok"))
		{
			logp("Problem requesting extra_comms_end\n");
			ret=-1;
		}
	}

	if(!ret)
	{
		rfd=-1;
		int resume=0;
		const char *phase1str="backupphase1";
		switch(act)
		{
			case ACTION_BACKUP_TIMED:
				phase1str="backupphase1timed";
			case ACTION_BACKUP:
			{
				if(!(ret=maybe_check_timer(phase1str,
					conf, &resume)))
				{
					if(conf->backup_script_pre
					 && run_script(
					  conf->backup_script_pre,
					  conf->backup_script_pre_arg,
					  conf->bprecount,
					  "pre",
					  "reserved2",
					  "reserved3",
					  "reserved4",
					  "reserved5",
					  &p1cntr, 1)) ret=-1;

					if(!ret && do_backup_client(conf,
						resume, 0, &p1cntr, &cntr))
							ret=-1;

					if((conf->backup_script_post_run_on_fail
					  || !ret) && conf->backup_script_post)
					{
					  if(run_script(
						conf->backup_script_post,
						conf->backup_script_post_arg,
					  	conf->bpostcount,
						"post",
					// Tell post script whether the restore
					// failed.
						ret?"1":"0",
						"reserved3",
						"reserved4",
						"reserved5",
						&cntr, 1)) ret=-1;
					}
				}

				if(ret<0)
					logp("error in backup\n");
				else if(ret>0)
				{ } // timer script said no.
				else
					logp("backup finished ok\n");
				
				break;
			}
			case ACTION_RESTORE:
			case ACTION_VERIFY:
			{
				if(conf->restore_script_pre
				   && run_script(
					conf->restore_script_pre,
					conf->restore_script_pre_arg,
					conf->rprecount,
					"pre",
					"reserved2",
					"reserved3",
					"reserved4",
					"reserved5",
					&cntr, 1)) ret=-1;
				if(!ret && do_restore_client(conf,
					act, backup,
					restoreprefix, regex, forceoverwrite,
					&p1cntr, &cntr)) ret=-1;
				if((conf->restore_script_post_run_on_fail
				  || !ret) && conf->restore_script_post)
				{
				   if(run_script(
					conf->restore_script_post,
					conf->restore_script_post_arg,
					conf->rpostcount,
					"post",
					// Tell post script whether the restore
					// failed.
					ret?"1":"0",
					"reserved3",
					"reserved4",
					"reserved5",
					&cntr, 1)) ret=-1;
				}

				// Return non-zero if there were warnings,
				// so that the test script can easily check.
				if(p1cntr.warning+cntr.warning)
					ret=1;

				break;
			}
			case ACTION_ESTIMATE:
				if(!ret) ret=do_backup_client(conf, 0, 1,
						&p1cntr, &cntr);
				break;
			case ACTION_LIST:
			case ACTION_LONG_LIST:
			default:
				ret=do_list_client(backup, regex, act);
				break;
		}
	}

	rfd=-1;
	async_free();
	if(act!=ACTION_ESTIMATE)
		ssl_destroy_ctx(ctx);

        //logp("end client\n");
	return ret;
}
