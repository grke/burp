#include "../burp.h"
#include "../conffile.h"
#include "../action.h"
#include "../asfd.h"
#include "../async.h"
#include "../cmd.h"
#include "../cntr.h"
#include "../fsops.h"
#include "../handy.h"
#include "../iobuf.h"
#include "../log.h"
#include "../run_script.h"
#include "auth.h"
#include "backup.h"
#include "ca.h"
#include "delete.h"
#include "extra_comms.h"
#include "list.h"
#include "monitor.h"
#include "find_logic.h"
#include "monitor/status_client_ncurses.h"
#include "protocol2/restore.h"
#include "restore.h"
#include "main.h"

#ifndef HAVE_WIN32
#include <sys/utsname.h>
#endif

// These will also be used as the exit codes of the program and are therefore
// unsigned integers.
// Remember to update the man page if you update these.
enum cliret
{
	CLIENT_OK=0,
	CLIENT_ERROR=1,
	CLIENT_RESTORE_WARNINGS=2,
	CLIENT_SERVER_TIMER_NOT_MET=3,
	CLIENT_COULD_NOT_CONNECT=4,
	CLIENT_SERVER_MAX_PARALLEL_BACKUPS=5,
	// This one happens after a successful certificate signing request so
	// that it connects again straight away with the new key/certificate.
	CLIENT_RECONNECT=100
};

struct tchk
{
	int resume;
	enum cliret ret;
};

static enum asl_ret maybe_check_timer_func(struct asfd *asfd,
	struct conf **confs, void *param)
{
	int complen=0;
	struct tchk *tchk=(struct tchk *)param;

	if(!strcmp(asfd->rbuf->buf, "max parallel backups"))
	{
		logp("Max parallel backups reached\n");
		tchk->ret=CLIENT_SERVER_MAX_PARALLEL_BACKUPS;
		return ASL_END_OK;
	} else if(!strcmp(asfd->rbuf->buf, "timer conditions not met"))
	{
		logp("Timer conditions on the server were not met\n");
		tchk->ret=CLIENT_SERVER_TIMER_NOT_MET;
		return ASL_END_OK;
	}
	else if(!strcmp(asfd->rbuf->buf, "timer conditions met"))
	{
		// Only happens on 'timer check only'.
		logp("Timer conditions on the server were met\n");
		tchk->ret=CLIENT_OK;
		return ASL_END_OK;
	}

	if(!strncmp_w(asfd->rbuf->buf, "ok"))
		complen=3;
	else if(!strncmp_w(asfd->rbuf->buf, "resume"))
	{
		complen=7;
		tchk->resume=1;
		logp("server wants to resume previous backup.\n");
	}
	else
	{
		iobuf_log_unexpected(asfd->rbuf, __func__);
		return ASL_END_ERROR;
	}

	// The server now tells us the compression level in the OK response.
	if(strlen(asfd->rbuf->buf)>3)
		set_int(confs[OPT_COMPRESSION], atoi(asfd->rbuf->buf+complen));
	logp("Compression level: %d\n",
		get_int(confs[OPT_COMPRESSION]));

	return ASL_END_OK;
}

static enum cliret maybe_check_timer(struct asfd *asfd,
	const char *phase1str, struct conf **confs, int *resume)
{
	struct tchk tchk;
	memset(&tchk, 0, sizeof(tchk));
	if(asfd->write_str(asfd, CMD_GEN, phase1str))
		return CLIENT_ERROR;

	if(asfd->simple_loop(asfd, confs, &tchk,
		__func__, maybe_check_timer_func)) return CLIENT_ERROR;
	*resume=tchk.resume;
	return tchk.ret;
}

static enum cliret backup_wrapper(struct asfd *asfd,
	enum action action, const char *phase1str,
	const char *incexc, struct conf **confs)
{
	int resume=0;
	enum cliret ret=CLIENT_OK;
	const char *b_script_pre=get_string(confs[OPT_B_SCRIPT_PRE]);
	const char *b_script_post=get_string(confs[OPT_B_SCRIPT_POST]);

	// Set bulk packets quality of service flags on backup.
	if(incexc)
	{
		logp("Server is overriding the configuration\n");
		logp("with the following settings:\n");
		if(log_incexcs_buf(incexc)) goto error;
	}
	if(!get_strlist(confs[OPT_STARTDIR]))
	{
		logp("Found no include paths!\n");
		goto error;
	}

	switch(maybe_check_timer(asfd, phase1str, confs, &resume))
	{
		case CLIENT_OK:
			if(action==ACTION_TIMER_CHECK) goto end;
			break;
		case CLIENT_SERVER_TIMER_NOT_MET:
			goto timer_not_met;
		case CLIENT_SERVER_MAX_PARALLEL_BACKUPS:
			goto max_parallel_backups;
		default:
			goto error;
	}

	if(b_script_pre)
	{
		int a=0;
		const char *args[12];
		args[a++]=b_script_pre;
		if(get_int(confs[OPT_B_SCRIPT_RESERVED_ARGS]))
		{
			args[a++]="pre";
			args[a++]="reserved2";
			args[a++]="reserved3";
			args[a++]="reserved4";
			args[a++]="reserved5";
		}
		args[a++]=NULL;
		if(run_script(asfd,
			args, get_strlist(confs[OPT_B_SCRIPT_PRE_ARG]),
			confs, 1, 1, 1))
				 ret=CLIENT_ERROR;

		if(get_int(confs[OPT_GLOB_AFTER_SCRIPT_PRE]))
		{
			if(reeval_glob(confs))
				ret=CLIENT_ERROR;
		}
	}

	if(ret==CLIENT_OK && do_backup_client(asfd,
		confs, action, resume)) ret=CLIENT_ERROR;

	if((ret==CLIENT_OK || get_int(confs[OPT_B_SCRIPT_POST_RUN_ON_FAIL]))
	  && b_script_post)
	{
		int a=0;
		const char *args[12];
		args[a++]=b_script_post;
		if(get_int(confs[OPT_B_SCRIPT_RESERVED_ARGS]))
		{
			args[a++]="post";
			// Tell post script whether the restore failed.
			args[a++]=ret?"1":"0";
			args[a++]="reserved3";
			args[a++]="reserved4";
			args[a++]="reserved5";
		}
		args[a++]=NULL;
		// At this point, the server may have closed the connection,
		// so cannot log remotely.
		if(run_script(asfd,
			args, get_strlist(confs[OPT_B_SCRIPT_POST_ARG]),
			confs, 1, 1, /*log_remote*/ 0))
				ret=CLIENT_ERROR;
	}

	if(ret==CLIENT_OK) logp("backup finished ok\n");

end:
	// The include_logic/exclude_logic cache may have been populated
	// during backup so we clean it here
	free_logic_cache();
	return ret;
error:
	logp("error in backup\n");
	return CLIENT_ERROR;
timer_not_met:
	return CLIENT_SERVER_TIMER_NOT_MET;
max_parallel_backups:
	return CLIENT_SERVER_MAX_PARALLEL_BACKUPS;
}

static int s_server_session_id_context=1;

static int ssl_setup(int *rfd, SSL **ssl, SSL_CTX **ctx,
	enum action action, struct conf **confs, const char *server,
	struct strlist *failover)
{
	int ret=-1;
	int port=0;
	char portstr[8]="";
	BIO *sbio=NULL;
	ssl_load_globals();
	char *cp=NULL;
	char *server_copy=NULL;
	int ssl_ret;

	if(!(server_copy=strdup_w(server, __func__)))
		goto end;

	if(!(*ctx=ssl_initialise_ctx(confs)))
	{
		logp("error initialising ssl ctx\n");
		goto end;
	}

	if((cp=strrchr(server_copy, ':')))
	{
		*cp='\0';
		port=atoi(cp+1);
	}

	SSL_CTX_set_session_id_context(*ctx,
		(const uint8_t *)&s_server_session_id_context,
		sizeof(s_server_session_id_context));

	switch(action)
	{
		case ACTION_BACKUP:
		case ACTION_BACKUP_TIMED:
		case ACTION_TIMER_CHECK:
			if(get_int(confs[OPT_PORT_BACKUP]))
				port=get_int(confs[OPT_PORT_BACKUP]);
			break;
		case ACTION_RESTORE:
			if(get_int(confs[OPT_PORT_RESTORE]))
				port=get_int(confs[OPT_PORT_RESTORE]);
			break;
		case ACTION_VERIFY:
			if(get_int(confs[OPT_PORT_VERIFY]))
				port=get_int(confs[OPT_PORT_VERIFY]);
			break;
		case ACTION_LIST:
		case ACTION_LIST_LONG:
		case ACTION_LIST_PARSEABLE:
		case ACTION_DIFF:
		case ACTION_DIFF_LONG:
			if(get_int(confs[OPT_PORT_LIST]))
				port=get_int(confs[OPT_PORT_LIST]);
			break;
		case ACTION_DELETE:
			if(get_int(confs[OPT_PORT_DELETE]))
				port=get_int(confs[OPT_PORT_DELETE]);
			break;
		case ACTION_MONITOR:
		{
			struct strlist *s;
			if(!(s=get_strlist(confs[OPT_STATUS_PORT])))
			{
				logp("%s not set\n",
					confs[OPT_STATUS_PORT]->field);
				goto end;
			}
			port=atoi(s->path);
			break;
		}
		case ACTION_CHAMP_CHOOSER:
		case ACTION_ESTIMATE:
		case ACTION_STATUS:
		case ACTION_STATUS_SNAPSHOT:
		case ACTION_UNSET:
			logp("Unexpected action in %s: %d\n",
				__func__, action);
			goto end;
	}

	snprintf(portstr, sizeof(portstr), "%d", port);
	if((*rfd=init_client_socket(server_copy, portstr))<0)
		goto end;

	if(!(*ssl=SSL_new(*ctx))
	  || !(sbio=BIO_new_socket(*rfd, BIO_NOCLOSE)))
	{
		logp_ssl_err("Problem joining SSL to the socket\n");
		goto end;
	}
	SSL_set_bio(*ssl, sbio, sbio);
	if((ssl_ret=SSL_connect(*ssl))<=0)
	{
		logp_ssl_err("SSL connect error: %d\n",
			SSL_get_error(*ssl, ssl_ret));
		goto end;
	}

	ret=0;
end:
	free_w(&server_copy);
	return ret;
}

static enum cliret initial_comms(struct async *as,
	enum action *action, char **incexc, struct conf **confs,
	struct strlist *failover)
{
	struct asfd *asfd;
	char *server_version=NULL;
	enum cliret ret=CLIENT_OK;
	asfd=as->asfd;

	if(authorise_client(asfd, &server_version,
	  get_string(confs[OPT_CNAME]),
	  get_string(confs[OPT_PASSWORD]),
	  get_cntr(confs)))
		goto error;

	if(server_version)
	{
		logp("Server version: %s\n", server_version);
		// Servers before 1.3.2 did not tell us their versions.
		// 1.3.2 and above can do the automatic CA stuff that
		// follows.
		switch(ca_client_setup(asfd, confs))
		{
			case 0:
				break; // All OK.
			case 1:
				// Certificate signed successfully.
				// Everything is OK, but we will reconnect now,
				// in order to use the new keys/certificates.
				goto reconnect;
			default:
				logp("Error with cert signing request\n");
				goto error;
		}
	}

	if(ssl_check_cert(asfd->ssl, NULL, confs))
	{
		logp("check cert failed\n");
		goto error;
	}

	if(extra_comms_client(as, confs, action, failover, incexc))
	{
		logp("extra comms failed\n");
		goto error;
	}

	ret=CLIENT_OK; goto end;
error:
	ret=CLIENT_ERROR; goto end;
reconnect:
	ret=CLIENT_RECONNECT; goto end;
end:
	free_w(&server_version);
	return ret;
}

static enum cliret restore_wrapper(struct asfd *asfd, enum action action,
	struct conf **confs)
{
	enum cliret ret=CLIENT_OK;
	const char *r_script_pre=get_string(confs[OPT_R_SCRIPT_PRE]);
	const char *r_script_post=get_string(confs[OPT_R_SCRIPT_POST]);

	if(r_script_pre)
	{
		int a=0;
		const char *args[12];
		args[a++]=r_script_pre;
		if(get_int(confs[OPT_R_SCRIPT_RESERVED_ARGS]))
		{
			args[a++]="pre";
			args[a++]="reserved2";
			args[a++]="reserved3";
			args[a++]="reserved4";
			args[a++]="reserved5";
		}
		args[a++]=NULL;
		if(run_script(asfd,
			args, get_strlist(confs[OPT_R_SCRIPT_PRE_ARG]),
			confs, 1, 1, 1))
				ret=CLIENT_ERROR;
	}
	if(ret==CLIENT_OK)
	{
		if(do_restore_client(asfd, confs,
			action)) ret=CLIENT_ERROR;
	}
	if((ret==CLIENT_OK || get_int(confs[OPT_R_SCRIPT_POST_RUN_ON_FAIL]))
	  && r_script_post)
	{
		int a=0;
		const char *args[12];
		args[a++]=r_script_post;
		if(get_int(confs[OPT_R_SCRIPT_RESERVED_ARGS]))
		{
			args[a++]="post";
			// Tell post script whether the restore failed.
			args[a++]=ret?"1":"0";
			args[a++]="reserved3";
			args[a++]="reserved4";
			args[a++]="reserved5";
		}
		args[a++]=NULL;
		if(run_script(asfd,
			args, get_strlist(confs[OPT_R_SCRIPT_POST_ARG]),
			confs, 1, 1, /*log_remote*/ 0))
				ret=CLIENT_ERROR;
	}

	// Return non-zero if there were warnings,
	// so that the test script can easily check.
	if(ret==CLIENT_OK && get_cntr(confs)->ent[CMD_WARNING]->count)
		ret=CLIENT_RESTORE_WARNINGS;

	return ret;
}

static enum cliret do_client(struct conf **confs,
	enum action action, const char *server,
	struct strlist *failover)
{
	enum cliret ret=CLIENT_OK;
	int rfd=-1;
	SSL *ssl=NULL;
	SSL_CTX *ctx=NULL;
	struct cntr *cntr=NULL;
	char *incexc=NULL;
	enum action act=action;
	struct async *as=NULL;
	struct asfd *asfd=NULL;

//	as->settimers(0, 100);

//	logp("begin client\n");
//	logp("action %d\n", action);

	// Status monitor forks a child process instead of connecting to
	// the server directly.
	if(action==ACTION_STATUS
	  || action==ACTION_STATUS_SNAPSHOT)
	{
#ifdef HAVE_WIN32
		logp("Status mode not implemented on Windows.\n");
		goto error;
#endif
		if(status_client_ncurses_init(act)
		  || status_client_ncurses(confs)) ret=CLIENT_ERROR;
		goto end;
	}

	if(!(cntr=cntr_alloc())
	  || cntr_init(cntr, get_string(confs[OPT_CNAME]), getpid()))
		goto error;
	set_cntr(confs[OPT_CNTR], cntr);

	if(act!=ACTION_ESTIMATE)
	{
		if(ssl_setup(&rfd,
			&ssl, &ctx, action, confs, server, failover))
				goto could_not_connect;

		if(!(as=async_alloc())
		  || as->init(as, act==ACTION_ESTIMATE)
		  || !(asfd=setup_asfd_ssl(as, "main socket", &rfd, ssl)))
			goto end;
		asfd->set_timeout(asfd, get_int(confs[OPT_NETWORK_TIMEOUT]));
		asfd->ratelimit=get_float(confs[OPT_RATELIMIT]);

		// Set quality of service bits on backup packets.
		if(act==ACTION_BACKUP
				|| act==ACTION_BACKUP_TIMED
				|| act==ACTION_TIMER_CHECK)
			as->asfd->set_bulk_packets(as->asfd);

		if((ret=initial_comms(as, &act, &incexc, confs, failover)))
			goto end;
	}

	rfd=-1;
	switch(act)
	{
		case ACTION_BACKUP:
			ret=backup_wrapper(asfd, act, "backupphase1",
			  incexc, confs);
			break;
		case ACTION_BACKUP_TIMED:
			ret=backup_wrapper(asfd, act, "backupphase1timed",
			  incexc, confs);
			break;
		case ACTION_TIMER_CHECK:
			ret=backup_wrapper(asfd, act, "backupphase1timedcheck",
			  incexc, confs);
			break;
		case ACTION_RESTORE:
		case ACTION_VERIFY:
			ret=restore_wrapper(asfd, act, confs);
			break;
		case ACTION_ESTIMATE:
			if(do_backup_client(asfd, confs, act, 0))
				goto error;
			break;
		case ACTION_DELETE:
			if(do_delete_client(asfd, confs))
				goto error;
			break;
		case ACTION_MONITOR:
			if(do_monitor_client(asfd))
				goto error;
			break;
		case ACTION_DIFF:
		case ACTION_DIFF_LONG:
/*
			if(!strcmp(get_string(confs[OPT_BACKUP2]), "n"))
				// Do a phase1 scan and diff that.
				ret=backup_wrapper(asfd, act,
					"backupphase1diff", incexc, confs);
			else
*/
			// Diff two backups that already exist.
			// Fall through, the list code is all we need
			// for simple diffs on the client side.
		case ACTION_LIST:
		case ACTION_LIST_LONG:
		case ACTION_LIST_PARSEABLE:
		default:
			if(do_list_client(asfd, act, confs)) goto error;
			break;
	}

	if(asfd_flush_asio(asfd))
		ret=CLIENT_ERROR;

	goto end;
error:
	ret=CLIENT_ERROR; goto end;
could_not_connect:
	ret=CLIENT_COULD_NOT_CONNECT;
end:
	close_fd(&rfd);
	async_free(&as);
	asfd_free(&asfd);
	if(ctx) ssl_destroy_ctx(ctx);
	free_w(&incexc);
	set_cntr(confs[OPT_CNTR], NULL);
	cntr_free(&cntr);

	//logp("end client\n");
	return ret;
}

int client(struct conf **confs,
	enum action action)
{
	int finished=0;
	enum cliret ret=CLIENT_OK;
	const char *server=NULL;
	struct strlist *failover=NULL;

	if(!get_int(confs[OPT_ENABLED]))
	{
		logp("Client not enabled\n");
		return ret;
	}

#ifdef HAVE_WIN32
	// prevent sleep when idle
	SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED);
#endif
	server=get_string(confs[OPT_SERVER]);
	failover=get_strlist(confs[OPT_SERVER_FAILOVER]);

	while(!finished)
	{
		ret=do_client(confs,
			action, server, failover);
		if(ret==CLIENT_RECONNECT)
		{
			logp("Re-opening connection to %s\n", server);
			sleep(5);
			ret=do_client(confs,
				action, server, failover);
		}
		switch(ret)
		{
			case CLIENT_OK:
			case CLIENT_SERVER_TIMER_NOT_MET:
			case CLIENT_SERVER_MAX_PARALLEL_BACKUPS:
			case CLIENT_RESTORE_WARNINGS:
				finished=1;
				break;
			case CLIENT_ERROR:
				if(action!=ACTION_BACKUP
				  && action!=ACTION_BACKUP_TIMED)
				{
					finished=1;
					break;
				}
				if(!get_int(
					confs[OPT_FAILOVER_ON_BACKUP_ERROR]))
				{
					finished=1;
					break;
				}
				// Fall through to failover.
			case CLIENT_COULD_NOT_CONNECT:
				if(!failover)
				{
					finished=1;
					break;
				}
				logp("Failing over\n");
				// Use a failover server.
				server=failover->path;
				failover=failover->next;
				break;
			case CLIENT_RECONNECT:
				logp("Multiple reconnect requests to %s- this should not happen!", server);
				finished=1;
				break;
		}
	}

#ifdef HAVE_WIN32
	// allow sleep when idle
	SetThreadExecutionState(ES_CONTINUOUS);
#endif

	// See enum cliret for return codes.
	return (int)ret;
}
