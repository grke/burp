#include "include.h"

#include "burp2/restore.h"

#ifndef HAVE_WIN32
#include <sys/utsname.h>
#endif

// These will also be used as the exit codes of the program and are therefore
// unsigned integers.
enum cliret
{
	CLIENT_OK=0,
	CLIENT_ERROR=1,
	CLIENT_RESTORE_WARNINGS=2,
	CLIENT_SERVER_TIMER_NOT_MET=3,
	// This one happens after a successful certificate signing request so
	// that it connects again straight away with the new key/certificate.
	CLIENT_RECONNECT=4
};

static enum cliret maybe_check_timer(struct asfd *asfd,
	enum action action, const char *phase1str,
	struct conf *conf, int *resume)
{
	int complen=0;
	struct iobuf *rbuf=asfd->rbuf;

        if(asfd->write_str(asfd, CMD_GEN, phase1str)) goto error;

        if(asfd->read(asfd)) goto error;

        if(rbuf->cmd!=CMD_GEN)
        {
		iobuf_free_content(rbuf);
		iobuf_log_unexpected(rbuf, __func__);
		goto error;
        }
        if(!strcmp(rbuf->buf, "timer conditions not met"))
        {
		iobuf_free_content(rbuf);
                logp("Timer conditions on the server were not met\n");
		goto timer_not_met;
        }
        else if(!strcmp(rbuf->buf, "timer conditions met"))
        {
		iobuf_free_content(rbuf);
                logp("Timer conditions on the server were met\n");
		if(action==ACTION_TIMER_CHECK) goto end;
        }

	if(!strncmp_w(rbuf->buf, "ok"))
		complen=3;
	else if(!strncmp_w(rbuf->buf, "resume"))
	{
		complen=7;
		*resume=1;
		logp("server wants to resume previous backup.\n");
	}
	else
	{
		iobuf_log_unexpected(rbuf, __func__);
		iobuf_free_content(rbuf);
		goto error;
	}
        // The server now tells us the compression level in the OK response.
        if(strlen(rbuf->buf)>3) conf->compression=atoi(rbuf->buf+complen);
        logp("Compression level: %d\n", conf->compression);

	iobuf_free_content(rbuf);
end:
	return CLIENT_OK;
error:
	return CLIENT_ERROR;
timer_not_met:
	return CLIENT_SERVER_TIMER_NOT_MET;
}

static enum cliret backup_wrapper(struct asfd *asfd,
	enum action action, const char *phase1str,
	const char *incexc, int resume, long name_max, struct conf *conf)
{
	enum cliret ret=CLIENT_OK;

	// Set bulk packets quality of service flags on backup.
	if(incexc)
	{
		logp("Server is overriding the configuration\n");
		logp("with the following settings:\n");
		if(log_incexcs_buf(incexc)) goto error;
	}
	if(!conf->startdir)
	{
		logp("Found no include paths!\n");
		goto error;
	}

	switch(maybe_check_timer(asfd, action, phase1str, conf, &resume))
	{
		case CLIENT_OK:
			if(action==ACTION_TIMER_CHECK) goto end;
			break;
		case CLIENT_SERVER_TIMER_NOT_MET:
			goto timer_not_met;
		default:
			goto error;
	}
		
	if(conf->b_script_pre)
	{
		int a=0;
		const char *args[12];
		args[a++]=conf->b_script_pre;
		args[a++]="pre";
		args[a++]="reserved2";
		args[a++]="reserved3";
		args[a++]="reserved4";
		args[a++]="reserved5";
		args[a++]=NULL;
		if(run_script(asfd,
			args, conf->b_script_pre_arg, conf, 1, 1, 1))
				 ret=CLIENT_ERROR;
	}

	if(ret==CLIENT_OK && do_backup_client(asfd,
		conf, action, name_max, resume)) ret=CLIENT_ERROR;

	if((ret==CLIENT_OK || conf->b_script_post_run_on_fail)
	  && conf->b_script_post)
	{
		int a=0;
		const char *args[12];
		args[a++]=conf->b_script_post;
		args[a++]="post";
		// Tell post script whether the restore
		// failed.
		args[a++]=ret?"1":"0";
		args[a++]="reserved3";
		args[a++]="reserved4";
		args[a++]="reserved5";
		args[a++]=NULL;
		if(run_script(asfd,
			args, conf->b_script_post_arg, conf, 1, 1, 1))
			ret=CLIENT_ERROR;
	}

	if(ret==CLIENT_OK) logp("backup finished ok\n");

end:
	return CLIENT_OK;
error:
	logp("error in backup\n");
	return CLIENT_ERROR;
timer_not_met:
	return CLIENT_SERVER_TIMER_NOT_MET;
}

static int s_server_session_id_context=1;

static int ssl_setup(int *rfd, SSL **ssl, SSL_CTX **ctx, struct conf *conf)
{
	BIO *sbio=NULL;
	char buf[256]="";
	ssl_load_globals();
	if(!(*ctx=ssl_initialise_ctx(conf)))
	{
		logp("error initialising ssl ctx\n");
		return -1;
	}

	SSL_CTX_set_session_id_context(*ctx,
		(const uint8_t *)&s_server_session_id_context,
		sizeof(s_server_session_id_context));

	if((*rfd=init_client_socket(conf->server, conf->port))<0)
		return -1;
	set_peer_env_vars(*rfd);

	if(!(*ssl=SSL_new(*ctx))
	  || !(sbio=BIO_new_socket(*rfd, BIO_NOCLOSE)))
	{
		ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
		logp("Problem joining SSL to the socket: %s\n", buf);
		return -1;
	}
	SSL_set_bio(*ssl, sbio, sbio);
	if(SSL_connect(*ssl)<=0)
	{
		ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
		logp("SSL connect error: %s\n", buf);
		return -1;
	}
	return 0;
}

static enum cliret initial_comms(struct async *as,
	enum action *action, char **incexc, long *name_max, 
	struct conf *conf)
{
	struct asfd *asfd;
	char *server_version=NULL;
	enum cliret ret=CLIENT_OK;
	asfd=as->asfd;

	if(authorise_client(asfd, conf, &server_version))
		goto error;

	if(server_version)
	{
		int ca_ret=0;
		logp("Server version: %s\n", server_version);
		// Servers before 1.3.2 did not tell us their versions.
		// 1.3.2 and above can do the automatic CA stuff that
		// follows.
		if((ca_ret=ca_client_setup(asfd, conf))<0)
		{
			// Error
			logp("Error with certificate signing request\n");
			goto error;
		}
		else if(ca_ret>0)
		{
			// Certificate signed successfully.
			// Everything is OK, but we will reconnect now, in
			// order to use the new keys/certificates.
			goto reconnect;
		}
	}

	set_non_blocking(asfd->fd);

	if(ssl_check_cert(asfd->ssl, conf))
	{
		logp("check cert failed\n");
		goto error;
	}

	if(extra_comms(as, conf, action, incexc, name_max))
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
	if(server_version) free(server_version);
	return ret;
}

static enum cliret restore_wrapper(struct asfd *asfd, enum action action,
	int vss_restore, struct conf *conf)
{
	enum cliret ret=CLIENT_OK;

	if(conf->r_script_pre)
	{
		int a=0;
		const char *args[12];
		args[a++]=conf->r_script_pre;
		args[a++]="pre";
		args[a++]="reserved2";
		args[a++]="reserved3";
		args[a++]="reserved4";
		args[a++]="reserved5";
		args[a++]=NULL;
		if(run_script(asfd, args,
			conf->r_script_pre_arg, conf, 1, 1, 1))
				ret=CLIENT_ERROR;
	}
	if(ret==CLIENT_OK)
	{
		if(do_restore_client(asfd, conf,
			action, vss_restore)) ret=CLIENT_ERROR;
	}
	if((ret==CLIENT_OK || conf->r_script_post_run_on_fail)
	  && conf->r_script_post)
	{
		int a=0;
		const char *args[12];
		args[a++]=conf->r_script_pre;
		args[a++]="post";
		// Tell post script whether the restore
		// failed.
		args[a++]=ret?"1":"0";
		args[a++]="reserved3";
		args[a++]="reserved4";
		args[a++]="reserved5";
		args[a++]=NULL;
		if(run_script(asfd, args,
			conf->r_script_post_arg, conf, 1, 1, 1))
				ret=CLIENT_ERROR;
	}

	// Return non-zero if there were warnings,
	// so that the test script can easily check.
	if(conf->cntr->ent[CMD_WARNING]->count)
		ret=CLIENT_RESTORE_WARNINGS;

	return ret;
}

static enum cliret do_client(struct conf *conf,
	enum action action, int vss_restore, int json)
{
	enum cliret ret=CLIENT_OK;
	int rfd=-1;
	int resume=0;
	SSL *ssl=NULL;
	SSL_CTX *ctx=NULL;
	struct cntr *cntr=NULL;
	char *incexc=NULL;
	long name_max=0;
	enum action act=action;
	struct async *as=NULL;
	struct asfd *asfd=NULL;

//	as->settimers(0, 100);

	logp("begin client\n");

	if(!(cntr=cntr_alloc()) || cntr_init(cntr, conf->cname)) goto error;
	conf->cntr=cntr;

	if(act!=ACTION_ESTIMATE
	  && ssl_setup(&rfd, &ssl, &ctx, conf))
		goto error;

	if(!(as=async_alloc())
	  || !(asfd=asfd_alloc())
	  || as->init(as, act==ACTION_ESTIMATE)
	  || asfd->init(asfd, "main socket", as, rfd, ssl, conf))
		goto end;
	as->asfd_add(as, asfd);

	// Set quality of service bits on backup packets.
	if(act==ACTION_BACKUP
	  || act==ACTION_BACKUP_TIMED
	  || act==ACTION_TIMER_CHECK)
		as->asfd->set_bulk_packets(as->asfd);

	if(act!=ACTION_ESTIMATE)
	{
		if((ret=initial_comms(as, &act, &incexc, &name_max, conf)))
			goto end;
	}

	rfd=-1;
	switch(act)
	{
		case ACTION_BACKUP:
			ret=backup_wrapper(asfd, act, "backupphase1",
			  incexc, resume, name_max, conf);
			break;
		case ACTION_BACKUP_TIMED:
			ret=backup_wrapper(asfd, act, "backupphase1timed",
			  incexc, resume, name_max, conf);
			break;
		case ACTION_TIMER_CHECK:
			ret=backup_wrapper(asfd, act, "backupphase1timedcheck",
			  incexc, resume, name_max, conf);
			break;
		case ACTION_RESTORE:
		case ACTION_VERIFY:
			ret=restore_wrapper(asfd, act, vss_restore, conf);
			break;
		case ACTION_ESTIMATE:
			if(do_backup_client(asfd, conf, act, name_max, 0))
				goto error;
			break;
		case ACTION_DELETE:
			if(do_delete_client(asfd, conf)) goto error;
			break;
		case ACTION_LIST:
		case ACTION_LONG_LIST:
		default:
			if(do_list_client(asfd, conf, act, json)) goto error;
			break;
	}

	goto end;
error:
	ret=CLIENT_ERROR;
end:
	close_fd(&rfd);
	async_free(&as);
	asfd_free(&asfd);
	if(ctx) ssl_destroy_ctx(ctx);
	if(incexc) free(incexc);
	conf->cntr=NULL;
	if(cntr) cntr_free(&cntr);

        //logp("end client\n");
	return ret;
}

int client(struct conf *conf, enum action action, int vss_restore, int json)
{
	enum cliret ret=CLIENT_OK;
	
#ifdef HAVE_WIN32
	// prevent sleep when idle
	SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED);
#endif
	
	switch((ret=do_client(conf, action, vss_restore, json)))
	{
		case CLIENT_RECONNECT:
			logp("Re-opening connection to server\n");
			sleep(5);
			ret=do_client(conf, action, vss_restore, json);
		default:
			break;
	}
	
#ifdef HAVE_WIN32
	// allow sleep when idle
	SetThreadExecutionState(ES_CONTINUOUS);
#endif

	// See enum cliret for return codes.
	return (int)ret;
}
