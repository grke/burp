#include "include.h"

#include <sys/types.h>

static enum asl_ret maybe_check_timer_func(struct iobuf *rbuf,
        struct config *conf, void *param)
{
	int complen=0;
        if(!strcmp(rbuf->buf, "timer conditions not met"))
        {
                logp("Timer conditions on the server were not met\n");
		return ASL_END_OK_RETURN_1;
        }

	if(!strncmp(rbuf->buf, "ok", 2))
		complen=3;
	else
	{
		iobuf_log_unexpected(rbuf, __FUNCTION__);
		return ASL_END_ERROR;
	}
        // The server now tells us the compression level in the OK response.
        if(strlen(rbuf->buf)>3) conf->compression=atoi(rbuf->buf+complen);
        logp("Compression level: %d\n", conf->compression);
	return ASL_END_OK;
}

// Return 0 for OK, -1 for error, 1 for timer conditions not met.
static int maybe_check_timer(const char *backupstr, struct config *conf)
{
        if(async_write_str(CMD_GEN, backupstr))
		return -1;
	return async_simple_loop(conf, NULL, maybe_check_timer_func);
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

static int server_supports(const char *feat, const char *wanted)
{
	if(strstr(feat, wanted)) return 1;
	return 0;
}

static int server_supports_autoupgrade(const char *feat)
{
	// 1.3.0 servers did not list the features, but the only feature
	// that was supported was autoupgrade.
	if(!strcmp(feat, "extra_comms_begin ok")) return 1;
	return server_supports(feat, ":autoupgrade:");
}

// Servers greater than 1.3.0 will list the extra_comms features they support.
static enum asl_ret comms_func(struct iobuf *rbuf,
        struct config *conf, void *param)
{
	char *incexc=NULL;
	enum asl_ret ret=ASL_END_ERROR;
	enum action *action=(enum action *)param;

	if(strncmp(rbuf->buf,
	  "extra_comms_begin ok", strlen("extra_comms_begin ok")))
	{
		iobuf_log_unexpected(rbuf, __FUNCTION__);
		goto end;
	}

	// Can add extra bits here. The first extra bit is the
	// autoupgrade stuff.

	if(server_supports_autoupgrade(rbuf->buf))
	{
		if(conf->autoupgrade_dir && conf->autoupgrade_os
		  && autoupgrade_client(conf))
			goto end;
	}

	// :srestore: means that the server wants to do a restore.
	if(server_supports(rbuf->buf, ":srestore:"))
	{
		if(conf->server_can_restore)
		{
			logp("Server is initiating a restore\n");
			if(incexc_recv_client_restore(&incexc, conf))
				goto end;
			if(incexc)
			{
				if(parse_incexcs_buf(conf, incexc))
					goto end;
				*action=ACTION_RESTORE;
				log_restore_settings(conf, 1);
			}
		}
		else
		{
			logp("Server wants to initiate a restore\n");
			logp("Client configuration says no\n");
			if(async_write_str(CMD_GEN, "srestore not ok"))
				goto end;
		}
	}

	if(conf->orig_client)
	{
		char str[512]="";
		snprintf(str, sizeof(str),
			"orig_client=%s", conf->orig_client);
		if(!server_supports(rbuf->buf, ":orig_client:"))
		{
			logp("Server does not support switching client.\n");
			goto end;
		}
		if(async_write_str(CMD_GEN, str)
		  || async_read_expect(CMD_GEN, "orig_client ok"))
		{
			logp("Problem requesting %s\n", str);
			goto end;
		}
		logp("Switched to client %s\n", conf->orig_client);
	}

	// :sincexc: is for the server giving the client the
	// incexc config.
	if(*action==ACTION_BACKUP
	  || *action==ACTION_BACKUP_TIMED)
	{
		if(!incexc && server_supports(rbuf->buf, ":sincexc:"))
		{
			if(incexc_recv_client(&incexc, conf)
			  || parse_incexcs_buf(conf, incexc))
				goto end;
			logp("Server is overriding the configuration\n");
			logp("with the following settings:\n");
			if(log_incexcs_buf(incexc)) goto end;
		}
	}

	if(server_supports(rbuf->buf, ":counters:"))
	{
		if(async_write_str(CMD_GEN, "countersok"))
			goto end;
		conf->send_client_counters=1;
	}

	// :incexc: is for the client sending the server the
	// incexc config so that it better knows what to do on
	// resume.
	if(server_supports(rbuf->buf, ":incexc:")
	  && incexc_send_client(conf))
		goto end;

	if(*action==ACTION_RESTORE)
	{
		// Client may have a temporary directory for restores.
		if(conf->restore_spool)
		{
			char str[512]="";
			snprintf(str, sizeof(str),
			  "restore_spool=%s", conf->restore_spool);
			if(async_write_str(CMD_GEN, str))
				goto end;
		}
	}

	ret=ASL_END_OK;
end:
	if(incexc) free(incexc);
	return ret;
}

// Returns -1 for error, 0 for OK, 1 for certificate signed.
static int comms(int rfd, SSL *ssl, char **server_version,
	enum action *action, struct config *conf)
{
	int ret=0;
	int ca_ret=0;

	if(authorise_client(conf, server_version)) goto error;

	if(*server_version)
	{
		logp("Server version: %s\n", *server_version);
		// Servers before 1.3.2 did not tell us their versions.
		// 1.3.2 and above can do the automatic CA stuff that
		// follows.
		if((ca_ret=ca_client_setup(conf))<0)
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
			ret=1;
			goto end;
		}
	}

	set_non_blocking(rfd);

	if(ssl_check_cert(ssl, conf))
	{
		logp("check cert failed\n");
		goto error;
	}

	if(async_write_str(CMD_GEN, "extra_comms_begin"))
	{
		logp("Problem requesting extra_comms_begin\n");
		goto error;
	}

	if(async_simple_loop(conf, action, comms_func))
		goto error;

	if(async_write_str(CMD_GEN, "extra_comms_end")
	  || async_read_expect(CMD_GEN, "extra_comms_end ok"))
	{
		logp("Problem requesting extra_comms_end\n");
		goto error;
	}

	goto end;
error:
	ret=-1;
end:
	return ret;
}

static int s_server_session_id_context=1;

/* May return 1 to mean try again. This happens after a successful certificate
   signing request so that it connects again straight away with the new
   key/certificate.
   Returns 2 if there were restore/verify warnings.
   Returns 3 if timer conditions were not met.
*/
static int do_client(struct config *conf, enum action act, int vss_restore, int json)
{
	int ret=0;
	int rfd=-1;
	SSL *ssl=NULL;
	BIO *sbio=NULL;
	char buf[256]="";
	SSL_CTX *ctx=NULL;
	struct cntr cntr;
	struct cntr p1cntr;
	char *server_version=NULL;
	const char *backupstr="backup";
	enum action action=act;

	conf->p1cntr=&p1cntr;
	conf->cntr=&cntr;
	reset_filecounters(conf, time(NULL));

	setup_signals_client();
//	settimers(0, 100);
	logp("begin client\n");

	if(action!=ACTION_ESTIMATE)
	{
		ssl_load_globals();
		if(!(ctx=ssl_initialise_ctx(conf)))
		{
			logp("error initialising ssl ctx\n");
			goto error;
		}

		SSL_CTX_set_session_id_context(ctx,
			(const unsigned char *)&s_server_session_id_context,
			sizeof(s_server_session_id_context));

		if((rfd=init_client_socket(conf->server, conf->port))<0)
			goto error;

		if(!(ssl=SSL_new(ctx))
		  || !(sbio=BIO_new_socket(rfd, BIO_NOCLOSE)))
		{
			ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
			logp("Problem joining SSL to the socket: %s\n", buf);
			goto error;
		}
		SSL_set_bio(ssl, sbio, sbio);
		if(SSL_connect(ssl)<=0)
		{
			ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
			logp("SSL connect error: %s\n", buf);
			goto error;
		}
	}

	if(async_init(rfd, ssl, conf, action==ACTION_ESTIMATE))
		goto error;

	// Set quality of service bits on backup packets.
	if(action==ACTION_BACKUP || action==ACTION_BACKUP_TIMED)
		set_bulk_packets();

	if(action!=ACTION_ESTIMATE)
	{
		// Returns -1 for error, 0 for OK, 1 for certificate signed.
		if((ret=comms(rfd, ssl, &server_version, &action, conf)))
			goto end;
	}

	rfd=-1;
	switch(action)
	{
		case ACTION_BACKUP_TIMED:
			backupstr="backup_timed";
		case ACTION_BACKUP:
		{
			int bret=0;
			if(!conf->sdcount)
			{
				logp("Found no include paths!\n");
				goto error;
			}

			if(!(bret=maybe_check_timer(backupstr, conf)))
			{
				if(conf->backup_script_pre)
				{
					int a=0;
					const char *args[12];
					args[a++]=conf->backup_script_pre;
					args[a++]="pre";
					args[a++]="reserved2";
					args[a++]="reserved3";
					args[a++]="reserved4";
					args[a++]="reserved5";
					args[a++]=NULL;
					if(run_script(args,
						conf->backup_script_pre_arg,
						conf->bprecount,
						conf->p1cntr, 1, 1)) bret=-1;
				}

				if(!bret && do_backup_client(conf, action))
					bret=-1;

				if((conf->backup_script_post_run_on_fail
				  || !bret) && conf->backup_script_post)
				{
					int a=0;
					const char *args[12];
					args[a++]=conf->backup_script_post;
					args[a++]="post";
					// Tell post script whether the restore
					// failed.
					args[a++]=bret?"1":"0";
					args[a++]="reserved3";
					args[a++]="reserved4";
					args[a++]="reserved5";
					args[a++]=NULL;
					if(run_script(args,
						conf->backup_script_post_arg,
						conf->bpostcount,
						conf->cntr, 1, 1)) bret=-1;
				}
			}

			if(ret<0)
			{
				logp("error in backup\n");
				goto error;
			}
			else if(ret>0)
			{
				// Timer script said no.
				// Have a distinct return value to
				// differentiate between other cases
				// (ssl reconnection and restore/verify
				// warnings).
				ret=3;
			}
			else
				logp("backup finished ok\n");
			
			break;
		}
		case ACTION_RESTORE:
		case ACTION_VERIFY:
		{
			int rret=0;
			if(conf->restore_script_pre)
			{
				int a=0;
				const char *args[12];
				args[a++]=conf->restore_script_pre;
				args[a++]="pre";
				args[a++]="reserved2";
				args[a++]="reserved3";
				args[a++]="reserved4";
				args[a++]="reserved5";
				args[a++]=NULL;
				if(run_script(args,
					conf->restore_script_pre_arg,
					conf->rprecount,
					conf->cntr, 1, 1)) rret=-1;
			}
			if(!rret && do_restore_client(conf,
				action, vss_restore)) rret=-1;
			if((conf->restore_script_post_run_on_fail
			  || !rret) && conf->restore_script_post)
			{
				int a=0;
				const char *args[12];
				args[a++]=conf->restore_script_pre;
				args[a++]="post";
				// Tell post script whether the restore
				// failed.
				args[a++]=rret?"1":"0";
				args[a++]="reserved3";
				args[a++]="reserved4";
				args[a++]="reserved5";
				args[a++]=NULL;
				if(run_script(args,
					conf->restore_script_post_arg,
					conf->rpostcount,
					conf->cntr, 1, 1)) rret=-1;
			}

			// Return non-zero if there were warnings,
			// so that the test script can easily check.
			if(conf->p1cntr->warning+conf->cntr->warning)
			{
				rret=2;
				goto end;
			}

			break;
		}
		case ACTION_ESTIMATE:
			if(do_backup_client(conf, action)) goto error;
			break;
		case ACTION_DELETE:
			if(do_delete_client(conf)) goto error;
			break;
		case ACTION_LIST:
		case ACTION_LONG_LIST:
		default:
			if(do_list_client(conf, action, json)) goto error;
			break;
	}

	goto end;
error:
	ret=-1;
end:
	close_fd(&rfd);
	async_free();
	if(action!=ACTION_ESTIMATE) ssl_destroy_ctx(ctx);

	if(server_version) free(server_version);

        //logp("end client\n");
	return ret;
}

int client(struct config *conf, enum action act, int vss_restore, int json)
{
	int ret=0;
	
#ifdef HAVE_WIN32
	// prevent sleep when idle
	SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED);
#endif
	
	if((ret=do_client(conf, act, vss_restore, json))==1)
	{
		logp("Re-opening connection to server\n");
		sleep(5);
		ret=do_client(conf, act, vss_restore, json);
	}
	
#ifdef HAVE_WIN32
	// allow sleep when idle
	SetThreadExecutionState(ES_CONTINUOUS);
#endif
	
	return ret;
}
