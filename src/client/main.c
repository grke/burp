#include "include.h"

#include "../legacy/client/restore.h"

#ifndef HAVE_WIN32
#include <sys/utsname.h>
#endif

// Return 0 for OK, -1 for error, 1 for timer conditions not met.
static int maybe_check_timer(enum action action, const char *phase1str, struct config *conf, int *resume)
{
	int complen=0;
	struct iobuf rbuf;
	iobuf_init(&rbuf);

        if(async_write_str(CMD_GEN, phase1str)) return -1;

        if(async_read(&rbuf)) return -1;

        if(rbuf.cmd!=CMD_GEN)
        {
		iobuf_log_unexpected(&rbuf, __FUNCTION__);
                return -1;
        }
        if(!strcmp(rbuf.buf, "timer conditions not met"))
        {
		iobuf_free_content(&rbuf);
                logp("Timer conditions on the server were not met\n");
                return 1;
        }
        else if(!strcmp(rbuf.buf, "timer conditions met"))
        {
		iobuf_free_content(&rbuf);
                logp("Timer conditions on the server were met\n");
		if(action==ACTION_TIMER_CHECK) return 0;
        }

	if(!strncmp(rbuf.buf, "ok", 2))
		complen=3;
	else if(!strncmp(rbuf.buf, "resume", 6))
	{
		complen=7;
		*resume=1;
		logp("server wants to resume previous backup.\n");
	}
	else
	{
		iobuf_log_unexpected(&rbuf, __FUNCTION__);
		iobuf_free_content(&rbuf);
                return -1;
	}
        // The server now tells us the compression level in the OK response.
        if(strlen(rbuf.buf)>3) conf->compression=atoi(rbuf.buf+complen);
        logp("Compression level: %d\n", conf->compression);

	return 0;
}

static int s_server_session_id_context=1;

static int backup_wrapper(enum action action, const char *phase1str, const char *incexc, int resume, long name_max, struct cntr *p1cntr, struct cntr *cntr, struct config *conf)
{
	int ret=0;
	// Set bulk packets quality of service flags on backup.
	if(incexc)
	{
		logp("Server is overriding the configuration\n");
		logp("with the following settings:\n");
		if(log_incexcs_buf(incexc))
		{
			ret=-1;
			goto end;
		}
	}
	if(!conf->startdir)
	{
		logp("Found no include paths!\n");
		ret=-1;
		goto end;
	}

	if(!(ret=maybe_check_timer(action, phase1str,
		conf, &resume)))
	{
		if(action==ACTION_TIMER_CHECK) goto end;
		
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
			if(run_script(args,
				conf->b_script_pre_arg,
				p1cntr, 1, 1)) ret=-1;
		}

		if(!ret && do_backup_client(conf, action, name_max, resume))
			ret=-1;

		if((conf->b_script_post_run_on_fail
		  || !ret) && conf->b_script_post)
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
			if(run_script(args,
				conf->b_script_post_arg,
				cntr, 1, 1)) ret=-1;
		}
	}

	if(ret<0)
		logp("error in backup\n");
	else if(ret>0)
	{
		// Timer script said no.
		// Have a distinct return value to differentiate between other
		// cases (ssl reconnection and restore/verify warnings).
		ret=3;
	}
	else
		logp("backup finished ok\n");

end:
	return ret;
}

/* May return 1 to mean try again. This happens after a successful certificate
   signing request so that it connects again straight away with the new
   key/certificate.
   Returns 2 if there were restore/verify warnings.
   Returns 3 if timer conditions were not met.
*/
static int do_client(struct config *conf, enum action action, int vss_restore, int json)
{
	int ret=0;
	int rfd=-1;
	int resume=0;
	SSL *ssl=NULL;
	BIO *sbio=NULL;
	char buf[256]="";
	SSL_CTX *ctx=NULL;
	struct cntr cntr;
	struct cntr p1cntr;
	char *incexc=NULL;
	char *server_version=NULL;
	long name_max=0;

	conf->p1cntr=&p1cntr;
	conf->cntr=&cntr;
	reset_filecounters(conf, time(NULL));

//	settimers(0, 100);
	logp("begin client\n");

	if(action!=ACTION_ESTIMATE)
	{
		ssl_load_globals();
		if(!(ctx=ssl_initialise_ctx(conf)))
		{
			logp("error initialising ssl ctx\n");
			ret=-1;
			goto end;
		}

		SSL_CTX_set_session_id_context(ctx,
			(const unsigned char *)&s_server_session_id_context,
			sizeof(s_server_session_id_context));

		if((rfd=init_client_socket(conf->server, conf->port))<0)
		{
			ret=-1;
			goto end;
		}

		if(!(ssl=SSL_new(ctx))
		  || !(sbio=BIO_new_socket(rfd, BIO_NOCLOSE)))
		{
			ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
			logp("Problem joining SSL to the socket: %s\n", buf);
			ret=-1;
			goto end;
		}
		SSL_set_bio(ssl, sbio, sbio);
		if(SSL_connect(ssl)<=0)
		{
			ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
			logp("SSL connect error: %s\n", buf);
			ret=-1;
			goto end;
		}
	}

	if((ret=async_init(rfd, ssl, conf, action==ACTION_ESTIMATE)))
		goto end;

	// Set quality of service bits on backup packets.
	if(action==ACTION_BACKUP
	  || action==ACTION_BACKUP_TIMED
	  || action==ACTION_TIMER_CHECK)
		set_bulk_packets();

	if(action!=ACTION_ESTIMATE)
	{
		int ca_ret=0;
		if((ret=authorise_client(conf, &server_version)))
			goto end;

		if(server_version)
		{
			logp("Server version: %s\n", server_version);
			// Servers before 1.3.2 did not tell us their versions.
			// 1.3.2 and above can do the automatic CA stuff that
			// follows.
			if((ca_ret=ca_client_setup(conf))<0)
			{
				// Error
				logp("Error with certificate signing request\n");
				ret=-1;
				goto end;
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

		if((ret=ssl_check_cert(ssl, conf)))
		{
			logp("check cert failed\n");
			goto end;
		}

		if((ret=extra_comms(conf, &action, &incexc, &name_max)))
		{
			logp("extra comms failed\n");
			goto end;
		}
	}

	rfd=-1;
	switch(action)
	{
		case ACTION_BACKUP:
			ret=backup_wrapper(action, "backupphase1",
			  incexc, resume, name_max, &p1cntr, &cntr, conf);
			break;
		case ACTION_BACKUP_TIMED:
			ret=backup_wrapper(action, "backupphase1timed",
			  incexc, resume, name_max, &p1cntr, &cntr, conf);
			break;
		case ACTION_TIMER_CHECK:
			ret=backup_wrapper(action, "backupphase1timedcheck",
			  incexc, resume, name_max, &p1cntr, &cntr, conf);
			break;
		case ACTION_RESTORE:
		case ACTION_VERIFY:
		{
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
				if(run_script(args, conf->r_script_pre_arg,
					&cntr, 1, 1)) ret=-1;
			}
			if(!ret)
			{
				// FIX THIS: Really need to abstract these
				// functions to be a single pointer.
				if(conf->protocol==PROTO_BURP1)
				{
					if(do_restore_client_legacy(conf,
						action, vss_restore)) ret=-1;
				}
				else
				{
					if(do_restore_client(conf,
						action, vss_restore)) ret=-1;
				}
			}
			if((conf->r_script_post_run_on_fail
			  || !ret) && conf->r_script_post)
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
				if(run_script(args,
					conf->r_script_post_arg,
					&cntr, 1, 1)) ret=-1;
			}

			// Return non-zero if there were warnings,
			// so that the test script can easily check.
			if(p1cntr.warning+cntr.warning)
				ret=2;

			break;
		}
		case ACTION_ESTIMATE:
			if(!ret) ret=do_backup_client(conf,
				action, name_max, 0);
			break;
		case ACTION_DELETE:
			if(!ret) ret=do_delete_client(conf);
			break;
		case ACTION_LIST:
		case ACTION_LONG_LIST:
		default:
			ret=do_list_client(conf, action, json);
			break;
	}

end:
	close_fd(&rfd);
	async_free();
	if(action!=ACTION_ESTIMATE) ssl_destroy_ctx(ctx);

	if(incexc) free(incexc);
	if(server_version) free(server_version);

        //logp("end client\n");
	return ret;
}

int client(struct config *conf, enum action action, int vss_restore, int json)
{
	int ret=0;
	
#ifdef HAVE_WIN32
	// prevent sleep when idle
	SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED);
#endif
	
	if((ret=do_client(conf, action, vss_restore, json))==1)
	{
		logp("Re-opening connection to server\n");
		sleep(5);
		ret=do_client(conf, action, vss_restore, json);
	}
	
#ifdef HAVE_WIN32
	// allow sleep when idle
	SetThreadExecutionState(ES_CONTINUOUS);
#endif
	
	return ret;
}
