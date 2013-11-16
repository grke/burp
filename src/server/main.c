#include "include.h"

#include <netdb.h>

static int sfd=-1; // status fd for the main server

static int hupreload=0;
static int hupreload_logged=0;
static int gentleshutdown=0;
static int gentleshutdown_logged=0;
static int sigchld=0;

static void huphandler(int sig)
{
	hupreload=1;
	// Be careful about not logging inside a signal handler.
	hupreload_logged=0;
}

static void usr2handler(int sig)
{
	gentleshutdown=1;
	// Be careful about not logging inside a signal handler.
	gentleshutdown_logged=0;
}

static int init_listen_socket(const char *port, int alladdr)
{
	int rfd;
	int gai_ret;
#ifdef HAVE_IPV6
	int no = 0;
	int sockopt_ret = 0;
#endif
	struct addrinfo hints;
	struct addrinfo *result=NULL;
	struct addrinfo *rp=NULL;

	memset(&hints, 0, sizeof(struct addrinfo));
#ifdef HAVE_IPV6
	hints.ai_family = AF_INET6;
#else
	hints.ai_family = AF_INET;
#endif /* HAVE_IPV6 */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = alladdr ? AI_PASSIVE : 0;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	if((gai_ret=getaddrinfo(NULL, port, &hints, &result)))
	{
		logp("unable to getaddrinfo on port %s: %s\n",
			port, gai_strerror(gai_ret));
		return -1;
	}

	for(rp=result; rp; rp=rp->ai_next)
	{
		rfd=socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(rfd<0)
		{
			logp("unable to create socket on port %s: %s\n",
				port, strerror(errno));
			continue;
		}
		if(!bind(rfd, rp->ai_addr, rp->ai_addrlen)) break;
		logp("unable to bind socket on port %s: %s\n",
			port, strerror(errno));
		close(rfd);
		rfd=-1;
	}
	if(!rp || rfd<0)
	{
		logp("unable to bind listening socket on port %s\n", port);
		return -1;
	}

#ifdef HAVE_IPV6
	if (rp->ai_family == AF_INET6) {
		sockopt_ret = setsockopt(rfd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
	}

	if(!sockopt_ret)
	{
		logp("unable to change socket option to "
			"listen on both IPv4 and IPv6\n");
		return -1;
	}
#endif

	freeaddrinfo(result);

	reuseaddr(rfd);

	// Say that we are happy to accept connections.
	if(listen(rfd, 5)<0)
	{
		close_fd(&rfd);
		logp("could not listen on main socket %d\n", port);
		return -1;
	}

#ifdef HAVE_WIN32
	{
		u_long ioctlArg=0;
		ioctlsocket(rfd, FIONBIO, &ioctlArg);
	}
#endif

	return rfd;
}

static void sigchld_handler(int sig)
{
	sigchld=1;
}

int setup_signals(int oldmax_children, int max_children, int oldmax_status_children, int max_status_children)
{
	// Ignore SIGPIPE - we are careful with read and write return values.
	signal(SIGPIPE, SIG_IGN);

	chld_setup(oldmax_children, max_children,
		oldmax_status_children, max_status_children);

	setup_signal(SIGCHLD, sigchld_handler);
	setup_signal(SIGHUP, huphandler);
	setup_signal(SIGUSR2, usr2handler);

	return 0;
}

/*
static int incexc_matches(const char *fullrealwork, const char *incexc)
{
	int ret=0;
	int got=0;
	FILE *fp=NULL;
	char buf[4096]="";
	const char *inc=NULL;
	char *old_incexc_path=NULL;
	if(!(old_incexc_path=prepend_s(fullrealwork, "incexc")))
			return -1;
	if(!(fp=open_file(old_incexc_path, "rb")))
	{
		// Assume that no incexc file could be found because the client
		// was on an old version. Assume resume is OK and return 1.
		ret=1;
		goto end;
	}
	inc=incexc;
	while((got=fread(buf, 1, sizeof(buf), fp))>0)
	{
		if(strlen(inc)<(size_t)got) break;
		if(strncmp(buf, inc, got)) break;
		inc+=got;
	}
	if(inc && strlen(inc)) ret=0;
	else ret=1;
end:
	close_fp(&fp);
	free(old_incexc_path);
	return ret;
}
*/

static int get_lock_w(struct sdirs *sdirs, char **gotlock)
{
	int ret=0;
	// Make sure the lock directory exists.
printf("before: %s %s\n", sdirs->lockfile, sdirs->lock);
	if(mkpath(&sdirs->lockfile, sdirs->lock))
	{
		async_write_str(CMD_ERROR, "problem with lock directory");
		return -1;
	}

	if(get_lock(sdirs->lockfile))
	{
		logp("another instance of client is already running,\n");
		logp("or %s is not writable.\n", sdirs->lockfile);
		async_write_str(CMD_ERROR, "another instance is already running");
		ret=-1;
	}
	else
	{
		if(*gotlock) free(*gotlock);
		if(!(*gotlock=strdup(sdirs->lockfile)))
		{
			log_out_of_memory(__FUNCTION__);
			ret=-1;
		}
	}

	return ret;
}

/* I am sure I wrote this function already, somewhere else. */
static int reset_conf_val(const char *src, char **dest)
{
	if(src)
	{
		if(*dest) free(*dest);
		if(!(*dest=strdup(src)))
		{
			log_out_of_memory(__FUNCTION__);
			return -1;
		}
	}
	return 0;
}

static char *get_restorepath(struct config *cconf, const char *client)
{
	char *tmp=NULL;
	char *restorepath=NULL;
	if(!(tmp=prepend_s(cconf->directory, client))
	 || !(restorepath=prepend_s(tmp, "restore")))
	{
		if(tmp) free(tmp);
		return NULL;
	}
	free(tmp);
	return restorepath;
}

static int client_can_restore(struct config *cconf, const char *client)
{
	struct stat statp;
	// If there is a restore file on the server, it is always OK.
	if(cconf->restore_path
	  && !lstat(cconf->restore_path, &statp))
	{
		// Remove the file.
		unlink(cconf->restore_path);
		return 1;
	}
	return cconf->client_can_restore;
}

static void maybe_do_notification(int status, const char *client, const char *clientdir, const char *storagedir, const char *filename, const char *brv, struct config *cconf)
{
	int a=0;
	const char *args[12];
	args[a++]=NULL; // Fill in the script name later.
	args[a++]=client;
	args[a++]=clientdir;
	args[a++]=storagedir;
	args[a++]=filename;
	args[a++]=brv;
	if(status)
	{
		args[0]=cconf->notify_failure_script;
		args[a++]="0";
		args[a++]=NULL;
		run_script(args, cconf->notify_failure_arg, cconf->nfcount,
			cconf->cntr, 1, 1);
	}
	else if((cconf->notify_success_warnings_only
		&& (cconf->p1cntr->warning+cconf->cntr->warning)>0)
	  || (cconf->notify_success_changes_only
		&& (cconf->cntr->total_changed>0))
	  || (!cconf->notify_success_warnings_only
		&& !cconf->notify_success_changes_only))
	{
		char warnings[32]="";
		snprintf(warnings, sizeof(warnings), "%llu",
			cconf->p1cntr->warning+cconf->cntr->warning);
		args[0]=cconf->notify_success_script;
		args[a++]=warnings;
		args[a++]=NULL;
		run_script(args, cconf->notify_success_arg, cconf->nscount,
			cconf->cntr, 1, 1);
	}
}

static int child(struct config *conf, struct config *cconf, const char *client, const char *cversion, const char *incexc, int srestore, struct iobuf *rbuf, char **gotlock, int *timer_ret)
{
	int ret=0;
	char msg[256]="";
	struct sdirs *sdirs=NULL;

	if(!(sdirs=sdirs_alloc())
	  || sdirs_init(sdirs, cconf, client))
		return -1;

	// Make sure some directories exist.
	if(mkpath(&sdirs->current, sdirs->dedup))
	{
		snprintf(msg, sizeof(msg),
			"could not mkpath %s", sdirs->current);
		log_and_send(msg);
		ret=-1;
		goto end;
	}
	
	if(rbuf->cmd==CMD_GEN
	  && !strncmp(rbuf->buf, "backup", strlen("backup")))
	{
		if(cconf->restore_client)
		{
			// This client is not the original client, so a
			// backup might cause all sorts of trouble.
			logp("Not allowing backup of %s\n", client);
			async_write_str(CMD_GEN, "Backup is not allowed");
			goto end;
		}

		// Set quality of service bits on backups.
		set_bulk_packets();
		if(get_lock_w(sdirs, gotlock))
			ret=-1;
		else
		{
			char okstr[32]="";
			if(!strcmp(rbuf->buf, "backup_timed"))
			{
				int a=0;
				const char *args[12];
				args[a++]=cconf->timer_script;
				args[a++]=client;
				args[a++]=sdirs->current;
				args[a++]=sdirs->client;
				args[a++]="reserved1";
				args[a++]="reserved2";
				args[a++]=NULL;
				if((*timer_ret=run_script(args,
				  cconf->timer_arg,
				  cconf->tacount,
				  /* cntr is NULL so that run_script does not
				     write warnings down the socket, otherwise
				     the client will never print the 'timer
				     conditions not met' message below. */
				  NULL,
				  1 /* wait */, 1 /* use logp */))<0)
				{
					ret=*timer_ret;
					logp("Error running timer script for %s\n", client);
					goto end;
				}
				if(*timer_ret)
				{
					logp("Not running backup of %s\n",
						client);
					async_write_str(CMD_GEN,
						"timer conditions not met");
					goto end;
				}
				logp("Running backup of %s\n", client);
			}
			else
			{
				if(!cconf->client_can_force_backup)
				{
					logp("Not allowing forced backup of %s\n", client);
					async_write_str(CMD_GEN, "Forced backup is not allowed");
					goto end;
				}
			}

			snprintf(okstr, sizeof(okstr), "ok:%d",
				cconf->compression);
			async_write_str(CMD_GEN, okstr);
			ret=do_backup_server(sdirs, cconf,
				client, cversion, incexc);
			maybe_do_notification(ret, client,
				sdirs->client, sdirs->current,
				"log", "backup", cconf);
		}
	}
	else if(rbuf->cmd==CMD_GEN
	  && (!strncmp(rbuf->buf, "restore ", strlen("restore "))
		|| !strncmp(rbuf->buf, "verify ", strlen("verify "))))
	{
		char *cp=NULL;
		enum action act;
		char *backupnostr=NULL;
		// Hmm. inefficient.
	  	if(!strncmp(rbuf->buf, "restore ", strlen("restore ")))
		{
			backupnostr=rbuf->buf+strlen("restore ");
			act=ACTION_RESTORE;
		}
		else
		{
			backupnostr=rbuf->buf+strlen("verify ");
			act=ACTION_VERIFY;
		}
		reset_conf_val(backupnostr, &(cconf->backup));
		if((cp=strchr(cconf->backup, ':'))) *cp='\0';

		if(get_lock_w(sdirs, gotlock))
			ret=-1;
		else
		{
			char *restoreregex=NULL;
			char *dir_for_notify=NULL;

			if(act==ACTION_RESTORE)
			{
				int r;
				if((r=client_can_restore(cconf, client))<0)
				{
					ret=-1;
					goto end;
				}
				else if(!r)
				{
					logp("Not allowing restore of %s\n",
						client);
					async_write_str(CMD_GEN,
					  "Client restore is not allowed");
					goto end;
				}
			}
			if(act==ACTION_VERIFY && !cconf->client_can_verify)
			{
				logp("Not allowing verify of %s\n", client);
				async_write_str(CMD_GEN,
					"Client verify is not allowed");
				goto end;
			}

			if((restoreregex=strchr(rbuf->buf, ':')))
			{
				*restoreregex='\0';
				restoreregex++;
			}
			reset_conf_val(restoreregex, &(cconf->regex));
			async_write_str(CMD_GEN, "ok");
			ret=do_restore_server(sdirs, act, client,
				srestore, &dir_for_notify, cconf);
			if(dir_for_notify)
			{
				maybe_do_notification(ret, client,
					sdirs->client, dir_for_notify,
					act==ACTION_RESTORE?
						"restorelog":"verifylog",
					act==ACTION_RESTORE?
						"restore":"verify",
					cconf);
				free(dir_for_notify);
			}
		}
	}
	else if(rbuf->cmd==CMD_GEN
	  && !strncmp(rbuf->buf, "delete ", strlen("delete ")))
	{
		if(get_lock_w(sdirs, gotlock))
			ret=-1;
		else
		{
			char *backupno=NULL;
			if(!cconf->client_can_delete)
			{
				logp("Not allowing delete of %s\n", client);
				async_write_str(CMD_GEN,
					"Client delete is not allowed");
				goto end;
			}
			backupno=rbuf->buf+strlen("delete ");
			ret=do_delete_server(sdirs->client,
				backupno, client, cconf);
		}
	}
	else if(rbuf->cmd==CMD_GEN
	  && (!strncmp(rbuf->buf, "list ", strlen("list "))
	      || !strncmp(rbuf->buf, "listb ", strlen("listb "))))
	{
		if(get_lock_w(sdirs, gotlock))
			ret=-1;
		else
		{
			char *backupno=NULL;
			char *browsedir=NULL;
			char *listregex=NULL;

			if(!cconf->client_can_list)
			{
				logp("Not allowing list of %s\n", client);
				async_write_str(CMD_GEN,
					"Client list is not allowed");
				goto end;
			}

			if(!strncmp(rbuf->buf, "list ", strlen("list ")))
			{
				if((listregex=strrchr(rbuf->buf, ':')))
				{
					*listregex='\0';
					listregex++;
				}
				backupno=rbuf->buf+strlen("list ");
			}
			else if(!strncmp(rbuf->buf, "listb ", strlen("listb ")))
			{
				if((browsedir=strchr(rbuf->buf, ':')))
				{
					*browsedir='\0';
					browsedir++;
				}
				// strip any trailing slashes
				// (unless it is '/').
				if(strcmp(browsedir, "/")
				 && browsedir[strlen(browsedir)-1]=='/')
				  browsedir[strlen(browsedir)-1]='\0';
				backupno=rbuf->buf+strlen("listb ");
			}
			async_write_str(CMD_GEN, "ok");
			ret=do_list_server(sdirs->client, backupno,
				listregex, browsedir, client, cconf);
		}
	}
	else
	{
		logp("unknown command: %c:%s\n", rbuf->cmd, rbuf->buf);
		async_write_str(CMD_ERROR, "unknown command");
		ret=-1;
	}

end:
	sdirs_free(sdirs);
	return ret;
}

static int append_to_feat(char **feat, const char *str)
{
	char *tmp=NULL;
	if(!*feat)
	{
		if(!(*feat=strdup(str)))
		{
			log_out_of_memory(__FUNCTION__);
			return -1;
		}
		return 0;
	}
	if(!(tmp=prepend(*feat, str, strlen(str), "")))
		return -1;
	free(*feat);
	*feat=tmp;
	return 0;
}

static int send_features(const char *client, struct config *cconf)
{
	int ret=-1;
	char *feat=NULL;
	struct stat statp;
	if(append_to_feat(&feat, "extra_comms_begin ok:")
		/* clients can autoupgrade */
	  || append_to_feat(&feat, "autoupgrade:")
		/* clients can give server incexc config so that the
		   server knows better what to do on resume */
	  || append_to_feat(&feat, "incexc:")
		/* clients can give the server an alternative client
		   to restore from */
	  || append_to_feat(&feat, "orig_client:"))
		goto end;

	/* Clients can receive restore initiated from the server. */
	if(cconf->restore_path) free(cconf->restore_path);
	if(!(cconf->restore_path=get_restorepath(cconf, client)))
		goto end;
	if(!lstat(cconf->restore_path, &statp) && S_ISREG(statp.st_mode)
	  && append_to_feat(&feat, "srestore:"))
		goto end;

	/* Clients can receive incexc config from the server.
	   Only give it as an option if the server has some starting
	   directory configured in the clientconfdir. */
	if(cconf->sdcount && append_to_feat(&feat, "sincexc:"))
		goto end;

	/* Clients can be sent counters on resume/verify/restore. */
	if(append_to_feat(&feat, "counters:"))
		goto end;

	//printf("feat: %s\n", feat);

	if(async_write_str(CMD_GEN, feat))
	{
		logp("problem in extra_comms\n");
		goto end;
	}

	ret=0;
end:
	if(feat) free(feat);
	return ret;
}

struct vers
{
	long min;
	long cli;
	long ser;
	long feat_list;
	long directory_tree;
};

static int extra_comms_read(struct vers *vers, char **client, int *srestore, char **incexc, struct config *conf, struct config *cconf)
{
	int ret=-1;
	struct iobuf *rbuf=NULL;
	if(!(rbuf=iobuf_alloc())) goto end;

	while(1)
	{
		iobuf_free_content(rbuf);
		if(async_read(rbuf)) goto end;

		if(rbuf->cmd!=CMD_GEN)
		{
			iobuf_log_unexpected(rbuf, __FUNCTION__);
			goto end;
		}
	
		if(!strcmp(rbuf->buf, "extra_comms_end"))
		{
			if(async_write_str(CMD_GEN, "extra_comms_end ok"))
				goto end;
			break;
		}
		else if(!strncmp(rbuf->buf,
			"autoupgrade:", strlen("autoupgrade:")))
		{
			char *os=NULL;
			os=rbuf->buf+strlen("autoupgrade:");
			if(os && *os && autoupgrade_server(vers->ser,
				vers->cli, os, conf)) goto end;
		}
		else if(!strcmp(rbuf->buf, "srestore ok"))
		{
			// Client can accept the restore.
			// Load the restore config, then send it.
			*srestore=1;
			if(parse_incexcs_path(cconf, cconf->restore_path)
			  || incexc_send_server_restore(cconf))
				goto end;
			// Do not unlink it here - wait until
			// the client says that it wants to do the
			// restore.
			// Also need to leave it around if the
			// restore is to an alternative client, so
			// that the code below that reloads the config
			// can read it again.
			//unlink(cconf->restore_path);
		}
		else if(!strcmp(rbuf->buf, "srestore not ok"))
		{
			// Client will not accept the restore.
			unlink(cconf->restore_path);
			free(cconf->restore_path);
			cconf->restore_path=NULL;
			logp("Client not accepting server initiated restore.\n");
		}
		else if(!strcmp(rbuf->buf, "sincexc ok"))
		{
			// Client can accept incexc conf from the
			// server.
			if(incexc_send_server(cconf)) goto end;
		}
		else if(!strcmp(rbuf->buf, "incexc"))
		{
			// Client is telling server its incexc
			// configuration so that it can better decide
			// what to do on resume.
			if(*incexc) { free(*incexc); *incexc=NULL; }
			if(incexc_recv_server(incexc, conf)) goto end;
			if(*incexc)
			{
				char *tmp=NULL;
				char comp[32]="";
				snprintf(comp, sizeof(comp),
					"compression = %d\n",
					cconf->compression);
				if(!(tmp=prepend(*incexc, comp,
					strlen(comp), 0))) goto end;
				free(*incexc);
				*incexc=tmp;
			}
		}
		else if(!strcmp(rbuf->buf, "countersok"))
		{
			// Client can accept counters on
			// resume/verify/restore.
			logp("Client supports being sent counters.\n");
			cconf->send_client_counters=1;
		}
		else if(!strncmp(rbuf->buf,
			"orig_client=", strlen("orig_client="))
		  && strlen(rbuf->buf)>strlen("orig_client="))
		{
			int r=0;
			int rcok=0;
			struct config *sconf=NULL;
			const char *orig_client=NULL;
			orig_client=rbuf->buf+strlen("orig_client=");

			if(!(sconf=(struct config *)
				malloc(sizeof(struct config))))
			{
				log_out_of_memory(__FUNCTION__);
				goto end;
			}
			logp("Client wants to switch to client: %s\n",
				orig_client);
			if(config_load_client(conf, sconf, orig_client))
			{
				char msg[256]="";
				snprintf(msg, sizeof(msg),
				  "Could not load alternate config: %s",
				  orig_client);
				log_and_send(msg);
				goto end;
			}
			sconf->send_client_counters=cconf->send_client_counters;
			for(r=0; r<sconf->rccount; r++)
			{
				if(sconf->rclients[r])
				{
				  if(!strcmp(sconf->rclients[r]->path, *client))
				  {
					rcok++;
					break;
				  }
				}
			}

			if(!rcok)
			{
				char msg[256]="";
				snprintf(msg, sizeof(msg),
				  "Access to client is not allowed: %s",
					orig_client);
				log_and_send(msg);
				goto end;
			}
			sconf->restore_path=cconf->restore_path;
			cconf->restore_path=NULL;
			config_free(cconf);
			memcpy(cconf, sconf, sizeof(struct config));
			sconf=NULL;
			cconf->restore_client=*client;
			if(!(*client=strdup(orig_client))
			  || !(cconf->orig_client=strdup(orig_client)))
			{
				log_and_send_oom(__FUNCTION__);
				goto end;
			}
			orig_client=NULL;

			// If this started out as a server-initiated
			// restore, need to load the restore file
			// again.
			if(*srestore)
			{
				if(parse_incexcs_path(cconf,
					cconf->restore_path)) goto end;
			}
			logp("Switched to client %s\n", *client);
			if(async_write_str(CMD_GEN, "orig_client ok"))
				goto end;
		}
		else if(!strncmp(rbuf->buf,
			"restore_spool=", strlen("restore_spool=")))
		{
			// Client supports temporary spool directory
			// for restores.
			if(!(cconf->restore_spool=
			  strdup(rbuf->buf+strlen("restore_spool="))))
			{
				log_and_send_oom(__FUNCTION__);
				goto end;
			}
		}
		else
		{
			iobuf_log_unexpected(rbuf, __FUNCTION__);
			goto end;
		}
	}

	ret=0;
end:
	iobuf_free(rbuf);
	return ret;
}

static int init_vers(struct vers *vers, const char *cversion)
{
	memset(vers, 0, sizeof(struct vers));
	return ((vers->min=version_to_long("1.2.7"))<0
	  || (vers->cli=version_to_long(cversion))<0
	  || (vers->ser=version_to_long(VERSION))<0
	  || (vers->feat_list=version_to_long("1.3.0"))<0
	  || (vers->directory_tree=version_to_long("1.3.6"))<0);
}

static int extra_comms(char **client, const char *cversion, char **incexc, int *srestore, struct config *conf, struct config *cconf)
{
	int ret=-1;
	struct vers vers;
	//char *restorepath=NULL;

	if(init_vers(&vers, cversion)) goto end;

	if(vers.cli<vers.directory_tree)
	{
		conf->directory_tree=0;
		cconf->directory_tree=0;
	}

	// Clients before 1.2.7 did not know how to do extra comms, so skip
	// this section for them.
	if(vers.cli<vers.min) return 0;

	if(async_read_expect(CMD_GEN, "extra_comms_begin"))
	{
		logp("problem reading in extra_comms\n");
		goto end;
	}
	// Want to tell the clients the extra comms features that are
	// supported, so that new clients are more likely to work with old
	// servers.
	if(vers.cli==vers.feat_list)
	{
		// 1.3.0 did not support the feature list.
		if(async_write_str(CMD_GEN, "extra_comms_begin ok"))
		{
			logp("problem writing in extra_comms\n");
			goto end;
		}
	}
	else
	{
		if(send_features(*client, cconf)) goto end;
	}

	if(extra_comms_read(&vers, client,
		srestore, incexc, conf, cconf)) goto end;

	ret=0;
end:
	return ret;
}

static int run_server_script(const char *client,
	const char *pre_or_post, struct iobuf *rbuf, const char *script,
	struct strlist **script_arg, int argcount,
	uint8_t notify, struct config *cconf, int backup_ret, int timer_ret)
{
	int a=0;
	int ret=0;
	char *logbuf=NULL;
	const char *args[12];

	args[a++]=script;
	args[a++]=pre_or_post;
	args[a++]=rbuf->buf?rbuf->buf:"", // Action requested by client.
	args[a++]=client;
	args[a++]=backup_ret?"1":"0", // Indicate success or failure.
	// Indicate whether the timer script said OK or not.
	args[a++]=timer_ret?"1":"0",
	args[a++]=NULL;

	// Do not have a client storage directory, so capture the
	// output in a buffer to pass to the notification script.
	if(run_script_to_buf(args, script_arg, argcount, NULL, 1, 1, &logbuf))
	{
		char msg[256];
		snprintf(msg, sizeof(msg),
			"server %s script %s returned an error",
			pre_or_post, script);
		log_and_send(msg);
		ret=-1;
		if(!notify) goto end;

		a=0;
		args[a++]=cconf->notify_failure_script;
		args[a++]=client;
		// magic - set basedir blank and the
		// notify script will know to get the content
		// from the next argument (usually storagedir)
		args[a++]=""; // usually basedir
		args[a++]=logbuf?logbuf:""; //usually storagedir
		args[a++]=""; // usually file
		args[a++]=""; // usually brv
		args[a++]=""; // usually warnings
		args[a++]=NULL;
		run_script(args, cconf->notify_failure_arg, cconf->nfcount,
			NULL, 1, 1);
	}
end:
	if(logbuf) free(logbuf);
	return ret;
}

static int child_w(char **client, const char *cversion,
	struct config *conf, struct config *cconf)
{
	int ret=-1;
	int srestore=0;
	int timer_ret=0;
	char *gotlock=NULL;
	struct iobuf *rbuf=NULL;
	char *incexc=NULL;

	/* Has to be before the chuser/chgrp stuff to allow clients to switch
	   to different clients when both clients have different user/group
	   settings. */
	if(extra_comms(client, cversion, &incexc, &srestore, conf, cconf))
	{
		log_and_send("running extra comms failed on server");
		goto end;
	}

	/* Now that the client conf is loaded, we might want to chuser or
	   chgrp.
	   The main process could have already done this, so we don't want
	   to try doing it again if cconf has the same values, because it
	   will fail. */
	if( (!conf->user  || (cconf->user && strcmp(conf->user, cconf->user)))
	  ||(!conf->group ||(cconf->group && strcmp(conf->group,cconf->group))))
	{
		if(chuser_and_or_chgrp(cconf->user, cconf->group))
		{
			log_and_send("chuser_and_or_chgrp failed on server");
			goto end;
		}
	}

	if(!(rbuf=iobuf_async_read())) goto end;

	ret=0;

	// FIX THIS: Make the script components part of a struct, and just
	// pass in the correct struct. Same below.
	if(cconf->server_script_pre)
		ret=run_server_script(*client, "pre", rbuf,
			cconf->server_script_pre,
			cconf->server_script_pre_arg,
			cconf->sprecount,
			cconf->server_script_pre_notify,
			cconf, ret, timer_ret);

	if(!ret) ret=child(conf, cconf, *client, cversion, incexc, srestore,
			rbuf, &gotlock, &timer_ret);

	if((!ret || cconf->server_script_post_run_on_fail)
	  && cconf->server_script_post)
		ret=run_server_script(*client, "post", rbuf,
			cconf->server_script_post,
			cconf->server_script_post_arg,
			cconf->spostcount,
			cconf->server_script_post_notify,
			cconf, ret, timer_ret);

end:
	if(gotlock)
	{
		unlink(gotlock);
		free(gotlock);
	}
	iobuf_free(rbuf);
	return ret;
}

static int run_child(int *rfd, int *cfd, SSL_CTX *ctx, const char *configfile, int forking)
{
	int ret=-1;
	int ca_ret=0;
	SSL *ssl=NULL;
	BIO *sbio=NULL;
	char *client=NULL;
	char *cversion=NULL;
	struct config conf;
	struct config cconf;
	struct cntr p1cntr;
	struct cntr cntr;

	conf.p1cntr=&p1cntr;
	conf.cntr=&cntr;
	cconf.p1cntr=&p1cntr;
	cconf.cntr=&cntr;
	reset_filecounters(&conf, time(NULL));

	if(forking) close_fd(rfd);

	// Reload global config, in case things have changed. This means that
	// the server does not need to be restarted for most config changes.
	config_init(&conf);
	config_init(&cconf);
	if(config_load(configfile, &conf, 1)) return -1;

	if(!(sbio=BIO_new_socket(*cfd, BIO_NOCLOSE))
	  || !(ssl=SSL_new(ctx)))
	{
		logp("There was a problem joining ssl to the socket\n");
		goto end;
	}
	SSL_set_bio(ssl, sbio, sbio);

	/* Do not try to check peer certificate straight away.
	   Clients can send a certificate signing request when they have
	   no certificate. */
	SSL_set_verify(ssl, SSL_VERIFY_PEER
		/* | SSL_VERIFY_FAIL_IF_NO_PEER_CERT */, 0);

	if(SSL_accept(ssl)<=0)
	{
		char buf[256]="";
		ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
		logp("SSL_accept: %s\n", buf);
		goto end;
	}
	if(async_init(*cfd, ssl, &conf, 0))
		goto end;
	if(authorise_server(&conf, &client, &cversion, &cconf)
		|| !client || !*client)
	{
		// Add an annoying delay in case they are tempted to
		// try repeatedly.
		log_and_send("unable to authorise on server");
		sleep(1);
		goto end;
	}

	/* At this point, the client might want to get a new certificate
	   signed. Clients on 1.3.2 or newer can do this. */
	if((ca_ret=ca_server_maybe_sign_client_cert(client, cversion, &conf))<0)
	{
		logp("Error signing client certificate request for %s\n",
			client);
		goto end;
	}
	else if(ca_ret>0)
	{
		// Certificate signed and sent back.
		// Everything is OK, but we will close this instance
		// so that the client can start again with a new
		// connection and its new certificates.
		logp("Signed and returned client certificate request for %s\n",
			client);
		ret=0;
		goto end;
	}

	/* Now it is time to check the certificate. */ 
	if(ssl_check_cert(ssl, &cconf))
	{
		log_and_send("check cert failed on server");
		goto end;
	}

	set_non_blocking(*cfd);

	ret=child_w(&client, cversion, &conf, &cconf);
end:
	*cfd=-1;
	async_free(); // this closes cfd for us.
	logp("exit child\n");
	if(client) free(client);
	if(cversion) free(cversion);
	config_free(&conf);
	config_free(&cconf);
	return ret;
}

static int run_status_server(int *rfd, int *cfd, const char *configfile)
{
	int ret=0;
	struct config conf;

	close_fd(rfd);

	// Reload global config, in case things have changed. This means that
	// the server does not need to be restarted for most config changes.
	config_init(&conf);
	if(config_load(configfile, &conf, 1)) return -1;

	ret=status_server(cfd, &conf);

	close_fd(cfd);

	logp("exit status server\n");

	config_free(&conf);

	return ret;
}

static int process_incoming_client(int rfd, struct config *conf, SSL_CTX *ctx, const char *configfile, int is_status_server)
{
	int cfd=-1;
	socklen_t client_length=0;
	struct sockaddr_in client_name;

	client_length=sizeof(client_name);
	if((cfd=accept(rfd,
		(struct sockaddr *) &client_name,
		&client_length))==-1)
	{
		// Look out, accept will get interrupted by SIGCHLDs.
		if(errno==EINTR) return 0;
		logp("accept failed on %d: %s\n", rfd, strerror(errno));
		return -1;
	}
	reuseaddr(cfd);
	chld_check_for_exiting();

	if(conf->forking)
	{
	  pid_t childpid;
	  int pipe_rfd[2];
	  int pipe_wfd[2];

	  if(chld_add_incoming(conf, is_status_server))
	  {
		logp("Closing new connection.\n");
		close_fd(&cfd);
		return 0;
	  }

	  if(pipe(pipe_rfd)<0
	    || pipe(pipe_wfd)<0)
	  {
		logp("pipe failed: %s", strerror(errno));
		close_fd(&cfd);
		return -1;
	  }
	  /* fork off our new process to handle this request */
	  switch((childpid=fork()))
	  {
		case -1:
			logp("fork failed: %s\n", strerror(errno));
			break;
		case 0:
		{
			int ret;
			// child
			struct sigaction sa;

			// Set SIGCHLD back to default, so that I
			// can get sensible returns from waitpid.
			memset(&sa, 0, sizeof(sa));
			sa.sa_handler=SIG_DFL;
			sigaction(SIGCHLD, &sa, NULL);

			close(pipe_rfd[0]); // close read end
			close(pipe_wfd[1]); // close write end

			config_free(conf);

			set_blocking(pipe_rfd[1]);
			status_wfd=pipe_rfd[1];
			status_rfd=pipe_wfd[0];

			if(is_status_server)
			  ret=run_status_server(&rfd, &cfd, configfile);
			else
			  ret=run_child(&rfd, &cfd, ctx,
				configfile, conf->forking);
			close_fd(&status_wfd);
			close_fd(&status_rfd);
			exit(ret);
		}
		default:
			// parent
			close(pipe_rfd[1]); // close write end
			close(pipe_wfd[0]); // close read end

			// keep a note of the child pid.
			if(is_status_server)
				logp("forked status server child pid %d\n",
					childpid);
			else
				logp("forked child pid %d\n", childpid);

			chld_forked(childpid,
				pipe_rfd[0], pipe_wfd[1], is_status_server);

			close_fd(&cfd);
			break;
	  }
	}
	else
	{
		if(is_status_server)
			return run_status_server(&rfd, &cfd, configfile);
		else
			return run_child(&rfd, &cfd, ctx, configfile,
				conf->forking);
	}
	return 0;
}

static int daemonise(void)
{
	/* process ID */
	pid_t pid;

	/* session ID */
	pid_t sid;

	/* fork new child and end parent */
	pid=fork();

	/* did we fork? */
	if(pid<0)
	{
		logp("error forking\n");
		return -1;
	}

	/* parent? */
	if(pid>0)
		exit(EXIT_SUCCESS);

	/* now we are in the child process */

	/* create a session and set the process group ID */
	sid=setsid();
	if(sid<0)
	{
		logp("error setting sid\n");
		return -1;
	}

	/* leave and unblock current working dir */
	if(chdir("/")<0)
	{
		logp("error changing working dir\n");
		return -1;
	}

	/* close std* */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	return 0;
}

static int relock(const char *lockfile)
{
	int tries=5;
	for(; tries>0; tries--)
	{
		if(!get_lock(lockfile)) return 0;
		sleep(2);
	}
	logp("Unable to re-get lockfile after forking.\n");
	return -1;
}

static int run_server(struct config *conf, const char *configfile, int *rfd, const char *oldport, const char *oldstatusport)
{
	int ret=0;
	SSL_CTX *ctx=NULL;
	int found_normal_child=0;

	if(!(ctx=ssl_initialise_ctx(conf)))
	{
		logp("error initialising ssl ctx\n");
		return 1;
	}
	if((ssl_load_dh_params(ctx, conf)))
	{
		logp("error loading dh params\n");
		return 1;
	}

	if(!oldport
	  || strcmp(oldport, conf->port))
	{
		close_fd(rfd);
		if((*rfd=init_listen_socket(conf->port, 1))<0)
			return 1;
	}
	if(conf->status_port
	  && (!oldstatusport
		|| strcmp(oldstatusport, conf->status_port)))
	{
		close_fd(&sfd);
		if((sfd=init_listen_socket(conf->status_port, 0))<0)
			return 1;
	}

	while(!hupreload)
	{
		int mfd=-1;
		berrno be;
		fd_set fsr;
		fd_set fsw;
		fd_set fse;
		struct timeval tval;

		if(sigchld)
		{
			chld_check_for_exiting();
			sigchld=0;
		}

		FD_ZERO(&fsr);
		FD_ZERO(&fse);

		tval.tv_sec=1;
		tval.tv_usec=0;

		add_fd_to_sets(*rfd, &fsr, NULL, &fse, &mfd);
		if(sfd>=0) add_fd_to_sets(sfd, &fsr, NULL, &fse, &mfd);

		// Add read fds of normal children.
		found_normal_child=chld_add_fd_to_normal_sets(conf,
			&fsr, &fse, &mfd);

		// Leave if we had a SIGUSR1 and there are no children
		// running.
		if(gentleshutdown)
		{
			if(!gentleshutdown_logged)
			{
				logp("got SIGUSR2 gentle reload signal\n");
				logp("will shut down once children have exited\n");
				gentleshutdown_logged++;
			}
			else if(!found_normal_child)
			{
				logp("all children have exited - shutting down\n");
				break;
			}
		}

		if(select(mfd+1, &fsr, NULL, &fse, &tval)<0)
		{
			if(errno!=EAGAIN && errno!=EINTR)
			{
				logp("select error in normal part of %s: %s\n",
					__func__, strerror(errno));
				ret=1;
				break;
			}
		}

		if(FD_ISSET(*rfd, &fse))
		{
			// Happens when a client exits.
			//logp("error on listening socket.\n");
			if(!conf->forking) { gentleshutdown++; break; }
			continue;
		}

		if((sfd>=0 && FD_ISSET(sfd, &fse)))
		{
			// Happens when a client exits.
			//logp("error on status socket.\n");
			if(!conf->forking) { gentleshutdown++; break; }
			continue;
		}

		if(FD_ISSET(*rfd, &fsr))
		{
			// A normal client is incoming.
			if(process_incoming_client(*rfd, conf, ctx,
				configfile, 0 /* not a status client */))
			{
				ret=1;
				break;
			}
			if(!conf->forking) { gentleshutdown++; break; }
		}

		if(sfd>=0 && FD_ISSET(sfd, &fsr))
		{
			// A status client is incoming.
			//printf("status client?\n");
			if(process_incoming_client(sfd, conf, ctx,
				configfile, 1 /* a status client */))
			{
				ret=1;
				break;
			}
			if(!conf->forking) { gentleshutdown++; break; }
		}

		if(chld_fd_isset_normal(conf, &fsr, &fse))
		{
			ret=1;
			break;
		}

		// Have a separate select for writing to status server children

		mfd=-1;
		FD_ZERO(&fsw);
		FD_ZERO(&fse);
		if(!chld_add_fd_to_normal_sets(conf, &fsw, &fse, &mfd))
		{
			// Did not find any status server children.
			// No need to do the select.
			continue;
		}

		// Do not hang around - doing the status stuff is a lower
		// priority thing than dealing with normal clients.
		tval.tv_sec=0;
		tval.tv_usec=500;

		//printf("try status server\n");

		if(select(mfd+1, NULL, &fsw, &fse, &tval)<0)
		{
			if(errno!=EAGAIN && errno!=EINTR)
			{
				logp("select error in status part of %s: %s\n",
					__func__, strerror(errno));
				ret=1;
				break;
			}
		}

		if(chld_fd_isset_status(conf, &fsw, &fse))
		{
			ret=1;
			break;
		}
	}

	if(hupreload) logp("got SIGHUP reload signal\n");

	ssl_destroy_ctx(ctx);

	return ret;
}

int server(struct config *conf, const char *configfile, int generate_ca_only)
{
	int ret=0;
	int rfd=-1; // normal client port
	// Only close and reopen listening sockets if the ports changed.
	// Otherwise you get an "unable to bind listening socket on port X"
	// error, and the server stops.
	char *oldport=NULL;
	char *oldstatusport=NULL;

	//return champ_test(conf);

	if(ca_server_setup(conf)) return 1;
	if(generate_ca_only)
	{
		logp("The '-g' command line option was given. Exiting now.\n");
		return 0;
	}

	if(conf->forking && conf->daemon)
	{
		if(daemonise() || relock(conf->lockfile)) return 1;
	}

	ssl_load_globals();

	while(!ret && !gentleshutdown)
	{
		ret=run_server(conf, configfile,
			&rfd, oldport, oldstatusport);
		if(ret) break;
		if(hupreload && !gentleshutdown)
		{
			if(oldport) free(oldport);
			if(oldstatusport) free(oldstatusport);
			oldport=strdup(conf->port);
			oldstatusport=conf->status_port?
				strdup(conf->status_port):NULL;
			if(reload(conf, configfile,
				0, // Not first time.
				conf->max_children,
				conf->max_status_children,
				0)) // Not JSON output.
					ret=1;
		}
		hupreload=0;
	}
	close_fd(&rfd);
	close_fd(&sfd);
	if(oldport) free(oldport);
	if(oldstatusport) free(oldstatusport);

	// The signal handler stuff sets up chlds. Need to free them.
	chlds_free();

	return ret;
}
