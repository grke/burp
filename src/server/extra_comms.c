#include "include.h"

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

static char *get_restorepath(struct config *cconf)
{
	char *tmp=NULL;
	char *restorepath=NULL;
	if(!(tmp=prepend_s(cconf->directory, cconf->cname))
	  || !(restorepath=prepend_s(tmp, "restore")))
	{
		if(tmp) free(tmp);
		return NULL;
	}
	free(tmp);
	return restorepath;
}

static int send_features(struct config *cconf)
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
	if(!(cconf->restore_path=get_restorepath(cconf)))
		goto end;
	if(!lstat(cconf->restore_path, &statp) && S_ISREG(statp.st_mode)
	  && append_to_feat(&feat, "srestore:"))
		goto end;

	/* Clients can receive incexc config from the server.
	   Only give it as an option if the server has some starting
	   directory configured in the clientconfdir. */
	if((cconf->startdir || cconf->incglob)
	  && append_to_feat(&feat, "sincexc:"))
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

static int extra_comms_read(struct vers *vers, int *srestore, char **incexc, struct config *conf, struct config *cconf)
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
		else if(!strncmp_w(rbuf->buf, "autoupgrade:"))
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
		else if(!strncmp_w(rbuf->buf, "orig_client=")
		  && strlen(rbuf->buf)>strlen("orig_client="))
		{
			int rcok=0;
			struct strlist *r;
			struct config *sconf=NULL;

			if(!(sconf=(struct config *)
				malloc(sizeof(struct config)))
			  || !(sconf->cname=strdup(
				rbuf->buf+strlen("orig_client="))))
			{
				log_out_of_memory(__FUNCTION__);
				goto end;
			}
			logp("Client wants to switch to client: %s\n",
				sconf->cname);
			if(config_load_client(conf, sconf))
			{
				char msg[256]="";
				snprintf(msg, sizeof(msg),
				  "Could not load alternate config: %s",
				  sconf->cname);
				log_and_send(msg);
				goto end;
			}
			sconf->send_client_counters=cconf->send_client_counters;
			for(r=sconf->rclients; r; r=r->next)
			{
				if(!strcmp(r->path, cconf->cname))
				{
					rcok++;
					break;
				}
			}

			if(!rcok)
			{
				char msg[256]="";
				snprintf(msg, sizeof(msg),
				  "Access to client is not allowed: %s",
					sconf->cname);
				log_and_send(msg);
				goto end;
			}
			sconf->restore_path=cconf->restore_path;
			cconf->restore_path=NULL;
			config_free(cconf);
			memcpy(cconf, sconf, sizeof(struct config));
			free(sconf);
			sconf=NULL;
			cconf->restore_client=cconf->cname;
			if(!(cconf->orig_client=strdup(cconf->cname)))
			{
				log_and_send_oom(__FUNCTION__);
				goto end;
			}

			// If this started out as a server-initiated
			// restore, need to load the restore file
			// again.
			if(*srestore)
			{
				if(parse_incexcs_path(cconf,
					cconf->restore_path)) goto end;
			}
			logp("Switched to client %s\n", cconf->cname);
			if(async_write_str(CMD_GEN, "orig_client ok"))
				goto end;
		}
		else if(!strncmp_w(rbuf->buf, "restore_spool="))
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

static int init_vers(struct vers *vers, struct config *cconf)
{
	memset(vers, 0, sizeof(struct vers));
	return ((vers->min=version_to_long("1.2.7"))<0
	  || (vers->cli=version_to_long(cconf->peer_version))<0
	  || (vers->ser=version_to_long(VERSION))<0
	  || (vers->feat_list=version_to_long("1.3.0"))<0
	  || (vers->directory_tree=version_to_long("1.3.6"))<0);
}

int extra_comms(char **incexc, int *srestore, struct config *conf, struct config *cconf)
{
	int ret=-1;
	struct vers vers;
	//char *restorepath=NULL;

	if(init_vers(&vers, cconf)) goto end;

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
		if(send_features(cconf)) goto end;
	}

	if(extra_comms_read(&vers, srestore, incexc, conf, cconf)) goto end;

	ret=0;
end:
	return ret;
}
