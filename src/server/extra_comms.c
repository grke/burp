#include "../burp.h"
#include "../alloc.h"
#include "../asfd.h"
#include "../async.h"
#include "../cmd.h"
#include "../conf.h"
#include "../conffile.h"
#include "../handy.h"
#include "../incexc_recv.h"
#include "../incexc_send.h"
#include "../iobuf.h"
#include "../log.h"
#include "../prepend.h"
#include "autoupgrade.h"

#include <librsync.h>

static int append_to_feat(char **feat, const char *str)
{
	char *tmp=NULL;
	if(!*feat)
	{
		if(!(*feat=strdup_w(str, __func__)))
			return -1;
		return 0;
	}
	if(!(tmp=prepend(*feat, str)))
		return -1;
	free_w(feat);
	*feat=tmp;
	return 0;
}

static char *get_restorepath(struct conf **cconfs)
{
	char *tmp=NULL;
	char *restorepath=NULL;
	if((tmp=prepend_s(get_string(cconfs[OPT_DIRECTORY]),
		get_string(cconfs[OPT_CNAME]))))
			restorepath=prepend_s(tmp, "restore");
	free_w(&tmp);
	return restorepath;
}

static int send_features(struct asfd *asfd, struct conf **cconfs)
{
	int ret=-1;
	char *feat=NULL;
	struct stat statp;
	char *restorepath=NULL;
	enum protocol protocol=get_protocol(cconfs);
	struct strlist *startdir=get_strlist(cconfs[OPT_STARTDIR]);
	struct strlist *incglob=get_strlist(cconfs[OPT_INCGLOB]);

	if(append_to_feat(&feat, "extra_comms_begin ok:")
		/* clients can autoupgrade */
	  || append_to_feat(&feat, "autoupgrade:")
		/* clients can give server incexc conf so that the
		   server knows better what to do on resume */
	  || append_to_feat(&feat, "incexc:")
		/* clients can give the server an alternative client
		   to restore from */
	  || append_to_feat(&feat, "orig_client:")
		/* clients can tell the server what kind of system they are. */
          || append_to_feat(&feat, "uname:"))
		goto end;

	/* Clients can receive restore initiated from the server. */
	if(!(restorepath=get_restorepath(cconfs))
	  || set_string(cconfs[OPT_RESTORE_PATH], restorepath))
		goto end;
	if(!lstat(restorepath, &statp) && S_ISREG(statp.st_mode)
	  && append_to_feat(&feat, "srestore:"))
		goto end;

	/* Clients can receive incexc conf from the server.
	   Only give it as an option if the server has some starting
	   directory configured in the clientconfdir. */
	if((startdir || incglob)
	  && append_to_feat(&feat, "sincexc:"))
		goto end;

	/* Clients can be sent cntrs on resume/verify/restore. */
/*
	if(append_to_feat(&feat, "counters_json:"))
		goto end;
*/

	// We support CMD_MESSAGE.
	if(append_to_feat(&feat, "msg:"))
		goto end;

	if(protocol==PROTO_AUTO)
	{
		/* If the server is configured to use either protocol, let the
		   client know that it can choose. */
		logp("Server is using protocol=0 (auto)\n");
		if(append_to_feat(&feat, "csetproto:"))
			goto end;
	}
	else
	{
		char p[32]="";
		/* Tell the client what we are going to use. */
		logp("Server is using protocol=%d\n", (int)protocol);
		snprintf(p, sizeof(p), "forceproto=%d:", (int)protocol);
		if(append_to_feat(&feat, p))
			goto end;
	}

#ifndef RS_DEFAULT_STRONG_LEN
	if(append_to_feat(&feat, "rshash=blake2:"))
		goto end;
#endif

	//printf("feat: %s\n", feat);

	if(asfd->write_str(asfd, CMD_GEN, feat))
	{
		logp("problem in extra_comms\n");
		goto end;
	}

	ret=0;
end:
	free_w(&feat);
	free_w(&restorepath);
	return ret;
}

struct vers
{
	long min;
	long cli;
	long ser;
	long feat_list;
	long directory_tree;
	long burp2;
};

static int extra_comms_read(struct async *as,
	struct vers *vers, int *srestore,
	char **incexc, struct conf **globalcs, struct conf **cconfs)
{
	int ret=-1;
	struct asfd *asfd;
	struct iobuf *rbuf;
	asfd=as->asfd;
	rbuf=asfd->rbuf;

	while(1)
	{
		iobuf_free_content(rbuf);
		if(asfd->read(asfd)) goto end;

		if(rbuf->cmd!=CMD_GEN)
		{
			iobuf_log_unexpected(rbuf, __func__);
			goto end;
		}

		if(!strcmp(rbuf->buf, "extra_comms_end"))
		{
			if(asfd->write_str(asfd, CMD_GEN, "extra_comms_end ok"))
				goto end;
			break;
		}
		else if(!strncmp_w(rbuf->buf, "autoupgrade:"))
		{
			char *os=NULL;
			const char *autoupgrade_dir=
				get_string(globalcs[OPT_AUTOUPGRADE_DIR]);
			os=rbuf->buf+strlen("autoupgrade:");
			iobuf_free_content(rbuf);
			if(os && *os && autoupgrade_server(as, vers->ser,
				vers->cli, os, get_cntr(globalcs),
				autoupgrade_dir))
					goto end;
		}
		else if(!strcmp(rbuf->buf, "srestore ok"))
		{
			iobuf_free_content(rbuf);
			// Client can accept the restore.
			// Load the restore config, then send it.
			*srestore=1;
			if(conf_parse_incexcs_path(cconfs,
				get_string(cconfs[OPT_RESTORE_PATH]))
			  || incexc_send_server_restore(asfd, cconfs))
				goto end;
			// Do not unlink it here - wait until
			// the client says that it wants to do the
			// restore.
			// Also need to leave it around if the
			// restore is to an alternative client, so
			// that the code below that reloads the config
			// can read it again.
			//unlink(get_string(cconfs[OPT_RESTORE_PATH]));
		}
		else if(!strcmp(rbuf->buf, "srestore not ok"))
		{
			const char *restore_path=get_string(
				cconfs[OPT_RESTORE_PATH]);
			// Client will not accept the restore.
			unlink(restore_path);
			if(set_string(cconfs[OPT_RESTORE_PATH], NULL))
				goto end;
			logp("Client not accepting server initiated restore.\n");
		}
		else if(!strcmp(rbuf->buf, "sincexc ok"))
		{
			// Client can accept incexc conf from the
			// server.
			iobuf_free_content(rbuf);
			if(incexc_send_server(asfd, cconfs))
				goto end;
		}
		else if(!strcmp(rbuf->buf, "incexc"))
		{
			// Client is telling server its incexc
			// configuration so that it can better decide
			// what to do on resume.
			iobuf_free_content(rbuf);
			if(incexc_recv_server(asfd, incexc, globalcs))
				goto end;
			if(*incexc)
			{
				char *tmp=NULL;
				char comp[32]="";
				snprintf(comp, sizeof(comp),
					"compression = %d\n",
					get_int(cconfs[OPT_COMPRESSION]));
				if(!(tmp=prepend(*incexc, comp)))
					goto end;
				free_w(incexc);
				*incexc=tmp;
			}
		}
		else if(!strcmp(rbuf->buf, "counters_json ok"))
		{
			// Client can accept counters on
			// resume/verify/restore.
			logp("Client supports being sent json counters.\n");
			set_int(cconfs[OPT_SEND_CLIENT_CNTR], 1);
		}
		else if(!strncmp_w(rbuf->buf, "uname=")
		  && strlen(rbuf->buf)>strlen("uname="))
		{
			char *uname=rbuf->buf+strlen("uname=");
			if(!strncasecmp("Windows", uname, strlen("Windows")))
				set_int(cconfs[OPT_CLIENT_IS_WINDOWS], 1);
		}
		else if(!strncmp_w(rbuf->buf, "orig_client=")
		  && strlen(rbuf->buf)>strlen("orig_client="))
		{
			if(conf_switch_to_orig_client(globalcs, cconfs,
				rbuf->buf+strlen("orig_client=")))
					goto end;
			// If this started out as a server-initiated
			// restore, need to load the restore file
			// again.
			if(*srestore)
			{
				if(conf_parse_incexcs_path(cconfs,
					get_string(cconfs[OPT_RESTORE_PATH])))
						goto end;
			}
			if(asfd->write_str(asfd, CMD_GEN, "orig_client ok"))
				goto end;
		}
		else if(!strncmp_w(rbuf->buf, "restore_spool="))
		{
			// Client supports temporary spool directory
			// for restores.
			if(set_string(cconfs[OPT_RESTORE_SPOOL],
				rbuf->buf+strlen("restore_spool=")))
					goto end;
		}
		else if(!strncmp_w(rbuf->buf, "protocol="))
		{
			char msg[128]="";
			// Client wants to set protocol.
			enum protocol protocol=get_protocol(cconfs);
			const char *cliproto=rbuf->buf+strlen("protocol=");
			if(protocol!=PROTO_AUTO)
			{
				snprintf(msg, sizeof(msg), "Client is trying to use protocol=%s but server is set to protocol=%d\n", cliproto, protocol);
				log_and_send(asfd, msg);
				goto end;
			}
			else if(!strcmp(cliproto, "1"))
			{
				set_protocol(cconfs, PROTO_1);
				set_protocol(globalcs, PROTO_1);
			}
			else if(!strcmp(cliproto, "2"))
			{
				set_protocol(cconfs, PROTO_2);
				set_protocol(globalcs, PROTO_2);
			}
			else
			{
				snprintf(msg, sizeof(msg), "Client is trying to use protocol=%s, which is unknown\n", cliproto);
				log_and_send(asfd, msg);
				goto end;
			}
			logp("Client has set protocol=%d\n",
				(int)get_protocol(cconfs));
		}
		else if(!strncmp_w(rbuf->buf, "rshash=blake2"))
		{
#ifdef RS_DEFAULT_STRONG_LEN
			logp("Client is trying to use librsync hash blake2, but server does not support it.\n");
			goto end;
#else
			set_e_rshash(cconfs[OPT_RSHASH], RSHASH_BLAKE2);
			set_e_rshash(globalcs[OPT_RSHASH], RSHASH_BLAKE2);
#endif
		}
		else if(!strncmp_w(rbuf->buf, "msg"))
		{
			set_int(cconfs[OPT_MESSAGE], 1);
			set_int(globalcs[OPT_MESSAGE], 1);
		}
		else
		{
			iobuf_log_unexpected(rbuf, __func__);
			goto end;
		}
	}

	ret=0;
end:
	iobuf_free_content(rbuf);
	return ret;
}

static int vers_init(struct vers *vers, struct conf **cconfs)
{
	memset(vers, 0, sizeof(struct vers));
	return ((vers->min=version_to_long("1.2.7"))<0
	  || (vers->cli=version_to_long(get_string(cconfs[OPT_PEER_VERSION])))<0
	  || (vers->ser=version_to_long(VERSION))<0
	  || (vers->feat_list=version_to_long("1.3.0"))<0
	  || (vers->directory_tree=version_to_long("1.3.6"))<0
	  || (vers->burp2=version_to_long("2.0.0"))<0);
}

int extra_comms(struct async *as,
	char **incexc, int *srestore, struct conf **confs, struct conf **cconfs)
{
	struct vers vers;
	struct asfd *asfd;
	asfd=as->asfd;
	//char *restorepath=NULL;
	const char *peer_version=NULL;

	if(vers_init(&vers, cconfs))
		goto error;

	if(vers.cli<vers.directory_tree)
	{
		set_int(confs[OPT_DIRECTORY_TREE], 0);
		set_int(cconfs[OPT_DIRECTORY_TREE], 0);
	}

	// Clients before 1.2.7 did not know how to do extra comms, so skip
	// this section for them.
	if(vers.cli<vers.min)
		return 0;

	if(asfd_read_expect(asfd, CMD_GEN, "extra_comms_begin"))
	{
		logp("problem reading in extra_comms\n");
		goto error;
	}
	// Want to tell the clients the extra comms features that are
	// supported, so that new clients are more likely to work with old
	// servers.
	if(vers.cli==vers.feat_list)
	{
		// 1.3.0 did not support the feature list.
		if(asfd->write_str(asfd, CMD_GEN, "extra_comms_begin ok"))
		{
			logp("problem writing in extra_comms\n");
			goto error;
		}
	}
	else
	{
		if(send_features(asfd, cconfs))
			goto error;
	}

	if(extra_comms_read(as, &vers, srestore, incexc, confs, cconfs))
		goto error;

	peer_version=get_string(cconfs[OPT_PEER_VERSION]);

	// This needs to come after extra_comms_read, as the client might
	// have set PROTO_1 or PROTO_2.
	switch(get_protocol(cconfs))
	{
		case PROTO_AUTO:
			// The protocol has not been specified. Make a choice.
			if(vers.cli<vers.burp2)
			{
				// Client is burp-1.x.x, use protocol1.
				set_protocol(confs, PROTO_1);
				set_protocol(cconfs, PROTO_1);
				logp("Client is burp-%s - using protocol=%d\n",
					peer_version, PROTO_1);
			}
			else
			{
				// Client is burp-2.x.x, use protocol2.
				// This will probably never be reached because
				// the negotiation will take care of it.
				/*
				set_protocol(confs, PROTO_2);
				set_protocol(cconfs, PROTO_2);
				logp("Client is burp-%s - using protocol=%d\n",
					peer_version, PROTO_2);
				*/
				// PROTO_1 is safer for now.
				set_protocol(confs, PROTO_1);
				set_protocol(cconfs, PROTO_1);
				logp("Client is burp-%s - using protocol=%d\n",
					peer_version, PROTO_1);
			}
			break;
		case PROTO_1:
			// It is OK for the client to be burp1 and for the
			// server to be forced to protocol1.
			break;
		case PROTO_2:
			if(vers.cli>=vers.burp2)
				break;
			logp("protocol=%d is set server side, "
			  "but client is burp version %s\n",
			  PROTO_2, peer_version);
			goto error;
	}

	if(get_protocol(cconfs)==PROTO_1)
	{
		if(get_e_rshash(cconfs[OPT_RSHASH])==RSHASH_UNSET)
		{
			set_e_rshash(confs[OPT_RSHASH], RSHASH_MD4);
			set_e_rshash(cconfs[OPT_RSHASH], RSHASH_MD4);
		}
	}

	return 0;
error:
	return -1;
}
