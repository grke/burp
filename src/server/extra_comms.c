#include "../burp.h"
#include "../alloc.h"
#include "../asfd.h"
#include "../async.h"
#include "../cmd.h"
#include "../conf.h"
#include "../conffile.h"
#include "../fsops.h"
#include "../handy.h"
#include "../incexc_recv.h"
#include "../incexc_send.h"
#include "../iobuf.h"
#include "../log.h"
#include "../pathcmp.h"
#include "../prepend.h"
#include "autoupgrade.h"
#include "extra_comms.h"

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

// It is unfortunate that we are having to figure out the server-initiated
// restore paths here instead of setting it in a struct sdirs.
// But doing the extra_comms needs to come before setting the sdirs, because
// extra_comms sets up a bunch of settings that sdirs need to know.
static char *get_restorepath_proto1(struct conf **cconfs)
{
	char *tmp=NULL;
	char *restorepath=NULL;
	if((tmp=prepend_s(get_string(cconfs[OPT_DIRECTORY]),
		get_string(cconfs[OPT_CNAME]))))
			restorepath=prepend_s(tmp, "restore");
	free_w(&tmp);
	return restorepath;
}

static char *get_restorepath_proto2(struct conf **cconfs)
{
	char *tmp1=NULL;
	char *tmp2=NULL;
	char *restorepath=NULL;
	if(!(tmp1=prepend_s(get_string(cconfs[OPT_DIRECTORY]),
		get_string(cconfs[OPT_DEDUP_GROUP]))))
			goto error;
	if(!(tmp2=prepend_s(tmp1, "clients")))
		goto error;
	free_w(&tmp1);
	if(!(tmp1=prepend_s(tmp2, get_string(cconfs[OPT_CNAME]))))
		goto error;
	if(!(restorepath=prepend_s(tmp1, "restore")))
		goto error;
	goto end;
error:
	free_w(&restorepath);
end:
	free_w(&tmp1);
	free_w(&tmp2);
	return restorepath;
}

static int set_restore_path(struct conf **cconfs, char **feat)
{
	int ret=-1;
	char *restorepath1=NULL;
	char *restorepath2=NULL;
	if(!(restorepath1=get_restorepath_proto1(cconfs))
	  || !(restorepath2=get_restorepath_proto2(cconfs)))
		goto end;
	if(is_reg_lstat(restorepath1)==1
	  && set_string(cconfs[OPT_RESTORE_PATH], restorepath1))
		goto end;
	else if(is_reg_lstat(restorepath2)==1
	  && set_string(cconfs[OPT_RESTORE_PATH], restorepath2))
		goto end;
	if(get_string(cconfs[OPT_RESTORE_PATH])
	  && append_to_feat(feat, "srestore:"))
		goto end;
	ret=0;
end:
	free_w(&restorepath1);
	free_w(&restorepath2);
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
	long counters_json;
};

static int send_features(struct asfd *asfd, struct conf **cconfs,
	struct vers *vers)
{
	int ret=-1;
	char *feat=NULL;
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
          || append_to_feat(&feat, "uname:")
          || append_to_feat(&feat, "failover:")
          || append_to_feat(&feat, "vss_restore:")
          || append_to_feat(&feat, "regex_icase:"))
		goto end;

	/* Clients can receive restore initiated from the server. */
	if(set_restore_path(cconfs, &feat))
		goto end;

	/* Clients can receive incexc conf from the server.
	   Only give it as an option if the server has some starting
	   directory configured in the clientconfdir. */
	if((startdir || incglob)
	  && append_to_feat(&feat, "sincexc:"))
		goto end;

	if(vers->cli>=vers->counters_json)
	{
		/* Clients can be sent cntrs on resume/verify/restore. */
		if(append_to_feat(&feat, "counters_json:"))
			goto end;
	}

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

#ifdef HAVE_BLAKE2
	if(append_to_feat(&feat, "rshash=blake2:"))
		goto end;
#endif

	if(append_to_feat(&feat, "seed:"))
		goto end;

	//printf("feat: %s\n", feat);

	if(asfd->write_str(asfd, CMD_GEN, feat))
	{
		logp("problem in extra_comms\n");
		goto end;
	}

	ret=0;
end:
	free_w(&feat);
	return ret;
}

static int do_autoupgrade(struct asfd *asfd, struct vers *vers,
	struct conf **globalcs)
{
	int ret=-1;
	char *os=NULL;
	struct iobuf *rbuf=asfd->rbuf;
	const char *autoupgrade_dir=get_string(globalcs[OPT_AUTOUPGRADE_DIR]);

	if(!(os=strdup_w(rbuf->buf+strlen("autoupgrade:"), __func__)))
		goto end;
	iobuf_free_content(rbuf);
	ret=0;
	if(os && *os)
	{
		// Sanitise path separators
		for(char *i=os; *i; ++i)
			if(*i == '/' || *i == '\\' || *i == ':')
				*i='-';

		ret=autoupgrade_server(asfd, vers->ser,
			vers->cli, os, get_cntr(globalcs),
			autoupgrade_dir);
	}
end:
	free_w(&os);
	return ret;
}

static int setup_seed(
	struct asfd *asfd,
	struct conf **cconfs,
	struct iobuf *rbuf,
	const char *what,
	enum conf_opt opt
) {
	int ret=-1;
	char *tmp=NULL;
	char *str=NULL;

	str=rbuf->buf+strlen(what)+1;
	strip_trailing_slashes(&str);

	if(!is_absolute(str))
	{
		char msg[128];
		snprintf(msg, sizeof(msg), "A %s needs to be absolute!", what);
		log_and_send(asfd, msg);
		goto end;
	}
	if(opt==OPT_SEED_SRC && *str!='/')
	{
printf("here: %s\n", str);
		// More windows hacks - add a slash to the beginning of things
		// like 'C:'.
		if(astrcat(&tmp, "/", __func__)
		  || astrcat(&tmp, str, __func__))
			goto end;
		str=tmp;
	}
	if(set_string(cconfs[opt], str))
		goto end;
	ret=0;
end:
	free_w(&tmp);
	return ret;
}

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
			if(do_autoupgrade(asfd, vers, globalcs))
				goto end;
		}
		else if(!strcmp(rbuf->buf, "srestore ok"))
		{
			char *restore_path=get_string(cconfs[OPT_RESTORE_PATH]);
			if(!restore_path)
			{
				logp("got srestore ok without a restore_path");
				goto end;
			}
			
			iobuf_free_content(rbuf);
			// Client can accept the restore.
			// Load the restore config, then send it.
			*srestore=1;
			// Need to wipe out OPT_INCEXDIR, as it is needed for
			// srestore includes. If it is not wiped out, it can
			// interfere if cconfs[OPT_RESTORE_PATH] contained no
			// includes.
			set_strlist(cconfs[OPT_INCEXCDIR], NULL);
			if(conf_parse_incexcs_path(cconfs, restore_path)
			  || incexc_send_server_restore(asfd, cconfs))
				goto end;
			// Do not unlink it here - wait until
			// the client says that it wants to do the
			// restore.
			// Also need to leave it around if the
			// restore is to an alternative client, so
			// that the code below that reloads the config
			// can read it again.
			// NOTE: that appears to be in
			// src/server/run_action.c::client_can_restore()
			//unlink(get_string(cconfs[OPT_RESTORE_PATH]));
		}
		else if(!strcmp(rbuf->buf, "srestore not ok"))
		{
			const char *restore_path=get_string(
				cconfs[OPT_RESTORE_PATH]);
			// Client will not accept the restore.
			if (restore_path)
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
			// Removed.
		}
		else if(!strncmp_w(rbuf->buf, "protocol="))
		{
			char msg[128]="";
			// Client wants to set protocol.
			enum protocol protocol;
			enum protocol cprotocol;
			const char *cliproto=NULL;
			protocol=get_protocol(cconfs);
			cliproto=rbuf->buf+strlen("protocol=");
			cprotocol=atoi(cliproto);

			if(protocol!=PROTO_AUTO)
			{
				if(protocol==cprotocol)
				{
					logp("Client is forcing protocol=%d\n", (int)protocol);
					continue;
				}
				snprintf(msg, sizeof(msg), "Client is trying to use protocol=%d but server is set to protocol=%d\n", (int)cprotocol, (int)protocol);
				log_and_send(asfd, msg);
				goto end;
			}
			else if(cprotocol==PROTO_1)
			{
				set_protocol(cconfs, cprotocol);
				set_protocol(globalcs, cprotocol);
			}
			else if(cprotocol==PROTO_2)
			{
				set_protocol(cconfs, cprotocol);
				set_protocol(globalcs, cprotocol);
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
#ifdef HAVE_BLAKE2
			set_e_rshash(cconfs[OPT_RSHASH], RSHASH_BLAKE2);
			set_e_rshash(globalcs[OPT_RSHASH], RSHASH_BLAKE2);
#else
			logp("Client is trying to use librsync hash blake2, but server does not support it.\n");
			goto end;
#endif
		}
		else if(!strncmp_w(rbuf->buf, "msg"))
		{
			set_int(cconfs[OPT_MESSAGE], 1);
			set_int(globalcs[OPT_MESSAGE], 1);
		}
		else if(!strncmp_w(rbuf->buf, "backup_failovers_left="))
		{
			int l;
			l=atoi(rbuf->buf+strlen("backup_failovers_left="));
			set_int(cconfs[OPT_BACKUP_FAILOVERS_LEFT], l);
			set_int(globalcs[OPT_BACKUP_FAILOVERS_LEFT], l);
		}
		else if(!strncmp_w(rbuf->buf, "seed_src="))
		{
			if(setup_seed(asfd, cconfs,
				rbuf, "seed_src", OPT_SEED_SRC))
					goto end;
		}
		else if(!strncmp_w(rbuf->buf, "seed_dst="))
		{
			if(setup_seed(asfd, cconfs,
				rbuf, "seed_dst", OPT_SEED_DST))
					goto end;
		}
		else if(!strncmp_w(rbuf->buf, "vss_restore=off"))
		{
			set_int(cconfs[OPT_VSS_RESTORE], VSS_RESTORE_OFF);
			set_int(globalcs[OPT_VSS_RESTORE], VSS_RESTORE_OFF);
		}
		else if(!strncmp_w(rbuf->buf, "vss_restore=strip"))
		{
			set_int(cconfs[OPT_VSS_RESTORE], VSS_RESTORE_OFF_STRIP);
			set_int(globalcs[OPT_VSS_RESTORE], VSS_RESTORE_OFF_STRIP);
		}
		else if(!strncmp_w(rbuf->buf, "regex_icase=1"))
		{
			set_int(cconfs[OPT_REGEX_CASE_INSENSITIVE], 1);
			set_int(globalcs[OPT_REGEX_CASE_INSENSITIVE], 1);
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
	  || (vers->ser=version_to_long(PACKAGE_VERSION))<0
	  || (vers->feat_list=version_to_long("1.3.0"))<0
	  || (vers->directory_tree=version_to_long("1.3.6"))<0
	  || (vers->burp2=version_to_long("2.0.0"))<0
	  || (vers->counters_json=version_to_long("2.0.46"))<0);
}

static int check_seed(struct asfd *asfd, struct conf **cconfs)
{
	char msg[128]="";
	const char *src=get_string(cconfs[OPT_SEED_SRC]);
	const char *dst=get_string(cconfs[OPT_SEED_DST]);
	if(!src && !dst)
		return 0;
	if(src && dst)
	{
		logp("Seeding '%s' -> '%s'\n", src, dst);
		return 0;
	}
	snprintf(msg, sizeof(msg),
		"You must specify %s and %s options together, or not at all.",
			cconfs[OPT_SEED_SRC]->field,
			cconfs[OPT_SEED_DST]->field);
	log_and_send(asfd, msg);
	return -1;
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
		if(send_features(asfd, cconfs, &vers))
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
				logp("Client is %s-%s - using protocol=%d\n",
					PACKAGE_TARNAME,
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
				logp("Client is %s-%s - using protocol=%d\n",
					PACKAGE_TARNAME,
					peer_version, PROTO_2);
				*/
				// PROTO_1 is safer for now.
				set_protocol(confs, PROTO_1);
				set_protocol(cconfs, PROTO_1);
				logp("Client is %s-%s - using protocol=%d\n",
					PACKAGE_TARNAME,
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
			  "but client is %s version %s\n",
			  PROTO_2, PACKAGE_TARNAME, peer_version);
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

	if(check_seed(asfd, cconfs))
		goto error;

	return 0;
error:
	return -1;
}
