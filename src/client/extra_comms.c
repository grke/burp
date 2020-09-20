#include "../burp.h"
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
#include "autoupgrade.h"
#include "extra_comms.h"

#ifndef HAVE_WIN32
#include <sys/utsname.h>
#endif

static const char *server_supports(const char *feat, const char *wanted)
{
	return strstr(feat, wanted);
}

static const char *server_supports_autoupgrade(const char *feat)
{
	// 1.3.0 servers did not list the features, but the only feature
	// that was supported was autoupgrade.
	if(!strcmp(feat, "extra_comms_begin ok")) return "ok";
	return server_supports(feat, ":autoupgrade:");
}

#include <librsync.h>

int extra_comms_client(struct async *as, struct conf **confs,
	enum action *action, struct strlist *failover, char **incexc)
{
	int ret=-1;
	char *feat=NULL;
	char *seed_src=NULL;
	char *seed_dst=NULL;
	struct asfd *asfd;
	struct iobuf *rbuf;
	const char *orig_client=NULL;
	asfd=as->asfd;
	rbuf=asfd->rbuf;

	if(asfd->write_str(asfd, CMD_GEN, "extra_comms_begin"))
	{
		logp("Problem requesting extra_comms_begin\n");
		goto end;
	}
	// Servers greater than 1.3.0 will list the extra_comms
	// features they support.
	if(asfd->read(asfd))
	{
		logp("Problem reading response to extra_comms_begin\n");
		goto end;
	}
	if(rbuf->cmd!=CMD_GEN
	  || strncmp_w(rbuf->buf, "extra_comms_begin ok"))
	{
		iobuf_log_unexpected(rbuf, __func__);
		goto end;
	}
	feat=rbuf->buf;
	rbuf->buf=NULL;
	logp("%s\n", feat);
	iobuf_init(rbuf);

	// Can add extra bits here. The first extra bit is the
	// autoupgrade stuff.
	if(server_supports_autoupgrade(feat)
	  && get_string(confs[OPT_AUTOUPGRADE_DIR])
	  && get_string(confs[OPT_AUTOUPGRADE_OS])
	  && autoupgrade_client(as, confs))
		goto end;


	// :srestore: means that the server wants to do a restore.
	if(server_supports(feat, ":srestore:"))
	{
		logp("Server wants to initiate a restore\n");
		if(*action==ACTION_MONITOR)
		{
			logp("Client is in monitor mode, so ignoring\n");
		}
		else if(get_int(confs[OPT_SERVER_CAN_RESTORE]))
		{
			logp("Client accepts.\n");
			if(incexc_recv_client_restore(asfd, incexc, confs))
				goto end;
			if(*incexc)
			{
				if(conf_parse_incexcs_srestore(confs, *incexc))
					goto end;
				*action=ACTION_RESTORE;
				log_restore_settings(confs, 1);
			}
		}
		else
		{
			logp("Client configuration says no\n");
			if(asfd->write_str(asfd, CMD_GEN, "srestore not ok"))
				goto end;
		}
	}

	// Needs to be after the srestore stuff, as the server may set
	// orig_client in the server-initiated restore file.
	if((orig_client=get_string(confs[OPT_ORIG_CLIENT])))
	{
		char str[512]="";
		snprintf(str, sizeof(str), "orig_client=%s", orig_client);
		if(!server_supports(feat, ":orig_client:"))
		{
			logp("Server does not support switching client.\n");
			goto end;
		}
		if(asfd->write_str(asfd, CMD_GEN, str)
		  || asfd_read_expect(asfd, CMD_GEN, "orig_client ok"))
		{
			logp("Problem requesting %s\n", str);
			goto end;
		}
		logp("Switched to client %s\n", orig_client);
	}

	// :sincexc: is for the server giving the client the
	// incexc config.
	if(*action==ACTION_BACKUP
	  || *action==ACTION_BACKUP_TIMED
	  || *action==ACTION_TIMER_CHECK)
	{
		if(!*incexc && server_supports(feat, ":sincexc:"))
		{
			logp("Server is setting includes/excludes.\n");
			if(get_int(confs[OPT_SERVER_CAN_OVERRIDE_INCLUDES]))
			{
				logp("Client accepts.\n");
				if(incexc_recv_client(asfd, incexc, confs))
					goto end;
				if(*incexc && conf_parse_incexcs_buf(confs,
					*incexc)) goto end;
			}
			else
			{
				logp("Client configuration says no\n");
			}
		}
	}

	if(server_supports(feat, ":counters_json:"))
	{
		if(asfd->write_str(asfd, CMD_GEN, "counters_json ok"))
			goto end;
		set_int(confs[OPT_SEND_CLIENT_CNTR], 1);
	}

	// :incexc: is for the client sending the server the
	// incexc conf so that it better knows what to do on
	// resume.
	if(server_supports(feat, ":incexc:")
	  && incexc_send_client(asfd, confs))
		goto end;

	if(server_supports(feat, ":uname:"))
	{
		const char *clientos=NULL;
#ifdef HAVE_WIN32
#ifdef _WIN64
		clientos="Windows 64bit";
#else
		clientos="Windows 32bit";
#endif
#else
		struct utsname utsname;
		if(!uname(&utsname))
			clientos=(const char *)utsname.sysname;
#endif
		if(clientos)
		{
			char *msg=NULL;
			if(astrcat(&msg, "uname=", __func__)
			  || astrcat(&msg, clientos, __func__))
				goto end;
			if(asfd->write_str(asfd, CMD_GEN, msg))
			{
				free_w(&msg);
				goto end;
			}
			free_w(&msg);
		}
	}

	if(server_supports(feat, ":csetproto:"))
	{
		char msg[128]="";
		// Use protocol1 if no choice has been made on client side.
		if(get_protocol(confs)==PROTO_AUTO)
		{
			logp("Server has protocol=0 (auto)\n");
			set_protocol(confs, PROTO_1);
		}
		// Send choice to server.
		snprintf(msg, sizeof(msg), "protocol=%d",
			get_protocol(confs));
		if(asfd->write_str(asfd, CMD_GEN, msg))
			goto end;
		logp("Using protocol=%d\n",
			get_protocol(confs));
	}
	else if(server_supports(feat, ":forceproto=1:"))
	{
		logp("Server is forcing protocol 1\n");
		if(get_protocol(confs)!=PROTO_AUTO
		  && get_protocol(confs)!=PROTO_1)
		{
			logp("But client has set protocol=%d!\n",
				get_protocol(confs));
			goto end;
		}
		set_protocol(confs, PROTO_1);
	}
	else if(server_supports(feat, ":forceproto=2:"))
	{
		logp("Server is forcing protocol 2\n");
		if(get_protocol(confs)!=PROTO_AUTO
		  && get_protocol(confs)!=PROTO_2)
		{
			logp("But client has set protocol=%d!\n",
				get_protocol(confs));
			goto end;
		}
		set_protocol(confs, PROTO_2);
	}

        if(get_protocol(confs)==PROTO_2
          && get_string(confs[OPT_ENCRYPTION_PASSWORD]))
	{
		char msg[64]="";
		snprintf(msg, sizeof(msg),
			"%s is not supported in protocol 2",
				confs[OPT_ENCRYPTION_PASSWORD]->field);
		log_and_send(asfd, msg);
		goto end;
	}

	if(server_supports(feat, ":msg:"))
	{
		set_int(confs[OPT_MESSAGE], 1);
		if(asfd->write_str(asfd, CMD_GEN, "msg"))
			goto end;
	}

#ifdef HAVE_BLAKE2
	if(server_supports(feat, ":rshash=blake2:"))
	{
		set_e_rshash(confs[OPT_RSHASH], RSHASH_BLAKE2);
		// Send choice to server.
		if(asfd->write_str(asfd, CMD_GEN, "rshash=blake2"))
			goto end;
	}
	else
#endif
		set_e_rshash(confs[OPT_RSHASH], RSHASH_MD4);

	if(server_supports(feat, ":failover:"))
	{
		if(*action==ACTION_BACKUP
		  || *action==ACTION_BACKUP_TIMED)
		{
			char msg[64]="";
			int left=0;
			struct strlist *f=NULL;
			for(f=failover; f; f=f->next)
				left++;
			snprintf(msg, sizeof(msg),
				"backup_failovers_left=%d", left);
			if(asfd->write_str(asfd, CMD_GEN, msg))
				goto end;
		}
	}

	seed_src=get_string(confs[OPT_SEED_SRC]);
	seed_dst=get_string(confs[OPT_SEED_DST]);
	if(seed_src && *seed_src
	  && seed_dst && *seed_dst
	  && server_supports(feat, ":seed:"))
	{
		char *msg=NULL;
		logp("Seeding from %s\n", seed_src);
		if(astrcat(&msg, "seed_src=", __func__)
		  || astrcat(&msg, seed_src, __func__)
		  || asfd->write_str(asfd, CMD_GEN, msg))
		{
			free_w(&msg);
			goto end;
		}
		free_w(&msg);
		logp("Seeding to %s\n", seed_dst);
		if(astrcat(&msg, "seed_dst=", __func__)
		  || astrcat(&msg, seed_dst, __func__)
		  || asfd->write_str(asfd, CMD_GEN, msg))
		{
			free_w(&msg);
			goto end;
		}
		free_w(&msg);
	}

	if(server_supports(feat, ":vss_restore:"))
	{
		enum vss_restore vss_restore=(enum vss_restore)
			get_int(confs[OPT_VSS_RESTORE]);
		if(vss_restore==VSS_RESTORE_OFF
		  && asfd->write_str(asfd, CMD_GEN, "vss_restore=off"))
			goto end;
		if(vss_restore==VSS_RESTORE_OFF_STRIP
		  && asfd->write_str(asfd, CMD_GEN, "vss_restore=strip"))
			goto end;
	}

	if(server_supports(feat, ":regex_icase:"))
	{
		if(get_int(confs[OPT_REGEX_CASE_INSENSITIVE]))
		{
			  if(asfd->write_str(asfd, CMD_GEN,
				"regex_icase=1"))
					goto end;
		}
	}

	if(asfd->write_str(asfd, CMD_GEN, "extra_comms_end")
	  || asfd_read_expect(asfd, CMD_GEN, "extra_comms_end ok"))
	{
		logp("Problem requesting extra_comms_end\n");
		goto end;
	}

	ret=0;
end:
	free_w(&feat);
	return ret;
}
