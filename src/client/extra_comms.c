#include "include.h"
#include "../cmd.h"

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

int extra_comms(struct async *as, struct conf *conf,
	enum action *action, char **incexc)
{
	int ret=-1;
	char *feat=NULL;
	struct asfd *asfd;
	struct iobuf *rbuf;
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
	feat=rbuf->buf;
	if(rbuf->cmd!=CMD_GEN
	  || strncmp_w(feat, "extra_comms_begin ok"))
	{
		iobuf_log_unexpected(rbuf, __func__);
		goto end;
	}
	logp("%s\n", feat);
	iobuf_init(rbuf);

	// Can add extra bits here. The first extra bit is the
	// autoupgrade stuff.
	if(server_supports_autoupgrade(feat)
	  && conf->autoupgrade_dir
	  && conf->autoupgrade_os
	  && autoupgrade_client(as, conf))
		goto end;

	// :srestore: means that the server wants to do a restore.
	if(server_supports(feat, ":srestore:"))
	{
		if(conf->server_can & SERVER_CAN_RESTORE)
		{
			logp("Server is initiating a restore\n");
			if(incexc_recv_client_restore(asfd, incexc, conf))
				goto end;
			if(*incexc)
			{
				if(conf_parse_incexcs_buf(conf, *incexc))
					goto end;
				*action=ACTION_RESTORE;
				log_restore_settings(conf, 1);
			}
		}
		else
		{
			logp("Server wants to initiate a restore\n");
			logp("Client configuration says no\n");
			if(asfd->write_str(asfd, CMD_GEN, "srestore not ok"))
				goto end;
		}
	}

	if(conf->orig_client)
	{
		char str[512]="";
		snprintf(str, sizeof(str), "orig_client=%s", conf->orig_client);
		if(!server_supports(feat, ":orig_client:"))
		{
			logp("Server does not support switching client.\n");
			goto end;
		}
		if(asfd->write_str(asfd, CMD_GEN, str)
		  || asfd->read_expect(asfd, CMD_GEN, "orig_client ok"))
		{
			logp("Problem requesting %s\n", str);
			goto end;
		}
		logp("Switched to client %s\n", conf->orig_client);
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
			if(incexc_recv_client(asfd, incexc, conf))
				goto end;
			if(*incexc && conf_parse_incexcs_buf(conf,
				*incexc)) goto end;
		}
	}

	if(server_supports(feat, ":counters:"))
	{
		if(asfd->write_str(asfd, CMD_GEN, "countersok"))
			goto end;
		conf->send_client_cntr=1;
	}

	// :incexc: is for the client sending the server the
	// incexc conf so that it better knows what to do on
	// resume.
	if(server_supports(feat, ":incexc:")
	  && incexc_send_client(asfd, conf))
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
			char msg[128]="";
			snprintf(msg, sizeof(msg),
				"uname=%s", clientos);
			if(asfd->write_str(asfd, CMD_GEN, msg))
				goto end;
		}
	}

	if(server_supports(feat, ":csetproto:"))
	{
		char msg[128]="";
		// Use burp2 if no choice has been made on client side.
		if(conf->protocol==PROTO_AUTO)
		{
			logp("Server has protocol=0 (auto)\n");
			conf->protocol=PROTO_BURP2;
		}
		// Send choice to server.
		snprintf(msg, sizeof(msg), "protocol=%d", conf->protocol);
		if(asfd->write_str(asfd, CMD_GEN, msg))
			goto end;
		logp("Using protocol=%d\n", conf->protocol);
	}
	else if(server_supports(feat, ":forceproto=1:"))
	{
		logp("Server is forcing protocol 1\n");
		if(conf->protocol!=PROTO_AUTO && conf->protocol!=PROTO_BURP1)
		{
			logp("But client has set protocol=%d!\n",
				conf->protocol);
			goto end;
		}
		conf->protocol=PROTO_BURP1;
	}
	else if(server_supports(feat, ":forceproto=2:"))
	{
		logp("Server is forcing protocol 2\n");
		if(conf->protocol!=PROTO_AUTO && conf->protocol!=PROTO_BURP2)
		{
			logp("But client has set protocol=%d!\n",
				conf->protocol);
			goto end;
		}
		conf->protocol=PROTO_BURP2;
	}

	if(asfd->write_str(asfd, CMD_GEN, "extra_comms_end")
	  || asfd->read_expect(asfd, CMD_GEN, "extra_comms_end ok"))
	{
		logp("Problem requesting extra_comms_end\n");
		goto end;
	}

	ret=0;
end:
	return ret;
}
