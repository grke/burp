#include "include.h"

#include <netdb.h>
#include <crypt.h>

static int check_passwd(const char *passwd, const char *plain_text)
{
	char salt[3];

	if(!plain_text || !passwd || strlen(passwd)!=13)
		return 0;

	salt[0]=passwd[0];
	salt[1]=passwd[1];
	salt[2]=0;
	return !strcmp(crypt(plain_text, salt), passwd);
}

static int check_client_and_password(struct conf *conf, const char *password, struct conf *cconf)
{
	// Cannot load it until here, because we need to have the name of the
	// client.
	if(conf_load_client(conf, cconf)) return -1;

	if(!cconf->ssl_peer_cn)
	{
		logp("ssl_peer_cn unset");
		if(cconf->cname)
		{
			logp("Falling back to using '%s'\n", cconf->cname);
			if(!(cconf->ssl_peer_cn=strdup(cconf->cname)))
			{
				log_out_of_memory(__func__);
				return -1;
			}
		}
	}

	if(cconf->password_check)
	{
		if(!cconf->password && !cconf->passwd)
		{
			logp("password rejected for client %s\n", cconf->cname);
			return -1;
		}
		// check against plain text
		if(cconf->password && strcmp(cconf->password, password))
		{
			logp("password rejected for client %s\n", cconf->cname);
			return -1;
		}
		// check against encypted passwd
		if(cconf->passwd && !check_passwd(cconf->passwd, password))
		{
			logp("password rejected for client %s\n", cconf->cname);
			return -1;
		}
	}

	if(!cconf->keep)
	{
		logp("%s: you cannot set the keep value for a client to 0!\n",
			cconf->cname);
		return -1;
	}
	return 0;
}

void version_warn(struct asfd *asfd, struct conf *conf, struct conf *cconf)
{
	if(!cconf->peer_version || strcmp(cconf->peer_version, VERSION))
	{
		char msg[256]="";

		if(!cconf->peer_version || !*(cconf->peer_version))
			snprintf(msg, sizeof(msg), "Client '%s' has an unknown version. Please upgrade.", cconf->cname?cconf->cname:"unknown");
		else
			snprintf(msg, sizeof(msg), "Client '%s' version '%s' does not match server version '%s'. An upgrade is recommended.", cconf->cname?cconf->cname:"unknown", cconf->peer_version, VERSION);
		if(conf) logw(asfd, conf, "%s", msg);
		logp("WARNING: %s\n", msg);
	}
}

int authorise_server(struct asfd *asfd, struct conf *conf, struct conf *cconf)
{
	int ret=-1;
	char *cp=NULL;
	char *password=NULL;
	char whoareyou[256]="";
	struct iobuf *rbuf=asfd->rbuf;
	if(asfd->read(asfd))
	{
		logp("unable to read initial message\n");
		goto end;
	}
	if(rbuf->cmd!=CMD_GEN || strncmp_w(rbuf->buf, "hello"))
	{
		iobuf_log_unexpected(rbuf, __func__);
		goto end;
	}
	// String may look like...
	// "hello"
	// "hello:(version)"
	// (version) is a version number
	if((cp=strchr(rbuf->buf, ':')))
	{
		cp++;
		if(cp && !(cconf->peer_version=strdup_w(cp, __func__)))
			goto end;
	}
	iobuf_free_content(rbuf);

	snprintf(whoareyou, sizeof(whoareyou), "whoareyou");
	if(cconf->peer_version)
	{
		long min_ver=0;
		long cli_ver=0;
		if((min_ver=version_to_long("1.3.2"))<0
		  || (cli_ver=version_to_long(cconf->peer_version))<0)
			return -1;
		// Stick the server version on the end of the whoareyou string.
		// if the client version is recent enough.
		if(min_ver<=cli_ver)
		 snprintf(whoareyou, sizeof(whoareyou),
			"whoareyou:%s", VERSION);
	}

	asfd->write_str(asfd, CMD_GEN, whoareyou);
	if(asfd->read(asfd))
	{
		logp("unable to get client name\n");
		goto end;
	}
	cconf->cname=rbuf->buf;
	iobuf_init(rbuf);

	asfd->write_str(asfd, CMD_GEN, "okpassword");
	if(asfd->read(asfd))
	{
		logp("unable to get password for client %s\n", cconf->cname);
		goto end;
	}
	password=rbuf->buf;
	iobuf_init(rbuf);

	if(check_client_and_password(conf, password, cconf))
		goto end;

	if(cconf->version_warn) version_warn(asfd, conf, cconf);

	logp("auth ok for: %s%s\n", cconf->cname,
		cconf->password_check?"":" (no password needed)");

	asfd->write_str(asfd, CMD_GEN, "ok");

	ret=0;
end:
	iobuf_free_content(rbuf);
	free_w(&password);
	return ret;
}
