#include "include.h"

#include <netdb.h>

static int check_passwd(const char *passwd, const char *plain_text)
{
#ifdef HAVE_CRYPT
	char salt[3];

	if(!plain_text || !passwd || strlen(passwd)!=13)
		return 0;

	salt[0]=passwd[0];
	salt[1]=passwd[1];
	salt[2]=0;
	return !strcmp(crypt(plain_text, salt), passwd);
#endif // HAVE_CRYPT
	logp("Server compiled without crypt support - cannot use passwd option\n");
	return -1;
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

void version_warn(struct async *as, struct conf *conf, struct conf *cconf)
{
	if(!cconf->peer_version || strcmp(cconf->peer_version, VERSION))
	{
		char msg[256]="";

		if(!cconf->peer_version || !*(cconf->peer_version))
			snprintf(msg, sizeof(msg), "Client '%s' has an unknown version. Please upgrade.", cconf->cname?cconf->cname:"unknown");
		else
			snprintf(msg, sizeof(msg), "Client '%s' version '%s' does not match server version '%s'. An upgrade is recommended.", cconf->cname?cconf->cname:"unknown", cconf->peer_version, VERSION);
		if(conf) logw(as, conf, "%s", msg);
		logp("WARNING: %s\n", msg);
	}
}

int authorise_server(struct async *as, struct conf *conf, struct conf *cconf)
{
	char *cp=NULL;
	char *password=NULL;
	char whoareyou[256]="";
	struct iobuf rbuf;
	iobuf_init(&rbuf);
	if(as->read(as, &rbuf))
	{
		logp("unable to read initial message\n");
		return -1;
	}
	if(rbuf.cmd!=CMD_GEN || strncmp_w(rbuf.buf, "hello"))
	{
		iobuf_log_unexpected(&rbuf, __func__);
		iobuf_free_content(&rbuf);
		return -1;
	}
	// String may look like...
	// "hello"
	// "hello:(version)"
	// (version) is a version number
	if((cp=strchr(rbuf.buf, ':')))
	{
		cp++;
		if(cp) cconf->peer_version=strdup(cp);
	}
	iobuf_free_content(&rbuf);
	iobuf_init(&rbuf);

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

	as->write_str(as, CMD_GEN, whoareyou);
	if(as->read(as, &rbuf))
	{
		logp("unable to get client name\n");
		return -1;
	}
	cconf->cname=rbuf.buf;
	iobuf_init(&rbuf);

	as->write_str(as, CMD_GEN, "okpassword");
	if(as->read(as, &rbuf))
	{
		logp("unable to get password for client %s\n", cconf->cname);
		iobuf_free_content(&rbuf);
		return -1;
	}
	password=rbuf.buf;
	iobuf_init(&rbuf);

	if(check_client_and_password(conf, password, cconf))
	{
		free(password); password=NULL;
		return -1;
	}

	if(cconf->version_warn) version_warn(as, conf, cconf);

	logp("auth ok for: %s%s\n", cconf->cname,
		cconf->password_check?"":" (no password needed)");
	if(password) free(password);

	as->write_str(as, CMD_GEN, "ok");
	return 0;
}
