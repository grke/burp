#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "lock.h"
#include "rs_buf.h"
#include "handy.h"
#include "asyncio.h"
#include "zlibio.h"
#include "counter.h"
#include "dpth.h"
#include "sbuf.h"
#include "auth_server.h"

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

static int check_client_and_password(struct config *conf, const char *client, const char *password, struct config *cconf)
{
	// Cannot load it until here, because we need to have the name of the
	// client.
	if(load_client_config(conf, cconf, client)) return -1;

	if(!cconf->ssl_peer_cn)
	{
		logp("ssl_peer_cn unset");
		if(client)
		{
			logp("Falling back to using '%s'\n", client);
			if(!(cconf->ssl_peer_cn=strdup(client)))
			{
				logp("out of memory\n");
				return -1;
			}
		}
	}

	if(cconf->password_check)
	{
		if(!cconf->password && !cconf->passwd)
		{
			logp("password rejected for client %s\n", client);
			return -1;
		}
		// check against plain text
		if(cconf->password && strcmp(cconf->password, password))
		{
			logp("password rejected for client %s\n", client);
			return -1;
		}
		// check against encypted passwd
		if(cconf->passwd && !check_passwd(cconf->passwd, password))
		{
			logp("password rejected for client %s\n", client);
			return -1;
		}
	}

	if(!cconf->keep)
	{
		logp("%s: you cannot set the keep value for a client to 0!\n",
				client);
		return -1;
	}
	return 0;
}

void version_warn(struct cntr *cntr, const char *client, const char *cversion)
{
	if(!cversion || strcmp(cversion, VERSION))
	{
		char msg[256]="";

		if(!cversion || !*cversion)
			snprintf(msg, sizeof(msg), "Client '%s' has an unknown version. Please upgrade.", client?client:"unknown");
		else
			snprintf(msg, sizeof(msg), "Client '%s' version '%s' does not match server version '%s'. An upgrade is recommended.", client?client:"unknown", cversion, VERSION);
		if(cntr) logw(cntr, "%s", msg);
		logp("WARNING: %s\n", msg);
	}
}

int authorise_server(struct config *conf, char **client, char **cversion, struct config *cconf, struct cntr *p1cntr)
{
	char cmd;
	char *cp=NULL;
	size_t len=0;
	char *buf=NULL;
	char *password=NULL;
	char whoareyou[256]="";
	if(async_read(&cmd, &buf, &len))
	{
		logp("unable to read initial message\n");
		return -1;
	}
	if(cmd!=CMD_GEN || strncmp(buf, "hello", strlen("hello")))
	{
		logp("unexpected command given: %c %s\n", cmd, buf);
		free(buf);
		return -1;
	}
	// String may look like...
	// "hello"
	// "hello:(version)"
	// (version) is a version number
	if((cp=strchr(buf, ':')))
	{
		cp++;
		if(cp) *cversion=strdup(cp);
	}
	free(buf); buf=NULL;

	snprintf(whoareyou, sizeof(whoareyou), "whoareyou");
	if(*cversion)
	{
		long min_ver=0;
		long cli_ver=0;
		if((min_ver=version_to_long("1.3.2"))<0
		  || (cli_ver=version_to_long(*cversion))<0)
			return -1;
		// Stick the server version on the end of the whoareyou string.
		// if the client version is recent enough.
		if(min_ver<=cli_ver)
		 snprintf(whoareyou, sizeof(whoareyou),
			"whoareyou:%s", VERSION);
	}

	async_write_str(CMD_GEN, whoareyou);
	if(async_read(&cmd, &buf, &len) || !len)
	{
		logp("unable to get client name\n");
		if(*cversion) free(*cversion); *cversion=NULL;
		return -1;
	}
	*client=buf;
	buf=NULL;
	async_write_str(CMD_GEN, "okpassword");
	if(async_read(&cmd, &buf, &len) || !len)
	{
		logp("unable to get password for client %s\n", *client);
		if(*client) free(*client); *client=NULL;
		if(*cversion) free(*cversion); *cversion=NULL;
		free(buf); buf=NULL;
		return -1;
	}
	password=buf;
	buf=NULL;

	if(check_client_and_password(conf, *client, password, cconf))
	{
		if(*client) free(*client); *client=NULL;
		if(*cversion) free(*cversion); *cversion=NULL;
		free(password); password=NULL;
		return -1;
	}

	if(cconf->version_warn)
		version_warn(p1cntr, *client, *cversion);

	logp("auth ok for: %s%s\n", *client,
		cconf->password_check?"":" (no password needed)");
	if(password) free(password);

	async_write_str(CMD_GEN, "ok");
	return 0;
}
