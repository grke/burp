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

static int check_client_and_password(struct config *conf, const char *client, const char *password, struct config *cconf)
{
	char cpath[256]="";
	snprintf(cpath, sizeof(cpath), "%s/%s", conf->clientconfdir, client);

	// Some client settings can be globally set in the server config and
	// overridden in the client specific config.
	init_config(cconf);
	if(set_client_global_config(conf, cconf)
	  || load_config(cpath, cconf, 0))
		return -1;

	if(!cconf->password || strcmp(cconf->password, password))
	{
		logp("password rejected for client %s\n", client);
		return -1;
	}
	if(!cconf->keep)
	{
		logp("%s: you cannot set the keep value for a client to 0!\n",
				client);
		return -1;
	}
	return 0;
}

int authorise_server(struct config *conf, char **client, struct config *cconf)
{
	char cmd;
	size_t len=0;
	char *buf=NULL;
	char *password=NULL;
	if(async_read(&cmd, &buf, &len))
	{
		logp("unable to read initial message\n");
		return -1;
	}
	if(cmd!='c' || strcmp(buf, "hello"))
	{
		logp("unexpected command given: %c %s\n", cmd, buf);
		free(buf);
		return -1;
	}
	free(buf); buf=NULL;
	async_write_str('c', "whoareyou");
	if(async_read(&cmd, &buf, &len) || !len)
	{
		logp("unable to get client name\n");
		return -1;
	}
	*client=buf;
	buf=NULL;
	async_write_str('c', "okpassword");
	if(async_read(&cmd, &buf, &len) || !len)
	{
		logp("unable to get password for client %s\n", *client);
		if(*client) free(*client); *client=NULL;
		free(buf); buf=NULL;
		return -1;
	}
	password=buf;
	buf=NULL;

	if(check_client_and_password(conf, *client, password, cconf))
	{
		if(*client) free(*client); *client=NULL;
		free(password); password=NULL;
		return -1;
	}

	async_write_str('c', "ok");
	logp("auth ok for client: %s\n", *client);
	if(password) free(password);
	return 0;
}
