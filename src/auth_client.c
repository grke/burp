#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "lock.h"
#include "handy.h"
#include "asyncio.h"
#include "zlibio.h"
#include "counter.h"
#include "dpth.h"
#include "sbuf.h"
#include "auth_client.h"

int authorise_client(struct config *conf, char **server_version)
{
	char cmd=0;
	char *buf=NULL;
	size_t l=0;
	char hello[256]="";
	snprintf(hello, sizeof(hello),
		"hello:%s",
		VERSION);
	if(async_write_str(CMD_GEN, hello))
	{
		logp("problem with auth\n");
		return -1;
	}
	if(async_rw_ensure_read(&cmd, &buf, &l, '\0', NULL, 0)
	  || cmd!=CMD_GEN || strncmp(buf, "whoareyou", strlen("whoareyou")))
	{
		logp("problem with auth\n");
		if(buf) free(buf);
		return -1;
	}
	if(buf)
	{
		char *cp=NULL;
		if((cp=strchr(buf, ':')))
		{
			cp++;
			if(cp) *server_version=strdup(cp);
		}
		free(buf);
		buf=NULL;
	}


	if(async_write_str(CMD_GEN, conf->cname)
	  || async_read_expect(CMD_GEN, "okpassword")
	  || async_write_str(CMD_GEN, conf->password)
	  || async_read(&cmd, &buf, &l))
	{
		logp("problem with auth\n");
		return -1;
	}

	if(cmd==CMD_WARNING) // special case for the version warning
	{
		//logw(conf->p1cntr, buf);
		logp("WARNING: %s\n", buf);
		conf->p1cntr->warning++;
		free(buf); buf=NULL;
		if(async_read(&cmd, &buf, &l))
		{
			logp("problem with auth\n");
			free(buf);
			return -1;
		}
	}
	if(cmd==CMD_GEN && !strcmp(buf, "ok"))
	{
		// It is OK.
		logp("auth ok\n");
	}
	else
	{
		logp("problem with auth: got %c %s\n", cmd, buf);
		free(buf);
		return -1;
	}

	if (buf)
		free(buf);
	
	return 0;
}
