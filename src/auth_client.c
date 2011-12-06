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
#include "auth_client.h"

int authorise_client(struct config *conf, struct cntr *p1cntr)
{
	char cmd;
	char *buf=NULL;
	size_t l=0;
	char hello[256]="";
	snprintf(hello, sizeof(hello), "hello:%s", VERSION);
	if(async_write_str(CMD_GEN, hello)
	  || async_read_expect(CMD_GEN, "whoareyou")
	  || async_write_str(CMD_GEN, conf->cname)
	  || async_read_expect(CMD_GEN, "okpassword")
	  || async_write_str(CMD_GEN, conf->password)
	  || async_read(&cmd, &buf, &l))
	{
		logp("problem with auth\n");
		return -1;
	}

	if(cmd==CMD_WARNING) // special case for the version warning
	{
		//logw(p1cntr, buf);
		logp("WARNING: %s\n", buf);
		p1cntr->warning++;
		if(async_read_expect(CMD_GEN, "ok"))
		{
			logp("problem with auth\n");
			free(buf);
			return -1;
		}
	}
	else if(cmd==CMD_GEN && !strcmp(buf, "ok"))
	{
		// It is OK.
	}
	else
	{
		logp("problem with auth: got %c %s\n", cmd, buf);
		free(buf);
		return -1;
	}
	free(buf);

	logp("auth ok\n");
	return 0;
}
