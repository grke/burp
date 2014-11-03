#include "burp.h"
#include "prog.h"
#include "counter.h"
#include "conf.h"
#include "msg.h"
#include "handy.h"
#include "cmd.h"
#include "asyncio.h"
#include "incexc_recv.h"

static int incexc_recv(char **incexc, const char *reqstr, const char *repstr, const char *endreqstr, const char *endrepstr, struct config *conf, struct cntr *p1cntr)
{
	int ret=-1;
	char *tmp=NULL;
	char *buf=NULL;
	if(async_write_str(CMD_GEN, repstr))
		goto end;
	while(1)
	{
		char cmd;
		size_t len=0;

		if(async_read(&cmd, &buf, &len))
			break;
		if(cmd==CMD_GEN)
		{
			if(!strcmp(buf, endreqstr))
			{
				if(async_write_str(CMD_GEN, endrepstr))
					goto end;
				ret=0;
				break;
			}
			if(!(tmp=prepend(*incexc?:"", buf, strlen(buf),
				*incexc?"\n":"")))
					goto end;
			if(*incexc) free(*incexc);
			*incexc=tmp;
		}
		else
		{
			logp("unexpected command when receiving %s: %c:%s\n",
				reqstr, cmd, buf);
			break;
		}
		if(buf) { free(buf); buf=NULL; }
	}
	// Need to put another new line at the end.
	if(*incexc)
	{
		if(!(tmp=prepend(*incexc, "\n", 1, "")))
			goto end;
		free(*incexc);
		*incexc=tmp;
	}
end:
	if(buf) free(buf);
	return ret;
}

int incexc_recv_client(char **incexc, struct config *conf, struct cntr *p1cntr)
{
	return incexc_recv(incexc,
		"sincexc", "sincexc ok",
		"sincexc end", "sincexc end ok",
		conf, p1cntr);
}

int incexc_recv_client_restore(char **incexc, struct config *conf, struct cntr *p1cntr)
{
	return incexc_recv(incexc,
		"srestore", "srestore ok",
		"srestore end", "srestore end ok",
		conf, p1cntr);
}

int incexc_recv_client_quota(char **incexc, struct config *conf, struct cntr *p1cntr)
{
	return incexc_recv(incexc,
		"quota", "quota ok",
		"quota end", "quota end ok",
		conf, p1cntr);
}

int incexc_recv_server(char **incexc, struct config *conf, struct cntr *p1cntr)
{
	return incexc_recv(incexc,
		"incexc", "incexc ok",
		"incexc end", "incexc end ok",
		conf, p1cntr);
}
