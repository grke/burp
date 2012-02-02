#include "burp.h"
#include "prog.h"
#include "counter.h"
#include "conf.h"
#include "msg.h"
#include "handy.h"
#include "cmd.h"
#include "asyncio.h"

int incexc_recv_server(char **incexc, struct config *conf, struct cntr *p1cntr)
{
	int ret=-1;
	char *tmp=NULL;
	char *buf=NULL;
	if(async_write_str(CMD_GEN, "incexc ok"))
		goto end;
	while(1)
	{
		char cmd;
		size_t len=0;

		if(async_read(&cmd, &buf, &len))
			break;
		if(cmd==CMD_GEN)
		{
			if(!strcmp(buf, "incexc end"))
			{
				if(async_write_str(CMD_GEN, "incexc end ok"))
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
			logp("unexpected command from client when receiving incexc: %c:%s\n", cmd, buf);
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
