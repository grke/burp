#include "include.h"

static int incexc_recv(char **incexc, const char *reqstr, const char *repstr, const char *endreqstr, const char *endrepstr, struct config *conf)
{
	int ret=-1;
	char *tmp=NULL;
	struct iobuf rbuf;
	if(async_write_str(CMD_GEN, repstr))
		goto end;
	while(1)
	{
		iobuf_init(&rbuf);

		if(async_read(&rbuf)) break;
		if(rbuf.cmd==CMD_GEN)
		{
			if(!strcmp(rbuf.buf, endreqstr))
			{
				if(async_write_str(CMD_GEN, endrepstr))
					goto end;
				ret=0;
				break;
			}
			if(!(tmp=prepend(*incexc?:"", rbuf.buf, rbuf.len,
				*incexc?"\n":""))) goto end;
			if(*incexc) free(*incexc);
			*incexc=tmp;
		}
		else
		{
			logp("unexpected command when receiving %s: %c:%s\n",
				reqstr, rbuf.cmd, rbuf.buf);
			break;
		}
		if(rbuf.buf) { free(rbuf.buf); rbuf.buf=NULL; }
	}
	// Need to put another new line at the end.
	if(*incexc)
	{
		if(!(tmp=prepend(*incexc, "\n", 1, ""))) goto end;
		free(*incexc);
		*incexc=tmp;
	}
end:
	if(rbuf.buf) free(rbuf.buf);
	return ret;
}

int incexc_recv_client(char **incexc, struct config *conf)
{
	return incexc_recv(incexc,
		"sincexc", "sincexc ok",
		"sincexc end", "sincexc end ok",
		conf);
}

int incexc_recv_client_restore(char **incexc, struct config *conf)
{
	return incexc_recv(incexc,
		"srestore", "srestore ok",
		"srestore end", "srestore end ok",
		conf);
}

int incexc_recv_server(char **incexc, struct config *conf)
{
	return incexc_recv(incexc,
		"incexc", "incexc ok",
		"incexc end", "incexc end ok",
		conf);
}
