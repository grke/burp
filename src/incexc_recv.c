#include "include.h"

static int incexc_recv(char **incexc, const char *reqstr, const char *repstr, const char *endreqstr, const char *endrepstr, struct config *conf)
{
	int ret=-1;
	char *tmp=NULL;
	struct iobuf *rbuf=NULL;
	if(async_write_str(CMD_GEN, repstr))
		goto end;

	if(!(rbuf=iobuf_alloc())) goto end;
	while(1)
	{
		iobuf_free_content(rbuf);
		if(async_read(rbuf)) break;
		if(rbuf->cmd!=CMD_GEN)
		{
			iobuf_log_unexpected(rbuf, __FUNCTION__);
			goto end;
		}
		if(!strcmp(rbuf->buf, endreqstr))
		{
			if(async_write_str(CMD_GEN, endrepstr))
				goto end;
			ret=0;
			break;
		}
		if(!(tmp=prepend(*incexc?:"", rbuf->buf, rbuf->len,
			*incexc?"\n":""))) goto end;
		if(*incexc) free(*incexc);
		*incexc=tmp;
	}
	// Need to put another new line at the end.
	if(*incexc)
	{
		if(!(tmp=prepend(*incexc, "\n", 1, ""))) goto end;
		free(*incexc);
		*incexc=tmp;
	}
end:
	iobuf_free(rbuf);
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
