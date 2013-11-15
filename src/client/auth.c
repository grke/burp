#include "include.h"

int authorise_client(struct config *conf, char **server_version)
{
	int ret=-1;
	struct iobuf rbuf;
	char hello[256]="";
	snprintf(hello, sizeof(hello), "hello:%s", VERSION);
	if(async_write_str(CMD_GEN, hello))
	{
		logp("problem with auth\n");
		goto end;
	}
	iobuf_init(&rbuf);
	if(async_read(&rbuf)
	  || rbuf.cmd!=CMD_GEN
	  || strncmp(rbuf.buf, "whoareyou", strlen("whoareyou")))
	{
		logp("problem with auth\n");
		goto end;
	}
	if(rbuf.buf)
	{
		char *cp=NULL;
		if((cp=strchr(rbuf.buf, ':')))
		{
			cp++;
			if(cp) *server_version=strdup(cp);
		}
		free(rbuf.buf);
	}
	iobuf_init(&rbuf);

	if(async_write_str(CMD_GEN, conf->cname)
	  || async_read_expect(CMD_GEN, "okpassword")
	  || async_write_str(CMD_GEN, conf->password)
	  || async_read(&rbuf))
	{
		logp("problem with auth\n");
		goto end;
	}

	if(rbuf.cmd==CMD_WARNING) // special case for the version warning
	{
		//logw(conf->p1cntr, rbuf.buf);
		logp("WARNING: %s\n", rbuf.buf);
		conf->p1cntr->warning++;
		free(rbuf.buf);
		iobuf_init(&rbuf);
		if(async_read(&rbuf))
		{
			logp("problem with auth\n");
			goto end;
		}
	}
	if(rbuf.cmd==CMD_GEN && !strcmp(rbuf.buf, "ok"))
	{
		// It is OK.
		logp("auth ok\n");
	}
	else
	{
		logp("problem with auth: got %c %s\n", rbuf.cmd, rbuf.buf);
		goto end;
	}

	ret=0;
end:
	if(rbuf.buf) free(rbuf.buf);
	return ret;
}
