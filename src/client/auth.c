#include "include.h"

int authorise_client(struct config *conf, char **server_version)
{
	int ret=-1;
	char hello[256]="";
	struct iobuf *rbuf=NULL;

	snprintf(hello, sizeof(hello), "hello:%s", VERSION);
	if(async_write_str(CMD_GEN, hello))
	{
		logp("problem with auth\n");
		goto end;
	}

	if(!(rbuf=iobuf_async_read())
	  || rbuf->cmd!=CMD_GEN
	  || strncmp(rbuf->buf, "whoareyou", strlen("whoareyou")))
	{
		logp("problem with auth\n");
		goto end;
	}
	if(rbuf->buf)
	{
		char *cp=NULL;
		if((cp=strchr(rbuf->buf, ':')))
		{
			cp++;
			if(cp)
			{
				if(!(*server_version=strdup(cp)))
				{
					log_out_of_memory(__FUNCTION__);
					goto end;
				}
			}
		}
		iobuf_free_content(rbuf);
	}

	if(async_write_str(CMD_GEN, conf->cname)
	  || async_read_expect(CMD_GEN, "okpassword")
	  || async_write_str(CMD_GEN, conf->password)
	  || async_read(rbuf))
	{
		logp("problem with auth\n");
		goto end;
	}

	if(rbuf->cmd==CMD_WARNING) // special case for the version warning
	{
		//logw(conf->p1cntr, rbuf->buf);
		logp("WARNING: %s\n", rbuf->buf);
		conf->p1cntr->warning++;
		iobuf_free_content(rbuf);
		if(async_read(rbuf))
		{
			logp("problem with auth\n");
			goto end;
		}
	}
	if(rbuf->cmd==CMD_GEN && !strcmp(rbuf->buf, "ok"))
	{
		// It is OK.
		logp("auth ok\n");
	}
	else
	{
		iobuf_log_unexpected(rbuf, __FUNCTION__);
		goto end;
	}

	ret=0;
end:
	iobuf_free(rbuf);
	return ret;
}
