#include "include.h"

int authorise_client(struct async *as,
	struct conf *conf, char **server_version)
{
	int ret=-1;
	char hello[256]="";
	struct iobuf *rbuf=NULL;

	snprintf(hello, sizeof(hello), "hello:%s", VERSION);
	if(as->write_str(as, CMD_GEN, hello))
	{
		logp("problem with auth\n");
		goto end;
	}

	if(!(rbuf=iobuf_async_read(as))
	  || rbuf->cmd!=CMD_GEN
	  || strncmp_w(rbuf->buf, "whoareyou"))
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
					log_out_of_memory(__func__);
					goto end;
				}
			}
		}
		iobuf_free_content(rbuf);
	}

	if(as->write_str(as, CMD_GEN, conf->cname)
	  || as->read_expect(as, CMD_GEN, "okpassword")
	  || as->write_str(as, CMD_GEN, conf->password)
	  || as->read(as, rbuf))
	{
		logp("problem with auth\n");
		goto end;
	}

	if(rbuf->cmd==CMD_WARNING) // special case for the version warning
	{
		//logw(conf->p1cntr, rbuf->buf);
		logp("WARNING: %s\n", rbuf->buf);
		cntr_add(conf->cntr, rbuf->cmd, 0);
		iobuf_free_content(rbuf);
		if(as->read(as, rbuf))
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
		iobuf_log_unexpected(rbuf, __func__);
		goto end;
	}

	ret=0;
end:
	iobuf_free(rbuf);
	return ret;
}
