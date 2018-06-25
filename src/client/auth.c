#include "../burp.h"
#include "../alloc.h"
#include "../asfd.h"
#include "../cmd.h"
#include "../cntr.h"
#include "../handy.h"
#include "../iobuf.h"
#include "../log.h"
#include "auth.h"

int authorise_client(struct asfd *asfd,
	char **server_version, const char *cname, const char *password,
	struct cntr *cntr)
{
	int ret=-1;
	char hello[256]="";
	struct iobuf *rbuf=asfd->rbuf;

	snprintf(hello, sizeof(hello), "hello:%s", PACKAGE_VERSION);
	if(asfd->write_str(asfd, CMD_GEN, hello))
	{
		logp("problem with auth\n");
		goto end;
	}

	if(asfd->read(asfd)
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
			if(cp && !(*server_version=strdup_w(cp, __func__)))
				goto end;
		}
		iobuf_free_content(rbuf);
	}

	if(asfd->write_str(asfd, CMD_GEN, cname)
	  || asfd_read_expect(asfd, CMD_GEN, "okpassword")
	  || asfd->write_str(asfd, CMD_GEN, password)
	  || asfd->read(asfd))
	{
		logp("problem with auth\n");
		goto end;
	}

	if(rbuf->cmd==CMD_WARNING) // special case for the version warning
	{
		//logw(conf->p1cntr, rbuf->buf);
		logp("WARNING: %s\n", iobuf_to_printable(rbuf));
		cntr_add(cntr, rbuf->cmd, 0);
		iobuf_free_content(rbuf);
		if(asfd->read(asfd))
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
	iobuf_free_content(rbuf);
	return ret;
}
