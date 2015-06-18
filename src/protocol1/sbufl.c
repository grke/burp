#include "../burp.h"
#include "../attribs.h"
#include "../cmd.h"
#include "../log.h"
#include "../sbuf.h"

static int unexpected(struct iobuf *rbuf, const char *func)
{
	iobuf_log_unexpected(rbuf, func);
	iobuf_free_content(rbuf);
	return -1;
}

static int read_stat(struct asfd *asfd, struct iobuf *rbuf,
	struct sbuf *sb, struct conf **confs)
{
	while(1)
	{
		iobuf_free_content(rbuf);
		if(asfd->read(asfd))
			break;
		if(rbuf->cmd==CMD_MESSAGE
		  || rbuf->cmd==CMD_WARNING)
		{
			log_recvd(rbuf, confs, 0);
		}
		else if(rbuf->cmd==CMD_DATAPTH)
		{
			iobuf_move(&(sb->protocol1->datapth), rbuf);
		}
		else if(rbuf->cmd==CMD_ATTRIBS)
		{
			iobuf_move(&sb->attr, rbuf);
			attribs_decode(sb);

			return 0;
		}
		else if((rbuf->cmd==CMD_GEN && !strcmp(rbuf->buf, "backupend"))
		  || (rbuf->cmd==CMD_GEN && !strcmp(rbuf->buf, "restoreend"))
		  || (rbuf->cmd==CMD_GEN && !strcmp(rbuf->buf, "phase1end"))
		  || (rbuf->cmd==CMD_GEN && !strcmp(rbuf->buf, "backupphase2"))
		  || (rbuf->cmd==CMD_GEN && !strcmp(rbuf->buf, "estimateend")))
		{
			iobuf_free_content(rbuf);
			return 1;
		}
		else
			return unexpected(rbuf, __func__);
	}
	iobuf_free_content(rbuf);
	return -1;
}

int sbufl_fill_from_net(struct sbuf *sb, struct asfd *asfd,
	struct conf **confs)
{
	int ars;
	static struct iobuf *rbuf=NULL;
	rbuf=asfd->rbuf;
	iobuf_free_content(rbuf);
	if((ars=read_stat(asfd, rbuf, sb, confs))
	  || (ars=asfd->read(asfd))) return ars;
	iobuf_move(&sb->path, rbuf);
	if(sbuf_is_link(sb))
	{
		if((ars=asfd->read(asfd))) return ars;
		iobuf_move(&sb->link, rbuf);
		if(!cmd_is_link(rbuf->cmd))
			return unexpected(rbuf, __func__);
	}
	return 0;
}
