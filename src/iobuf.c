#include "include.h"

struct iobuf *iobuf_alloc(void)
{
	struct iobuf *iobuf;
	if(!(iobuf=(struct iobuf *)calloc(1, sizeof(struct iobuf))))
	{
		log_out_of_memory(__FUNCTION__);
		return NULL;
	}
	iobuf_init(iobuf);
	return iobuf;
}

void iobuf_init(struct iobuf *iobuf)
{
	iobuf->cmd=CMD_ERROR;
	iobuf->buf=NULL;
	iobuf->len=0;
}

void iobuf_free_content(struct iobuf *iobuf)
{
	if(!iobuf || !iobuf->buf) return;
	free(iobuf->buf);
	iobuf_init(iobuf);
}

void iobuf_free(struct iobuf *iobuf)
{
	iobuf_free_content(iobuf);
	if(iobuf) free(iobuf);
}

struct iobuf *iobuf_async_read(void)
{
	struct iobuf *iobuf;
	if(!(iobuf=iobuf_alloc()) || async_read(iobuf))
	{
		iobuf_free(iobuf);
		return NULL;
	}
	return iobuf;
}

void iobuf_log_unexpected(struct iobuf *iobuf, const char *func)
{
	logp("unexpected command in %s(): %c:%s\n",
		func, iobuf->cmd, iobuf->buf);
}

void iobuf_copy(struct iobuf *dst, struct iobuf *src)
{
	dst->cmd=src->cmd;
	dst->buf=src->buf;
	dst->len=src->len;
}

void iobuf_from_str(struct iobuf *iobuf, char cmd, char *str)
{
	iobuf->cmd=cmd;
	iobuf->buf=str;
	iobuf->len=strlen(str);
}

int iobuf_send_msg_fp(struct iobuf *iobuf, FILE *fp)
{
	return send_msg_fp(fp, iobuf->cmd, iobuf->buf, iobuf->len);
}

int iobuf_send_msg_zp(struct iobuf *iobuf, gzFile zp)
{
	return send_msg_zp(zp, iobuf->cmd, iobuf->buf, iobuf->len);
}
