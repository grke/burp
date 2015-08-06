#include "include.h"
#include "pathcmp.h"
#include "cmd.h"

struct iobuf *iobuf_alloc(void)
{
	struct iobuf *iobuf;
	if(!(iobuf=(struct iobuf *)calloc_w(1, sizeof(struct iobuf), __func__)))
		return NULL;
	iobuf_init(iobuf);
	return iobuf;
}

void iobuf_set(struct iobuf *iobuf, enum cmd cmd, char *buf, size_t len)
{
	iobuf->cmd=cmd;
	iobuf->buf=buf;
	iobuf->len=len;
}

void iobuf_init(struct iobuf *iobuf)
{
	iobuf_set(iobuf, CMD_ERROR, NULL, 0);
}

void iobuf_free_content(struct iobuf *iobuf)
{
	if(!iobuf) return;
	free_w(&iobuf->buf);
	iobuf_init(iobuf);
}

void iobuf_free(struct iobuf **iobuf)
{
	if(!iobuf || *iobuf) return;
	iobuf_free_content(*iobuf);
	free_v((void **)iobuf);
}

void iobuf_log_unexpected(struct iobuf *iobuf, const char *func)
{
	logp("unexpected command in %s(): %c:%s\n",
		func, iobuf->cmd, iobuf->buf);
}

void iobuf_copy(struct iobuf *dst, struct iobuf *src)
{
	iobuf_set(dst, src->cmd, src->buf, src->len);
}

void iobuf_move(struct iobuf *dst, struct iobuf *src)
{
	iobuf_copy(dst, src);
	src->buf=NULL;
}

void iobuf_from_str(struct iobuf *iobuf, enum cmd cmd, char *str)
{
	iobuf_set(iobuf, cmd, str, strlen(str));
}

int iobuf_send_msg_fzp(struct iobuf *iobuf, struct fzp *fzp)
{
	return send_msg_fzp(fzp, iobuf->cmd, iobuf->buf, iobuf->len);
}

int iobuf_pathcmp(struct iobuf *a, struct iobuf *b)
{
	int r;
	if((r=pathcmp(a->buf, b->buf))) return r;
	if(a->cmd==CMD_METADATA || a->cmd==CMD_ENC_METADATA)
	{
		if(b->cmd==CMD_METADATA || b->cmd==CMD_ENC_METADATA) return 0;
		else return 1;
	}
	else if(a->cmd==CMD_VSS || a->cmd==CMD_ENC_VSS)
	{
		if(b->cmd==CMD_VSS || b->cmd==CMD_ENC_VSS) return 0;
		else return -1;
	}
	else if(a->cmd==CMD_VSS_T || a->cmd==CMD_ENC_VSS_T)
	{
		if(b->cmd==CMD_VSS_T || b->cmd==CMD_ENC_VSS_T) return 0;
		else return 1;
	}
	else
	{
		if(b->cmd==CMD_METADATA || b->cmd==CMD_ENC_METADATA) return -1;
		else if(b->cmd==CMD_VSS || b->cmd==CMD_ENC_VSS) return 1;
		else if(b->cmd==CMD_VSS_T || b->cmd==CMD_ENC_VSS_T) return -1;
		else return 0;
	}
}

int iobuf_is_filedata(struct iobuf *iobuf)
{
	return cmd_is_filedata(iobuf->cmd);
}

int iobuf_is_vssdata(struct iobuf *iobuf)
{
	return cmd_is_vssdata(iobuf->cmd);
}

int iobuf_is_link(struct iobuf *iobuf)
{
	return cmd_is_link(iobuf->cmd);
}

int iobuf_is_encrypted(struct iobuf *iobuf)
{
	return cmd_is_encrypted(iobuf->cmd);
}

int iobuf_is_metadata(struct iobuf *iobuf)
{
	return cmd_is_metadata(iobuf->cmd);
}

static int do_iobuf_fill_from_fzp(struct iobuf *iobuf, struct fzp *fzp,
	int extra_bytes)
{
	static unsigned int s;
	static char lead[5]="";

	switch(fzp_read_ensure(fzp, lead, sizeof(lead), __func__))
	{
		case 0: break; // OK.
		case 1: return 1; // Finished OK.
		default: return -1; // Error.
	}
	if((sscanf(lead, "%c%04X", (char *)&iobuf->cmd, &s))!=2)
	{
		logp("sscanf failed reading manifest: %s\n", lead);
		return -1;
	}
	iobuf->len=(size_t)s;
	if(!(iobuf->buf=(char *)malloc_w(
		iobuf->len+extra_bytes+1, __func__)))
			return -1;
	switch(fzp_read_ensure(fzp,
		iobuf->buf, iobuf->len+extra_bytes, __func__))
	{
		case 0: break; // OK.
		case 1: return 1; // Finished OK.
		default: return -1; // Error.
	}
	iobuf->buf[iobuf->len]='\0';
	return 0;
}

int iobuf_fill_from_fzp(struct iobuf *iobuf, struct fzp *fzp)
{
	return do_iobuf_fill_from_fzp(iobuf, fzp, 1 /*newline*/);
}

int iobuf_fill_from_fzp_data(struct iobuf *iobuf, struct fzp *fzp)
{
	return do_iobuf_fill_from_fzp(iobuf, fzp, 0 /*no newline*/);
}
