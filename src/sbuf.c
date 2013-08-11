#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "lock.h"
#include "handy.h"
#include "asyncio.h"
#include "zlibio.h"
#include "counter.h"
#include "dpth.h"
#include "sbuf.h"
#include "attribs.h"

struct sbuf *sbuf_init(void)
{
	struct sbuf *sb;
	if(!(sb=(struct sbuf *)calloc(1, sizeof(struct sbuf))))
	{
		log_out_of_memory(__FUNCTION__);
		return NULL;
	}
	sb->cmd=CMD_ERROR;
	sb->compression=-1;
	return sb;
}

void sbuf_free(struct sbuf *sb)
{
//	sbuf_close_file(sb);
	if(!sb) return;
	if(sb->path) free(sb->path);
	if(sb->attribs) free(sb->attribs);
	if(sb->linkto) free(sb->linkto);
//	if(sb->endfile) free(sb->endfile);
	free(sb);
}

struct slist *slist_init(void)
{
	struct slist *slist;
	if(!(slist=(struct slist *)calloc(1, sizeof(struct slist))))
		log_out_of_memory(__FUNCTION__);
	return slist;
}

void slist_free(struct slist *slist)
{
	struct sbuf *sb;
	struct sbuf *shead;
	if(!slist) return;
	sb=slist->head;
	shead=sb;
	while(shead)
	{
		sb=shead;
		shead=shead->next;
		sbuf_free(sb);
	}
	free(slist);
}

void sbuf_add_to_list(struct sbuf *sb, struct slist *slist)
{
	if(slist->tail)
	{
		// Add to the end of the list.
		slist->tail->next=sb;
		slist->tail=sb;
		// Markers might have fallen off the end. Start them again
		// on the tail.
		if(!slist->last_requested) slist->last_requested=slist->tail;
		if(!slist->add_sigs_here) slist->add_sigs_here=slist->tail;
		if(!slist->blks_to_request) slist->blks_to_request=slist->tail;
		if(!slist->blks_to_send) slist->blks_to_send=slist->tail;
	}
	else
	{
		// Start the list.
		slist->head=sb;
		slist->tail=sb;
		// Pointers to the head that can move along the list
		// at a different rate.
		slist->last_requested=sb;
		slist->add_sigs_here=sb;
		slist->blks_to_request=sb;
		slist->blks_to_send=sb;
	}
}

int cmd_is_link(char cmd)
{
	return (cmd==CMD_SOFT_LINK || cmd==CMD_HARD_LINK);
}

int sbuf_is_link(struct sbuf *sb)
{
	return cmd_is_link(sb->cmd);
}

int sbuf_is_endfile(struct sbuf *sb)
{
	return sb->cmd==CMD_END_FILE;
}

int sbuf_fill(FILE *fp, gzFile zp, struct sbuf *sb, struct cntr *cntr)
{
	return -1;
}

static int sbuf_to_fp(struct sbuf *sb, FILE *mp, int write_endfile)
{
	if(sb->path)
	{
		if(send_msg_fp(mp, CMD_ATTRIBS, sb->attribs, sb->alen)
		  || send_msg_fp(mp, sb->cmd, sb->path, sb->plen))
			return -1;
		if(sb->linkto
		  && send_msg_fp(mp, sb->cmd, sb->linkto, sb->llen))
			return -1;
/*
		if(write_endfile && (sb->cmd==CMD_FILE
		  || sb->cmd==CMD_ENC_FILE
		  || sb->cmd==CMD_METADATA
		  || sb->cmd==CMD_ENC_METADATA
		  || sb->cmd==CMD_EFS_FILE))
		{
			if(send_msg_fp(mp, CMD_END_FILE,
				sb->endfile, sb->elen)) return -1;
		}
*/
	}
	return 0;
}

static int sbuf_to_zp(struct sbuf *sb, gzFile zp, int write_endfile)
{
	if(sb->path)
	{
		if(send_msg_zp(zp, CMD_ATTRIBS, sb->attribs, sb->alen)
		  || send_msg_zp(zp, sb->cmd, sb->path, sb->plen))
			return -1;
		if(sb->linkto
		  && send_msg_zp(zp, sb->cmd, sb->linkto, sb->llen))
			return -1;
/*
		if(write_endfile && (sb->cmd==CMD_FILE
		  || sb->cmd==CMD_ENC_FILE
		  || sb->cmd==CMD_METADATA
		  || sb->cmd==CMD_ENC_METADATA
		  || sb->cmd==CMD_EFS_FILE))
		{
			if(send_msg_zp(zp, CMD_END_FILE,
				sb->endfile, sb->elen)) return -1;
		}
*/
	}
	return 0;
}

int sbuf_to_manifest(struct sbuf *sb, FILE *mp, gzFile zp)
{
	if(mp) return sbuf_to_fp(sb, mp, 1);
	if(zp) return sbuf_to_zp(sb, zp, 1);
	logp("No valid file pointer given to sbuf_to_manifest()\n");
	return -1;
}

// Like pathcmp, but sort entries that have the same paths so that metadata
// comes later, and vss comes earlier, and trailing vss comes later.
int sbuf_pathcmp(struct sbuf *a, struct sbuf *b)
{
	int r;
	if((r=pathcmp(a->path, b->path))) return r;
	if(a->cmd==CMD_METADATA || a->cmd==CMD_ENC_METADATA)
	{
		if(b->cmd==CMD_METADATA || b->cmd==CMD_ENC_METADATA) return 0;
		else return 1;
	}
	else
	{
		if(b->cmd==CMD_METADATA || b->cmd==CMD_ENC_METADATA) return -1;
		else return 0;
	}
}

int sbuf_open_file(struct sbuf *sb, struct config *conf)
{
#ifdef HAVE_WIN32
	if(win32_lstat(sb->path, &sb->statp, &sb->winattr))
#else
	if(lstat(sb->path, &sb->statp))
#endif
	{
		// This file is no longer available.
		logw(conf->cntr, "%s has vanished\n", sb->path);
		return -1;
	}
	if(encode_stat(sb, conf->compression)) return -1;

	if(open_file_for_send(
#ifdef HAVE_WIN32
		&sb->bfd, NULL,
#else
		NULL, &sb->fp,
#endif
		sb->path, sb->winattr, conf->cntr))
	{
		logw(conf->cntr, "Could not open %s\n", sb->path);
		return -1;
	}
//printf("opened: %s\n", sb->path);
	sb->opened=1;
	return 0;
}

void sbuf_close_file(struct sbuf *sb)
{
	close_file_for_send(&sb->bfd, &sb->fp);
	sb->opened=0;
//printf("closed: %s\n", sb->path);
}

ssize_t sbuf_read(struct sbuf *sb, char *buf, size_t bufsize)
{
#ifdef HAVE_WIN32
	return (ssize_t)bread(&sb->bfd, buf, bufsize);
#else
	return fread(buf, 1, bufsize, sb->fp);
#endif
}

void sbuf_from_iobuf_path(struct sbuf *sb, struct iobuf *iobuf)
{
	sb->cmd=iobuf->cmd;
	sb->path=iobuf->buf;
	sb->plen=iobuf->len;
}

void sbuf_from_iobuf_attr(struct sbuf *sb, struct iobuf *iobuf)
{
	sb->attribs=iobuf->buf;
	sb->alen=iobuf->len;
}

void sbuf_from_iobuf_link(struct sbuf *sb, struct iobuf *iobuf)
{
	sb->linkto=iobuf->buf;
	sb->llen=iobuf->len;
}

void iobuf_from_sbuf_path(struct iobuf *iobuf, struct sbuf *sb)
{
	iobuf->cmd=sb->cmd;
	iobuf->buf=sb->path;
	iobuf->len=sb->plen;
}

void iobuf_from_sbuf_attr(struct iobuf *iobuf, struct sbuf *sb)
{
	iobuf->cmd=CMD_ATTRIBS;
	iobuf->buf=sb->attribs;
	iobuf->len=sb->alen;
}

void iobuf_from_sbuf_link(struct iobuf *iobuf, struct sbuf *sb)
{
	iobuf->cmd=sb->cmd;
	iobuf->buf=sb->linkto;
	iobuf->len=sb->llen;
}

void iobuf_from_str(struct iobuf *iobuf, char cmd, char *str)
{
	iobuf->cmd=cmd;
	iobuf->buf=str;
	iobuf->len=strlen(str);
}
