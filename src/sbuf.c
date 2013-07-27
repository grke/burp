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
	if(sb->path) free(sb->path);
	if(sb->attribs) free(sb->attribs);
	if(sb->linkto) free(sb->linkto);
	if(sb->endfile) free(sb->endfile);
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
		if(!slist->mark1) slist->mark1=slist->tail;
		if(!slist->mark2) slist->mark2=slist->tail;
	}
	else
	{
		// Start the list.
		slist->head=sb;
		slist->tail=sb;
		// Pointers to the head that can move along the list
		// at a different rate.
		slist->mark1=sb;
		slist->mark2=sb;
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

static int do_sbuf_fill_from_net(struct sbuf *sb, struct cntr *cntr)
{
	int ars;
	if((ars=async_read_stat(NULL, NULL, sb, cntr))) return ars;
	if((ars=async_read(&(sb->cmd), &(sb->path), &(sb->plen)))) return ars;
	if(sbuf_is_link(sb))
	{
		char cmd=0;
		if((ars=async_read(&cmd, &(sb->linkto), &(sb->llen))))
			return ars;
		if(!cmd_is_link(cmd))
		{
			logp("got non-link cmd after link cmd: %c %s\n",
				cmd, sb->linkto);
			return -1;
		}
	}
	return 0;
}

static int do_sbuf_fill_from_file(FILE *fp, gzFile zp, struct sbuf *sb, struct cntr *cntr)
{
	int ars;
	//free_sbuf(sb);
	if((ars=async_read_stat(fp, zp, sb, cntr))) return ars;
	if((ars=async_read_fp(fp, zp, &(sb->cmd), &(sb->path), &(sb->plen))))
		return ars;
	//sb->path[sb->plen]='\0'; sb->plen--; // avoid new line
	if(sbuf_is_link(sb))
	{
		char cmd;
		if((ars=async_read_fp(fp, zp, &cmd,
			&(sb->linkto), &(sb->llen))))
				return ars;
	//	sb->linkto[sb->llen]='\0'; sb->llen--; // avoid new line
		if(!cmd_is_link(cmd))
		{
			logp("got non-link cmd after link cmd: %c %s\n",
				cmd, sb->linkto);
			return -1;
		}
	}
	return 0;
}

int sbuf_fill(FILE *fp, gzFile zp, struct sbuf *sb, struct cntr *cntr)
{
	if(fp || zp) return do_sbuf_fill_from_file(fp, zp, sb, cntr);
	return do_sbuf_fill_from_net(sb, cntr);
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
		if(write_endfile && (sb->cmd==CMD_FILE
		  || sb->cmd==CMD_ENC_FILE
		  || sb->cmd==CMD_METADATA
		  || sb->cmd==CMD_ENC_METADATA
		  || sb->cmd==CMD_EFS_FILE))
		{
			if(send_msg_fp(mp, CMD_END_FILE,
				sb->endfile, sb->elen)) return -1;
		}
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
		if(write_endfile && (sb->cmd==CMD_FILE
		  || sb->cmd==CMD_ENC_FILE
		  || sb->cmd==CMD_METADATA
		  || sb->cmd==CMD_ENC_METADATA
		  || sb->cmd==CMD_EFS_FILE))
		{
			if(send_msg_zp(zp, CMD_END_FILE,
				sb->endfile, sb->elen)) return -1;
		}
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
printf("opened: %s\n", sb->path);
	sb->opened=1;
	return 0;
}

void sbuf_close_file(struct sbuf *sb)
{
	close_file_for_send(&sb->bfd, &sb->fp);
	sb->opened=0;
printf("closed: %s\n", sb->path);
}

ssize_t sbuf_read(struct sbuf *sb, char *buf, size_t bufsize)
{
#ifdef HAVE_WIN32
	return (ssize_t)bread(sb->bfd, buf, bufsize);
#else
	return fread(buf, 1, bufsize, sb->fp);
#endif
}
