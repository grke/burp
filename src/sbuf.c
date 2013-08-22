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

static int alloc_count=0;
static int free_count=0;

struct sbuf *sbuf_alloc(void)
{
	struct sbuf *sb;
	if(!(sb=(struct sbuf *)calloc(1, sizeof(struct sbuf))))
	{
		log_out_of_memory(__FUNCTION__);
		return NULL;
	}
	sb->cmd=CMD_ERROR;
	sb->compression=-1;
alloc_count++;
	return sb;
}

void sbuf_free_contents(struct sbuf *sb)
{
	if(sb->path) { free(sb->path); sb->path=NULL; }
	if(sb->attribs) { free(sb->attribs); sb->attribs=NULL; }
	if(sb->linkto) { free(sb->linkto); sb->linkto=NULL; }
//	if(sb->endfile) { free(sb->endfile); sb->endfile=NULL; }
}

void sbuf_free(struct sbuf *sb)
{
//	sbuf_close_file(sb);
	if(!sb) return;
	sbuf_free_contents(sb);
	free(sb);
free_count++;
}

void sbuf_print_alloc_stats(void)
{
	printf("sb_alloc: %d free: %d\n", alloc_count, free_count);
}

struct slist *slist_alloc(void)
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

int sbuf_to_manifest(struct sbuf *sb, gzFile zp)
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
	if(attribs_encode(sb, conf->compression)) return -1;

	if(open_file_for_send(&sb->bfd, sb->path, sb->winattr, conf))
	{
		logw(conf->cntr, "Could not open %s\n", sb->path);
		return -1;
	}
	return 0;
}

void sbuf_close_file(struct sbuf *sb)
{
	close_file_for_send(&sb->bfd);
//printf("closed: %s\n", sb->path);
}

ssize_t sbuf_read(struct sbuf *sb, char *buf, size_t bufsize)
{
	return (ssize_t)bread(&sb->bfd, buf, bufsize);
}

void sbuf_from_iobuf_path(struct sbuf *sb, struct iobuf *iobuf)
{
	if(sb->path) printf("SBUFA ALREADY SET!\n");
	sb->cmd=iobuf->cmd;
	sb->path=iobuf->buf;
	sb->plen=iobuf->len;
}

void sbuf_from_iobuf_attr(struct sbuf *sb, struct iobuf *iobuf)
{
	if(sb->attribs) printf("SBUFB ALREADY SET!\n");
	sb->attribs=iobuf->buf;
	sb->alen=iobuf->len;
}

void sbuf_from_iobuf_link(struct sbuf *sb, struct iobuf *iobuf)
{
	if(sb->linkto) printf("SBUFC ALREADY SET!\n");
	sb->linkto=iobuf->buf;
	sb->llen=iobuf->len;
}

static void set_iobuf(struct iobuf *iobuf, char cmd, char *buf, size_t len)
{
	iobuf->cmd=cmd;
	iobuf->buf=buf;
	iobuf->len=len;
}

void iobuf_from_sbuf_path(struct iobuf *iobuf, struct sbuf *sb)
{
	set_iobuf(iobuf, sb->cmd, sb->path, sb->plen);
}

void iobuf_from_sbuf_attr(struct iobuf *iobuf, struct sbuf *sb)
{
	set_iobuf(iobuf, CMD_ATTRIBS, sb->attribs, sb->alen);
}

void iobuf_from_sbuf_link(struct iobuf *iobuf, struct sbuf *sb)
{
	set_iobuf(iobuf, sb->cmd, sb->linkto, sb->llen);
}

void iobuf_from_str(struct iobuf *iobuf, char cmd, char *str)
{
	set_iobuf(iobuf, cmd, str, strlen(str));
}

// For retrieving stored data.
static struct iobuf readbuf[SIG_MAX];
static unsigned int readbuflen=0;

static int read_next_data(FILE *fp, int r)
{
	char cmd='\0';
	size_t bytes;
	unsigned int len;
	char buf[5];
	if(fread(buf, 1, 5, fp)!=5) return 0;
	if((sscanf(buf, "%c%04X", &cmd, &len))!=2)
	{
		logp("sscanf failed in %s: %s\n", __FUNCTION__, buf);
		return -1;
	}
	if(cmd!=CMD_DATA)
	{
		logp("unknown cmd in %s: %c\n", __FUNCTION__, cmd);
		return -1;
	}
	if(!(readbuf[r].buf=(char *)realloc(readbuf[r].buf, len)))
	{
		logp("Out of memory in %s\n", __FUNCTION__);
		return -1;
	}
	if((bytes=fread(readbuf[r].buf, 1, len, fp))!=len)
	{
		logp("Short read: %d wanted: %d\n", (int)bytes, (int)len);
		return -1;
	}
	readbuf[r].len=len;
	printf("read: %d:%d %04X\n", r, len, r);

	return 0;
}

static int retrieve_blk_data(struct iobuf *sigbuf, struct dpth *dpth, struct blk *blk)
{
	static char *current_dat=NULL;
	char *cp;
	char tmp[32]="";
	char datpath[256];
	unsigned int datno;

	snprintf(tmp, sigbuf->len+1, "%s", sigbuf->buf);
//printf("here: %s\n", tmp);
	snprintf(datpath, sizeof(datpath), "%s/%s", dpth->base_path_dat, tmp);
	if(!(cp=strrchr(datpath, '/')))
	{
		logp("Could not parse data path: %s\n", datpath);
		return -1;
	}
	*cp=0;
	cp++;
	datno=strtoul(cp, NULL, 16);
	if(!current_dat || strcmp(current_dat, datpath))
	{
		int r;
		FILE *dfp;
		if(current_dat) free(current_dat);
		if(!(current_dat=strdup(datpath)))
		{
			logp("Out of memory in %s\n", __FUNCTION__);
			current_dat=NULL;
			return -1;
		}
		printf("swap to: %s\n", current_dat);

		if(!(dfp=open_file(datpath, "rb"))) return -1;
		for(r=0; r<SIG_MAX; r++)
		{
			if(read_next_data(dfp, r))
			{
				fclose(dfp);
				return -1;
			}
		}
		readbuflen=r;
		fclose(dfp);
	}
	//printf("lookup: %s (%s)\n", datpath, cp);
	if(datno>readbuflen)
	{
		logp("dat index %d is greater than readbuflen: %d\n",
			datno, readbuflen);
		return -1;
	}
	blk->data=readbuf[datno].buf;
	blk->length=readbuf[datno].len;

        return 0;
}

static int do_sbuf_fill(struct sbuf *sb, gzFile zp, struct blk *blk, struct dpth *dpth, struct config *conf)
{
	static char lead[5]="";
	static iobuf *rbuf=NULL;
	static unsigned int s;

	if(!rbuf && !(rbuf=iobuf_alloc()))
	{
		log_and_send_oom(__FUNCTION__);
		return -1;
	}
	while(1)
	{
		if(zp)
		{
			size_t got;

			if((got=gzread(zp, lead, sizeof(lead)))!=5)
			{
				if(!got) return 1; // Finished OK.
				log_and_send("short read in manifest");
				break;
			}
			if((sscanf(lead, "%c%04X", &rbuf->cmd, &s))!=2)
			{
				log_and_send("sscanf failed reading manifest");
				break;
			}
			rbuf->len=(size_t)s;
			if(!(rbuf->buf=(char *)malloc(rbuf->len+2)))
			{
				log_and_send_oom(__FUNCTION__);
				break;
			}
			if(gzread(zp, rbuf->buf, rbuf->len+1)!=(int)rbuf->len+1)
			{
				log_and_send("short read in manifest");
				break;
			}
			rbuf->buf[rbuf->len]='\0';
		}
		else
		{
			// read from net
			if(async_read_ng(rbuf))
			{
				logp("error in async_read\n");
				break;
			}
		}

//printf("%c:%s\n", rbuf->cmd, rbuf->buf);

		switch(rbuf->cmd)
		{
			case CMD_ATTRIBS:
				sbuf_from_iobuf_attr(sb, rbuf);
				rbuf->buf=NULL;
				attribs_decode(sb, &sb->compression);
				break;

			case CMD_FILE:
			case CMD_DIRECTORY:
			case CMD_SOFT_LINK:
			case CMD_HARD_LINK:
			case CMD_SPECIAL:
				if(!sb->attribs)
				{
					log_and_send("read cmd with no attribs");
					break;
				}
				if(sb->need_link)
				{
					if(cmd_is_link(rbuf->cmd))
					{
						sbuf_from_iobuf_link(sb, rbuf);
						rbuf->buf=NULL;
						sb->need_link=0;
						return 0;
					}
					else
					{
						log_and_send("got non-link after link in manifest");
						break;
					}
				}
				else
				{
					sbuf_from_iobuf_path(sb, rbuf);
					rbuf->buf=NULL;
					if(cmd_is_link(rbuf->cmd))
						sb->need_link=1;
					else
						return 0;
				}
				rbuf->buf=NULL;
				break;
			case CMD_SIG:
				// Fill in the sig/block, if the caller provided
				// a pointer for one. Server only.
				if(!blk) break;
//				printf("got sig: %s\n", rbuf->buf);
				if(dpth)
				{
					if(retrieve_blk_data(rbuf, dpth, blk))
					{
						logp("Could not retrieve blk data.\n");
						free(rbuf->buf); rbuf->buf=NULL;
						return -1;
					}
				}
				else
				{
					// Just fill in the sig details.
					if(split_sig(rbuf->buf, rbuf->len,
						blk->weak, blk->strong))
					{
						free(rbuf->buf); rbuf->buf=NULL;
						return -1;
					}
					free(rbuf->buf); rbuf->buf=NULL;
				}
				return 0;
			case CMD_DATA:
				// Need to write the block to disk.
				// Client only.
				if(!blk) break;
//				printf("got data: %d\n", rbuf->len);
				blk->data=rbuf->buf;
				blk->length=rbuf->len;
				rbuf->buf=NULL;
				return 0;
			case CMD_WARNING:
				logw(conf->cntr, "%s", rbuf->buf);
				break;
			case CMD_GEN:
				if(!strcmp(rbuf->buf, "restore_end"))
				{
					free(rbuf->buf); rbuf->buf=NULL;
					return 1;
				}
				else
				{
					logp("unexpected cmd in %s: %s\n",
						__FUNCTION__, rbuf->buf);
					free(rbuf->buf); rbuf->buf=NULL;
					return -1;
				}
				break;
			case CMD_ERROR:
				printf("got error: %s\n", rbuf->buf);
				free(rbuf->buf); rbuf->buf=NULL;
				return -1;
			default:
				break;
		}
		if(rbuf->buf) { free(rbuf->buf); rbuf->buf=NULL; }
	}
	return -1;
}

int sbuf_fill_from_gzfile(struct sbuf *sb, gzFile zp, struct blk *blk, struct dpth *dpth, struct config *conf)
{
	return do_sbuf_fill(sb, zp, blk, dpth, conf);
}

int sbuf_fill_from_net(struct sbuf *sb, struct blk *blk, struct config *conf)
{
	return do_sbuf_fill(sb, NULL, blk, NULL, conf);
}
