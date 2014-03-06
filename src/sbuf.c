#include "include.h"

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
	sb->path.cmd=CMD_ERROR;
	sb->attr.cmd=CMD_ATTRIBS;
	sb->compression=-1;
alloc_count++;
	return sb;
}

void sbuf_free_contents(struct sbuf *sb)
{
	if(sb->path.buf) { free(sb->path.buf); sb->path.buf=NULL; }
	if(sb->attr.buf) { free(sb->attr.buf); sb->attr.buf=NULL; }
	if(sb->link.buf) { free(sb->link.buf); sb->link.buf=NULL; }
}

void sbuf_free(struct sbuf *sb)
{
//	sbuf_close_file(sb);
	if(!sb) return;
	sbuf_free_contents(sb);
//printf("sbuf_free: %p\n", sb);
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
	shead=slist->head;
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
	return cmd_is_link(sb->path.cmd);
}

int sbuf_is_endfile(struct sbuf *sb)
{
	return sb->path.cmd==CMD_END_FILE;
}

int sbuf_to_manifest(struct sbuf *sb, gzFile zp)
{
	if(sb->path.buf)
	{
		// Hackity hack: Strip the file index from the beginning of
		// the attribs so that manifests where nothing changed are
		// identical to each other. Better would be to preserve the
		// index.
		char *cp;
		if(!(cp=strchr(sb->attr.buf, ' ')))
		{
			logp("Strange attributes: %s\n", sb->attr.buf);
			return -1;
		}
		if(send_msg_zp(zp, CMD_ATTRIBS,
			cp, sb->attr.len-(cp-sb->attr.buf))
		  || send_msg_zp(zp, sb->path.cmd, sb->path.buf, sb->path.len))
			return -1;
		if(sb->link.buf
		  && send_msg_zp(zp, sb->link.cmd, sb->link.buf, sb->link.len))
			return -1;
	}
	return 0;
}

// Like pathcmp, but sort entries that have the same paths so that metadata
// comes later, and vss comes earlier, and trailing vss comes later.
int sbuf_pathcmp(struct sbuf *a, struct sbuf *b)
{
	int r;
	if((r=pathcmp(a->path.buf, b->path.buf))) return r;
	if(a->path.cmd==CMD_METADATA || a->path.cmd==CMD_ENC_METADATA)
	{
		if(b->path.cmd==CMD_METADATA
		  || b->path.cmd==CMD_ENC_METADATA) return 0;
		else return 1;
	}
	else
	{
		if(b->path.cmd==CMD_METADATA
		  || b->path.cmd==CMD_ENC_METADATA) return -1;
		else return 0;
	}
}

int sbuf_open_file(struct sbuf *sb, struct config *conf)
{
#ifdef HAVE_WIN32
	if(win32_lstat(sb->path.buf, &sb->statp, &sb->winattr))
#else
	if(lstat(sb->path.buf, &sb->statp))
#endif
	{
		// This file is no longer available.
		logw(conf->cntr, "%s has vanished\n", sb->path.buf);
		return -1;
	}
	sb->compression=conf->compression;
	if(sbuf_attribs_encode(sb, conf)) return -1;

	if(open_file_for_send(&sb->bfd, sb->path.buf, sb->winattr, conf))
	{
		logw(conf->cntr, "Could not open %s\n", sb->path.buf);
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

// For retrieving stored data.
struct rblk
{
	char *datpath;
	struct iobuf readbuf[SIG_MAX];
	unsigned int readbuflen;
};

#define RBLK_MAX	10

static int read_next_data(FILE *fp, struct rblk *rblk, int ind, int r)
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
	if(!(rblk[ind].readbuf[r].buf=
		(char *)realloc(rblk[ind].readbuf[r].buf, len)))
	{
		logp("Out of memory in %s\n", __FUNCTION__);
		return -1;
	}
	if((bytes=fread(rblk[ind].readbuf[r].buf, 1, len, fp))!=len)
	{
		logp("Short read: %d wanted: %d\n", (int)bytes, (int)len);
		return -1;
	}
	rblk[ind].readbuf[r].len=len;
	//printf("read: %d:%d %04X\n", r, len, r);

	return 0;
}

static int load_rblk(struct rblk *rblks, int ind, const char *datpath)
{
	int r;
	FILE *dfp;
	if(rblks[ind].datpath) free(rblks[ind].datpath);
	if(!(rblks[ind].datpath=strdup(datpath)))
	{
		logp("Out of memory in %s\n", __FUNCTION__);
		return -1;
	}
	printf("swap %d to: %s\n", ind, datpath);

	if(!(dfp=open_file(datpath, "rb"))) return -1;
	for(r=0; r<SIG_MAX; r++)
	{
		if(read_next_data(dfp, rblks, ind, r))
		{
			fclose(dfp);
			return -1;
		}
	}
	rblks[ind].readbuflen=r;
	fclose(dfp);
	return 0;
}

static struct rblk *get_rblk(struct rblk *rblks, const char *datpath)
{
	static int current_ind=0;
	static int last_swap_ind=0;
	int ind=current_ind;

	while(1)
	{
		if(!rblks[ind].datpath)
		{
			if(load_rblk(rblks, ind, datpath)) return NULL;
			last_swap_ind=ind;
			current_ind=ind;
			return &rblks[current_ind];
		}
		else if(!strcmp(rblks[ind].datpath, datpath))
		{
			current_ind=ind;
			return &rblks[current_ind];
		}
		ind++;
		if(ind==RBLK_MAX) ind=0;
		if(ind==current_ind)
		{
			// Went through all RBLK_MAX entries.
			// Replace the oldest one.
			ind=last_swap_ind+1;
			if(ind==RBLK_MAX) ind=0;
			if(load_rblk(rblks, ind, datpath)) return NULL;
			last_swap_ind=ind;
			current_ind=ind;
			return &rblks[current_ind];
		}
	}
}

static int retrieve_blk_data(char *datpath, struct blk *blk)
{
	static char fulldatpath[256]="";
	static struct rblk *rblks=NULL;
	char *cp;
	unsigned int datno;
	struct rblk *rblk;

	snprintf(fulldatpath, sizeof(fulldatpath),
		"%s/%s", datpath, blk->save_path);

//printf("x: %s\n", fulldatpath);
	if(!(cp=strrchr(fulldatpath, '/')))
	{
		logp("Could not parse data path: %s\n", fulldatpath);
		return -1;
	}
	*cp=0;
	cp++;
	datno=strtoul(cp, NULL, 16);
//printf("y: %s\n", fulldatpath);

	if(!rblks
	  && !(rblks=(struct rblk *)calloc(RBLK_MAX, sizeof(struct rblk))))
	{
		logp("Out of memory in %s\n", __FUNCTION__);
		return -1;
	}

	if(!(rblk=get_rblk(rblks, fulldatpath)))
	{
		return -1;
	}

//	printf("lookup: %s (%s)\n", fulldatpath, cp);
	if(datno>rblk->readbuflen)
	{
		logp("dat index %d is greater than readbuflen: %d\n",
			datno, rblk->readbuflen);
		return -1;
	}
	blk->data=rblk->readbuf[datno].buf;
	blk->length=rblk->readbuf[datno].len;
//	printf("length: %d\n", blk->length);

        return 0;
}

int sbuf_fill(struct sbuf *sb, gzFile zp, struct blk *blk, char *datpath, struct config *conf)
{
	static char lead[5]="";
	static iobuf *rbuf=NULL;
	static unsigned int s;
	int ret=-1;

	if(!rbuf && !(rbuf=iobuf_alloc()))
	{
		log_and_send_oom(__FUNCTION__);
		goto end;
	}
	while(1)
	{
		iobuf_free_content(rbuf);
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
				logp("%s\n", lead);
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
			if(async_read(rbuf))
			{
				logp("error in async_read\n");
				break;
			}
		}

		switch(rbuf->cmd)
		{
			case CMD_ATTRIBS:
				// I think these frees are hacks. Probably,
				// the calling function should deal with this.
				// FIX THIS.
				if(sb->attr.buf)
				{
					free(sb->attr.buf);
					sb->attr.buf=NULL;
				}
				if(sb->path.buf)
				{
					free(sb->path.buf);
					sb->path.buf=NULL;
				}
				if(sb->link.buf)
				{
					free(sb->link.buf);
					sb->link.buf=NULL;
				}
				iobuf_copy(&sb->attr, rbuf);
				rbuf->buf=NULL;
				sbuf_attribs_decode(sb, conf);
				break;

			case CMD_FILE:
			case CMD_DIRECTORY:
			case CMD_SOFT_LINK:
			case CMD_HARD_LINK:
			case CMD_SPECIAL:
			// Stuff not currently supported in burp-2, but OK
			// to find in burp-1.
			case CMD_ENC_FILE:
			case CMD_METADATA:
			case CMD_ENC_METADATA:
			case CMD_EFS_FILE:
			case CMD_VSS:
			case CMD_ENC_VSS:
			case CMD_VSS_T:
			case CMD_ENC_VSS_T:
				if(!sb->attr.buf)
				{
					log_and_send("read cmd with no attribs");
					break;
				}
				if(sb->need_link)
				{
					if(cmd_is_link(rbuf->cmd))
					{
						iobuf_copy(&sb->link, rbuf);
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
					iobuf_copy(&sb->path, rbuf);
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
				//printf("got sig: %s\n", rbuf->buf);

				// Just fill in the sig details.
				if(split_sig_with_save_path(rbuf->buf,
					rbuf->len,
					blk->weak, blk->strong,
					blk->save_path))
						goto end;
				iobuf_free_content(rbuf);
				if(datpath)
				{
					if(retrieve_blk_data(datpath, blk))
					{
						logp("Could not retrieve blk data.\n");
						goto end;
					}
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
					ret=1;
					goto end;
				}
				else
				{
					iobuf_log_unexpected(rbuf,
						__FUNCTION__);
					goto end;
				}
				break;
			case CMD_MANIFEST:
			case CMD_FINGERPRINT:
				iobuf_copy(&sb->path, rbuf);
				rbuf->buf=NULL;
				return 0;
			case CMD_ERROR:
				printf("got error: %s\n", rbuf->buf);
				goto end;
			// Stuff that is currently legacy. OK to find these
			// in burp-1, but not burp-2.
			case CMD_DATAPTH:
			case CMD_END_FILE:
				if(conf->legacy) continue;
			default:
				iobuf_log_unexpected(rbuf, __FUNCTION__);
				goto end;
		}
	}
end:
	iobuf_free_content(rbuf);
	return ret;
}

int sbuf_fill_from_gzfile(struct sbuf *sb, gzFile zp, struct blk *blk, char *datpath, struct config *conf)
{
	return sbuf_fill(sb, zp, blk, datpath, conf);
}

int sbuf_fill_from_net(struct sbuf *sb, struct blk *blk, struct config *conf)
{
	return sbuf_fill(sb, NULL, blk, NULL, conf);
}

int sbuf_attribs_encode(struct sbuf *sb, struct config *conf)
{
	return attribs_encode(&sb->statp, &sb->attr,
		sb->winattr, sb->compression,
		conf->legacy?NULL:&sb->index);
}

void sbuf_attribs_decode(struct sbuf *sb, struct config *conf)
{
	return attribs_decode(&sb->statp, &sb->attr,
		&sb->winattr, &sb->compression,
		conf->legacy?NULL:&sb->index);
}
