#include "include.h"
#include "../../burp2/rabin/include.h"

/* Ignore extrameta for now.
#ifndef HAVE_WIN32
static int maybe_send_extrameta(struct sbuf *sb, char cmd, struct cntr *p1cntr)
{
	if(has_extrameta(sb->path, cmd))
	{
		if(async_write_str(CMD_ATTRIBS, sb->attribs)
		  || async_write_str(CMD_METADATA, sb->path))
			return -1;
		cntr_add(p1cntr, CMD_METADATA, 1);
	}
	return 0;
}
#endif
*/

static uint64_t decode_req(const char *buf)
{
	int64_t val;
	const char *p=buf;
	p+=from_base64(&val, p);
	return (uint64_t)val;
}

static int add_to_file_requests(struct slist *slist, struct iobuf *rbuf,
	struct conf *conf)
{
	static uint64_t file_no=1;
	struct sbuf *sb;

	if(!(sb=sbuf_alloc(conf))) return -1;

	iobuf_copy(&sb->path, rbuf);
	rbuf->buf=NULL;
	// Give it a number to simplify tracking.
	sb->burp2->index=file_no++;
	slist_add_sbuf(slist, sb);

	return 0;
}

static int add_to_data_requests(struct blist *blist, struct iobuf *rbuf)
{
	uint64_t index;
	struct blk *blk;
	index=decode_req(rbuf->buf);

//printf("last_requested: %d\n", blist->last_requested->index);

	// Find the matching entry.
	for(blk=blist->last_requested; blk; blk=blk->next)
		if(index==blk->index) break;
	if(!blk)
	{
		logp("Could not find requested block %lu\n", index);
		return -1;
	}
	blk->requested=1;
	blist->last_requested=blk;
	//printf("Found %lu\n", index);
	return 0;
}

static int deal_with_read(struct iobuf *rbuf, struct slist *slist, struct blist  *blist, struct conf *conf, int *backup_end, int *requests_end, int *blk_requests_end)
{
	int ret=0;
	switch(rbuf->cmd)
	{
		/* Incoming file request. */
		case CMD_FILE:
			if(add_to_file_requests(slist, rbuf, conf)) goto error;
			return 0;

		/* Incoming data block request. */
		case CMD_DATA_REQ:
			if(add_to_data_requests(blist, rbuf)) goto error;
			goto end;

		/* Incoming control/message stuff. */
		case CMD_WRAP_UP:
		{
			int64_t wrap_up;
			struct blk *blk;
			from_base64(&wrap_up, rbuf->buf);
printf("got wrap_up: %d\n", wrap_up);
			for(blk=blist->head; blk; blk=blk->next)
			{
				if(blk->index==(uint64_t)wrap_up)
				{
					blist->last_requested=blk;
					blist->last_sent=blk;
					break;
				}
			}
			if(!blk)
			{
#ifdef HAVE_WIN32
				logp("Could not find wrap up index: %016I64X\n",
#else
				logp("Could not find wrap up index: %016lX\n",
#endif
					wrap_up);
				logp("Could not find wrap up index: %d\n",
					wrap_up);
//				goto error;
			}
			goto end;
		}
		case CMD_WARNING:
			logp("WARNING: %s\n", rbuf->cmd);
			cntr_add(conf->cntr, rbuf->cmd, 0);
			goto end;
		case CMD_GEN:
			if(!strcmp(rbuf->buf, "requests_end"))
			{
				*requests_end=1;
				goto end;
			}
			else if(!strcmp(rbuf->buf, "blk_requests_end"))
			{
				*blk_requests_end=1;
				goto end;
			}
			else if(!strcmp(rbuf->buf, "backup_end"))
			{
				*backup_end=1;
				goto end;
			}
			break;
	}

	iobuf_log_unexpected(rbuf, __func__);
error:
	ret=-1;
end:
	iobuf_free_content(rbuf);
	return ret;
}

static int add_to_blks_list(struct asfd *asfd, struct conf *conf,
	struct slist *slist, struct blist *blist, struct win *win)
{
	struct sbuf *sb=slist->last_requested;
	if(!sb) return 0;
	if(blks_generate(asfd, conf, sb, blist, win)) return -1;

	// If it closed the file, move to the next one.
	if(sb->burp2->bfd.mode==BF_CLOSED) slist->last_requested=sb->next;

	return 0;
}

static void free_stuff(struct slist *slist, struct blist *blist)
{
	struct blk *blk;
	blk=blist->head;
	while(blk && blk!=blist->last_sent)
	{
		if(blk==slist->head->burp2->bstart)
			slist->head->burp2->bstart=NULL;
		if(blk==slist->head->burp2->bend)
		{
			struct sbuf *sb;
			sb=slist->head;
			sb->burp2->bend=NULL;
			if(!(slist->head=slist->head->next))
				slist->tail=NULL;
			sbuf_free(&sb);
		}
		blk=blk->next;
		blk_free(&blist->head);
		blist->head=blk;
	}
}

static void get_wbuf_from_data(struct conf *conf,
	struct iobuf *wbuf, struct slist *slist,
	struct blist *blist, int blk_requests_end)
{
	struct blk *blk;

	for(blk=blist->last_sent; blk; blk=blk->next)
	{
		if(blk->requested)
		{
			wbuf->cmd=CMD_DATA;
			wbuf->buf=blk->data;
			wbuf->len=blk->length;
			blk->requested=0;
			blist->last_sent=blk;
			cntr_add(conf->cntr, CMD_DATA, 1);
			cntr_add_sentbytes(conf->cntr, blk->length);
			break;
		}
		else
		{
			cntr_add_same(conf->cntr, CMD_DATA);
			if(blk_requests_end)
			{
				// Force onwards when the server has said that
				// there are no more blocks to request.
				blist->last_sent=blk;
				continue;
			}
		}
		if(blk==blist->last_requested) break;
	}
	// Need to free stuff that is no longer needed.
	free_stuff(slist, blist);
}

static void iobuf_from_blk_data(struct iobuf *wbuf, struct blk *blk)
{
	static char buf[49];
// Check return of this - maybe should be done elsewhere.
	blk_md5_update(blk);

	// Fingerprint is 4 bytes.
	snprintf(blk->weak, sizeof(blk->weak),
#ifdef HAVE_WIN32
		"%016I64X",
#else
		"%016lX",
#endif
		blk->fingerprint);
	// MD5sum is 32 characters long.
	snprintf(blk->strong, sizeof(blk->strong),
		"%s", blk_get_md5sum_str(blk->md5sum));
	snprintf(buf, sizeof(buf), "%s%s", blk->weak, blk->strong);
	iobuf_from_str(wbuf, CMD_SIG, buf);
}

static void get_wbuf_from_blks(struct iobuf *wbuf,
	struct slist *slist, int requests_end, int *sigs_end)
{
	struct sbuf *sb=slist->blks_to_send;

	if(!sb)
	{
		if(requests_end && !*sigs_end)
		{
			iobuf_from_str(wbuf, CMD_GEN, (char *)"sigs_end");
			*sigs_end=1;
		}
		return;
	}
	if(!sb->burp2->bsighead) return;

	if(!(sb->flags & SBUF_SENT_STAT))
	{
		iobuf_copy(wbuf, &sb->attr);
		wbuf->cmd=CMD_ATTRIBS_SIGS; // hack
		sb->flags |= SBUF_SENT_STAT;
		return;
	}

	iobuf_from_blk_data(wbuf, sb->burp2->bsighead);

	// Move on.
	if(sb->burp2->bsighead==sb->burp2->bend)
	{
		slist->blks_to_send=sb->next;
		sb->burp2->bsighead=sb->burp2->bstart;
	}
	else
	{
		sb->burp2->bsighead=sb->burp2->bsighead->next;
	}
}

static void get_wbuf_from_scan(struct iobuf *wbuf, struct slist *flist)
{
	struct sbuf *sb=flist->head;
	if(!sb) return;
	if(!(sb->flags & SBUF_SENT_STAT))
	{
		iobuf_copy(wbuf, &sb->attr);
		sb->flags |= SBUF_SENT_STAT;
	}
	else if(!(sb->flags & SBUF_SENT_PATH))
	{
		iobuf_copy(wbuf, &sb->path);
		sb->flags |= SBUF_SENT_PATH;
	}
	else if(sb->link.buf && !(sb->flags & SBUF_SENT_LINK))
	{
		iobuf_copy(wbuf, &sb->link);
		sb->flags |= SBUF_SENT_LINK;
	}
	else
	{
		flist->head=flist->head->next;
		sbuf_free(&sb);
		if(flist->head)
		{
			// Go ahead and get the next one from the list.
			get_wbuf_from_scan(wbuf, flist);
		}
		else
		{
			flist->tail=NULL;
			iobuf_from_str(wbuf, CMD_GEN, (char *)"scan_end");
		}
	}
}

int backup_phase2_client_burp2(struct asfd *asfd, struct conf *conf, int resume)
{
	int ret=-1;
	int sigs_end=0;
	int backup_end=0;
	int requests_end=0;
	int blk_requests_end=0;
	struct win *win=NULL; // Rabin sliding window.
	struct slist *slist=NULL;
	struct blist *blist=NULL;
	struct iobuf *rbuf=NULL;
	struct iobuf *wbuf=NULL;

	logp("Phase 2 begin (send backup data)\n");

	if(!(slist=slist_alloc())
	  || !(blist=blist_alloc())
	  || !(wbuf=iobuf_alloc())
	  || blks_generate_init(conf)
	  || !(win=win_alloc(&conf->rconf)))
		goto end;
	rbuf=asfd->rbuf;

	if(!resume)
	{
		// Only do this bit if the server did not tell us to resume.
		if(asfd->write_str(asfd, CMD_GEN, "backupphase2")
		  || asfd->read_expect(asfd, CMD_GEN, "ok"))
			goto end;
	}
	else if(conf->send_client_cntr)
	{
		// On resume, the server might update the client with the
		// counters.
		if(cntr_recv(asfd, conf))
			goto end;
        }

	while(!backup_end)
	{
		if(!wbuf->len)
		{
			get_wbuf_from_data(conf, wbuf, slist, blist,
				blk_requests_end);
			if(!wbuf->len)
			{
				get_wbuf_from_blks(wbuf, slist,
					requests_end, &sigs_end);
			}
		}

		if(wbuf->len)
			asfd->append_all_to_write_buffer(asfd, wbuf);
		if(asfd->as->read_write(asfd->as))
		{
			logp("error in %s\n", __func__);
			goto end;
		}

		if(rbuf->buf && deal_with_read(rbuf, slist, blist,
			conf, &backup_end, &requests_end, &blk_requests_end))
				goto end;

		if(slist->head
		// Need to limit how many blocks are allocated at once.
		  && (!blist->head
		   || blist->tail->index - blist->head->index<BLKS_MAX_IN_MEM)
		)
		{
			if(add_to_blks_list(asfd, conf, slist, blist, win))
				goto end;
		}

		if(blk_requests_end)
		{
			// If got to the end of the file request list
			// and the last block of the last file, and
			// the write buffer is empty, we got to the end.
			if(slist->head==slist->tail)
			{
				if(!slist->tail
				  || blist->last_sent==slist->tail->burp2->bend)
				{
					if(!wbuf->len)
						break;
				}
			}

		}
	}

	if(asfd->write_str(asfd, CMD_GEN, "backup_end"))
		goto end;

	ret=0;
end:
blk_print_alloc_stats();
//sbuf_print_alloc_stats();
	win_free(win);
	slist_free(slist);
	blist_free(blist);
	// Write buffer did not allocate 'buf'.
	wbuf->buf=NULL;
	iobuf_free(wbuf);

	cntr_print_end(conf->cntr);
	cntr_print(conf->cntr, ACTION_BACKUP);
	if(ret) logp("Error in backup\n");
	logp("End backup\n");

	return ret;
}
