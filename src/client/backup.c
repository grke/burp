#include "include.h"
#include "../rabin/include.h"
#include "../legacy/client/backup_phase1.h"
#include "../legacy/client/backup_phase2.h"

/* Ignore extrameta for now.
#ifndef HAVE_WIN32
static int maybe_send_extrameta(struct sbuf *sb, char cmd, struct cntr *p1cntr)
{
	if(has_extrameta(sb->path, cmd))
	{
		if(async_write_str(CMD_ATTRIBS, sb->attribs)
		  || async_write_str(CMD_METADATA, sb->path))
			return -1;
		do_filecounter(p1cntr, CMD_METADATA, 1);
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

static int add_to_file_requests(struct slist *slist, struct iobuf *rbuf)
{
	static uint64_t file_no=1;
	struct sbuf *sb;

	if(!(sb=sbuf_alloc())) return -1;

	iobuf_copy(&sb->path, rbuf);
	rbuf->buf=NULL;
	// Give it a number to simplify tracking.
	sb->index=file_no++;
	sbuf_add_to_list(sb, slist);
//printf("got request for: %s\n", sb->path);

	return 0;
}

static int add_to_data_requests(struct blist *blist, struct iobuf *rbuf)
{
	uint64_t index;
	struct blk *blk;
	index=decode_req(rbuf->buf);

	// Find the matching entry.
//	printf("Request for data: %lu\n", index);

	//printf("last_requested: %lu\n", blist->last_requested->index);
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

static int deal_with_read(struct iobuf *rbuf, struct slist *slist, struct blist  *blist, struct config *conf, int *backup_end, int *requests_end, int *blk_requests_end)
{
	int ret=0;
	switch(rbuf->cmd)
	{
		/* Incoming file request. */
		case CMD_FILE:
			if(add_to_file_requests(slist, rbuf)) goto error;
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
//			printf("GOT WRAP UP: %016lX\n", wrap_up);
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
				goto error;
			}
			goto end;
		}
		case CMD_WARNING:
			logp("WARNING: %s\n", rbuf->cmd);
			do_filecounter(conf->cntr, rbuf->cmd, 0);
			goto end;
		case CMD_GEN:
			if(!strcmp(rbuf->buf, "requests_end"))
			{
printf("FILE REQUESTS END\n");
				*requests_end=1;
				goto end;
			}
			else if(!strcmp(rbuf->buf, "blk_requests_end"))
			{
printf("BLK REQUESTS END\n");
				*blk_requests_end=1;
/*
				if(!blist->last_sent)
					blist->last_sent=blist->head;
*/
				goto end;
			}
			else if(!strcmp(rbuf->buf, "backup_end"))
			{
printf("BACKUP END\n");
				*backup_end=1;
				goto end;
			}
			break;
	}

	iobuf_log_unexpected(rbuf, __FUNCTION__);
error:
	ret=-1;
end:
	iobuf_free_content(rbuf);
	return ret;
}

static int add_to_blks_list(struct config *conf, struct slist *slist, struct blist *blist, struct win *win)
{
	struct sbuf *sb=slist->last_requested;
	if(!sb) return 0;
//printf("get for: %s\n", sb->path);
	if(blks_generate(conf, sb, blist, win)) return -1;

	// If it closed the file, move to the next one.
	if(sb->bfd.mode==BF_CLOSED) slist->last_requested=sb->next;

	return 0;
}

static void free_stuff(struct slist *slist, struct blist *blist)
{
	struct blk *blk;
	blk=blist->head;
	while(blk && blk!=blist->last_sent)
	{
		if(blk==slist->head->bstart)
			slist->head->bstart=NULL;
		if(blk==slist->head->bend)
		{
			struct sbuf *sb;
			sb=slist->head;
			sb->bend=NULL;
			if(!(slist->head=slist->head->next))
				slist->tail=NULL;
//printf("FREE SB %lu %s\n", sb->index, sb->path);
			sbuf_free(sb);
		}
		blk=blk->next;
//printf("FREE BLK %lu\n", blist->head->index);
		blk_free(blist->head);
		blist->head=blk;
	}
}

static void get_wbuf_from_data(struct iobuf *wbuf, struct slist *slist, struct blist *blist, int blk_requests_end)
{
	struct blk *blk;

//printf("get wbuf: %s\n", blist->last_sent?"yes":"no");
	for(blk=blist->last_sent; blk; blk=blk->next)
	{
		if(blk->requested)
		{
//			printf("ee %lu %lu, %d\n", blk->index, blist->last_requested->index, blk->requested);
//			printf("WANT TO SEND ");
//			printf("%lu %s%s\n", blk->index, blk->weak, blk->strong);
			wbuf->cmd=CMD_DATA;
			wbuf->buf=blk->data;
			wbuf->len=blk->length;
			blk->requested=0;
			blist->last_sent=blk;
			break;
		}
		else
		{
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
//	printf("%s\n", buf);
//	printf("%d\n", blk->index);
	iobuf_from_str(wbuf, CMD_SIG, buf);
}

static void get_wbuf_from_blks(struct iobuf *wbuf, struct slist *slist, int requests_end, int *sigs_end)
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
//printf("x: %s\n", sb->path);
	if(!sb->bsighead) return;

	if(!(sb->flags & SBUF_SENT_STAT))
	{
//printf("want to send stat: %s\n", sb->path);
		iobuf_copy(wbuf, &sb->attr);
		wbuf->cmd=CMD_ATTRIBS_SIGS; // hack
		sb->flags |= SBUF_SENT_STAT;
		return;
	}

	iobuf_from_blk_data(wbuf, sb->bsighead);

	// Move on.
	if(sb->bsighead==sb->bend)
	{
		slist->blks_to_send=sb->next;
		sb->bsighead=sb->bstart;
	}
	else
	{
		sb->bsighead=sb->bsighead->next;
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
		sbuf_free(sb);
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

static int backup_phase2_client(struct config *conf, int resume)
{
	int ret=0;
	int sigs_end=0;
	int backup_end=0;
	int requests_end=0;
	int blk_requests_end=0;
	struct win *win=NULL; // Rabin sliding window.
	struct slist *slist=NULL;
	struct blist *blist=NULL;
	struct iobuf *rbuf=NULL;
	struct iobuf *wbuf=NULL;

	logp("Begin backup\n");

	if(!(slist=slist_alloc())
	  || !(blist=blist_alloc())
	  || !(wbuf=iobuf_alloc())
	  || !(rbuf=iobuf_alloc()))
	{
		ret=-1;
		goto end;
	}

	if(blks_generate_init(conf)
	  || !(win=win_alloc(&conf->rconf)))
		goto end;

	while(!backup_end)
	{
		if(!wbuf->len)
		{
			get_wbuf_from_data(wbuf, slist, blist,
				blk_requests_end);
			if(!wbuf->len)
			{
				get_wbuf_from_blks(wbuf, slist,
					requests_end, &sigs_end);
			}
		}

		if(async_rw(rbuf, wbuf))
		{
			logp("error in async_rw\n");
			ret=-1;
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
			if(add_to_blks_list(conf, slist, blist, win))
			{
				ret=-1;
				break;
			}
		}

		if(blk_requests_end)
		{
			// If got to the end of the file request list
			// and the last block of the last file, and
			// the write buffer is empty, we got to the end.
			if(slist->head==slist->tail)
			{
				if(!slist->tail
				  || blist->last_sent==slist->tail->bend)
				{
					if(!wbuf->len)
						break;
				}
			}

		}
	}

	if(async_write_str(CMD_GEN, "backup_end"))
	{
		ret=-1;
		goto end;
	}

end:
blk_print_alloc_stats();
sbuf_print_alloc_stats();
	win_free(win);
	slist_free(slist);
	blist_free(blist);
	iobuf_free(rbuf);
	// Write buffer did not allocate 'buf'.
	wbuf->buf=NULL;
	iobuf_free(wbuf);

	print_endcounter(conf->p1cntr);
	//print_filecounters(conf->p1cntr, conf->cntr, ACTION_BACKUP);
	if(ret) logp("Error in backup\n");
	logp("End backup\n");

	return ret;
}

// Return 0 for OK, -1 for error, 1 for timer conditions not met.
int do_backup_client(struct config *conf, enum action action,
	long name_max, int resume)
{
	int ret=0;

	if(action==ACTION_ESTIMATE)
		logp("do estimate client\n");
	else
		logp("do backup client\n");

#if defined(HAVE_WIN32)
	win32_enable_backup_privileges();
#if defined(WIN32_VSS)
	if((ret=win32_start_vss(conf))) return ret;
#endif
	if(action==ACTION_BACKUP_TIMED)
	{
		// Run timed backups with lower priority.
		// I found that this has to be done after the snapshot, or the
		// snapshot never finishes. At least, I waited 30 minutes with
		// nothing happening.
#if defined(B_VSS_XP) || defined(B_VSS_W2K3)
		if(SetThreadPriority(GetCurrentThread(),
					THREAD_PRIORITY_LOWEST))
			logp("Set thread_priority_lowest\n");
		else
			logp("Failed to set thread_priority_lowest\n");
#else
		if(SetThreadPriority(GetCurrentThread(),
					THREAD_MODE_BACKGROUND_BEGIN))
			logp("Set thread_mode_background_begin\n");
		else
			logp("Failed to set thread_mode_background_begin\n");
#endif
	}
#endif

	// Scan the file system and send the results to the server.
	// Skip phase1 if the server wanted to resume.
	if(!ret && !resume)
	{
printf("client legacy: %d\n", conf->legacy);
		if(conf->legacy)
			ret=backup_phase1_client_legacy(conf, name_max,
				action==ACTION_ESTIMATE);
		else
			ret=backup_phase1_client(conf, name_max,
				action==ACTION_ESTIMATE);
	}

	if(action!=ACTION_ESTIMATE && !ret)
	{
		// Now, the server will be telling us what data we need to
		// send.
		if(conf->legacy)
			ret=backup_phase2_client_legacy(conf, resume);
		else
			ret=backup_phase2_client(conf, resume);
	}

	if(action==ACTION_ESTIMATE) print_filecounters(conf, ACTION_ESTIMATE);

#if defined(HAVE_WIN32)
	if(action==ACTION_BACKUP_TIMED)
	{
		if(SetThreadPriority(GetCurrentThread(),
					THREAD_MODE_BACKGROUND_END))
			logp("Set thread_mode_background_end\n");
		else
			logp("Failed to set thread_mode_background_end\n");
	}
#if defined(WIN32_VSS)
	win32_stop_vss();
#endif
#endif

	return ret;
}
