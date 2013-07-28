#include "burp.h"
#include "prog.h"
#include "base64.h"
#include "msg.h"
#include "lock.h"
#include "handy.h"
#include "asyncio.h"
#include "counter.h"
#include "extrameta.h"
#include "backup_client.h"
#include "client_vss.h"
#include "find.h"
#include "attribs.h"
#include "sbuf.h"
#include "blk.h"
#include "rabin.h"
#include "rabin_win.h"

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

//static int data_requests=0;

static int deal_with_read(struct iobuf *rbuf, struct slist *slist, struct config *conf, int *backup_end)
{
	int ret=0;
	static uint64_t file_no=1;
	switch(rbuf->cmd)
	{
		case CMD_FILE:
		{
			struct sbuf *sb;
			if(!(sb=sbuf_init())) goto error;
			sbuf_from_iobuf_path(sb, rbuf);
			rbuf->buf=NULL;
			// Give it a number to simplify tracking.
			sb->no=file_no++;
			sbuf_add_to_list(sb, slist);
printf("got request for: %s\n", sb->path);

			return 0;
		}
		case CMD_DATA_REQ:
		{
			uint64_t index;
//			struct sbuf *sb;
			index=decode_req(rbuf->buf);

			// Find the matching entry.
			printf("Request for data: %lu\n", index);
/*
			for(sb=slist->head; sb; sb=sb->next)
				if(sno==sb->no) break;
			if(!sb)
			{
				logp("Could not find %d in client list\n", sno);
				goto error;
			}
			printf("It was: %s\n", sb->path);
			for(blkgrp=sb->bhead; blkgrp; blkgrp=blkgrp->next)
				if(blkgrp_ind==blkgrp->index) break;
			if(!blkgrp)
			{
				logp("Could not find blkgrp %d for client file %s\n", blkgrp_ind, sb->path);
				goto error;
			}
			blkgrp->blks[req_blk]->requested=1;
			data_requests++;
*/
			goto end;
		}
		case CMD_WARNING:
			logp("WARNING: %s\n", rbuf->cmd);
			do_filecounter(conf->cntr, rbuf->cmd, 0);
			goto end;
		case CMD_GEN:
			if(!strcmp(rbuf->buf, "backup_end"))
			{
				*backup_end=1;
				goto end;
			}
			break;
	}

	logp("unexpected cmd in %s, got '%c:%s'\n",
		__FUNCTION__, rbuf->cmd, rbuf->buf);
error:
	ret=-1;
end:
	if(rbuf->buf) { free(rbuf->buf); rbuf->buf=NULL; }
	return ret;
}

static int add_to_scan_list(struct slist *flist, int *scanning, struct config *conf, bool *top_level)
{
	int ff_ret;
	struct sbuf *sb;
	if(!(sb=sbuf_init())) return -1;
	if(!(ff_ret=find_file_next(sb, conf, top_level)))
	{
		// Got something.
		if(ftype_to_cmd(sb, conf, *top_level))
		{
			// It is not something we really want to send.
			sbuf_free(sb);
			return 0;
		}
		sbuf_add_to_list(sb, flist);
	}
	else if(ff_ret<0)
	{
		// Error.
		sbuf_free(sb);
		return ff_ret;
	}
	else
	{
		// No more file system to scan.
		*scanning=0;
	}
	return 0;
}

static int add_to_blks_list(struct config *conf, struct slist *slist, struct win *win, uint64_t *bindex)
{
	int bg_ret;
	struct sbuf *sb=slist->mark1;
	if(!sb) return 0;
printf("get for: %s\n", sb->path);
	if(!sb->opened)
	{
		if(sbuf_open_file(sb, conf)) return -1;
	}
	if((bg_ret=blks_generate(&conf->rconf, sb, win, bindex))>0)
	{
		sbuf_close_file(sb);
		slist->mark1=sb->next;
	}
	else if(bg_ret<0) return -1; // error

	return 0;
}

static void get_wbuf_from_data(struct iobuf *wbuf, struct slist *slist)
{
/*
	struct sbuf *sb;
	if(!data_requests) return;

	// Have at least one pending request.
	// Try to find it, freeing things along the way.
	while((sb=slist->head))
	{
		struct blkgrp *bg;
		while((bg=sb->bhead))
		{
			for(; bg->req_blk<bg->b; bg->req_blk++)
			{
				if(bg->blks[bg->req_blk]->requested)
				{
					struct blk *blk=bg->blks[bg->req_blk];
					printf("WANT TO SEND ");
					printf("%s%s\n", blk->weak, blk->strong);
					wbuf->cmd=CMD_DATA;
					wbuf->buf=blk->data;
					wbuf->len=blk->length;
					data_requests--;
					bg->req_blk++;
					return;
				}
				else
				{
					blk_free(bg->blks[bg->req_blk]);
					bg->blks[bg->req_blk]=NULL;
				}
			}
			if(sb->btail==sb->bhead) sb->btail=sb->bhead->next;
			if(sb->bsighead==sb->bhead) sb->bsighead=sb->bhead->next;
			sb->bhead=sb->bhead->next;
		}

		// Move along.
		slist->head=sb->next;
		// It is possible for the markers to drop behind.
		if(slist->tail==sb) slist->tail=sb->next;
		if(slist->mark1==sb) slist->mark1=sb->next;
		if(slist->mark2==sb) slist->mark2=sb->next;
		if(slist->mark3==sb) slist->mark3=sb->next;
		sbuf_free(sb);
	}
*/
}

static void get_wbuf_from_blks(struct iobuf *wbuf, struct slist *slist)
{
	static char buf[49];
	struct blk *blk;
	struct sbuf *sb=slist->mark2;

	if(!sb) return;
	if(!(blk=sb->bsighead)) return;

	if(!sb->sent_stat)
	{
		iobuf_from_sbuf_attr(wbuf, sb);
		wbuf->cmd=CMD_ATTRIBS_SIGS; // hack
		sb->sent_stat=1;
		return;
	}

// Check return of this - maybe should be done elsewhere.
	blk_md5_update(blk);

	// Fingerprint is 4 bytes.
	snprintf(blk->weak, sizeof(blk->weak),
		"%016lX", blk->fingerprint);
	// MD5sum is 32 characters long.
	snprintf(blk->strong, sizeof(blk->strong),
		"%s", blk_get_md5sum_str(blk->md5sum));
	snprintf(buf, sizeof(buf), "%s%s", blk->weak, blk->strong);
	printf("%s\n", sb->path);
	printf("%s\n", buf);
	iobuf_from_str(wbuf, CMD_SIG, buf);

	// Move on.
	if(!(sb->bsighead=blk->next))
		slist->mark2=sb->next;
}

static void get_wbuf_from_scan(struct iobuf *wbuf, struct slist *flist)
{
	struct sbuf *sb=flist->head;
	if(!sb) return;
	if(!sb->sent_stat)
	{
		iobuf_from_sbuf_attr(wbuf, sb);
		sb->sent_stat=1;
	}
	else if(!sb->sent_path)
	{
		iobuf_from_sbuf_path(wbuf, sb);
		sb->sent_path=1;
	}
	else if(sb->linkto && !sb->sent_link)
	{
		iobuf_from_sbuf_link(wbuf, sb);
		sb->sent_link=1;
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
		else flist->tail=NULL;
	}
}

static int backup_client(struct config *conf, int estimate)
{
	int ret=0;
	bool top_level=true;
	int scanning=1;
	int backup_end=0;
	struct win *win=NULL; // Rabin sliding window.
	struct slist *flist=NULL;
	struct slist *slist=NULL;
	struct iobuf *rbuf=NULL;
	struct iobuf *wbuf=NULL;
	uint64_t bindex=1;

	logp("Begin backup\n");

	if(!(flist=slist_init())
	  || !(slist=slist_init())
	  || !(wbuf=iobuf_init())
	  || !(rbuf=iobuf_init()))
	{
		ret=-1;
		goto end;
	}

	if(find_files_init()
	  || !(win=win_alloc(&conf->rconf)))
		goto end;

	while(!backup_end)
	{
		if(!wbuf->len)
		{
			get_wbuf_from_data(wbuf, slist);
			if(!wbuf->len)
			{
				get_wbuf_from_blks(wbuf, slist);
				if(!wbuf->len)
				{
					get_wbuf_from_scan(wbuf, flist);
				}
			}
		}

		if(async_rw_ng(rbuf, wbuf))
		{
			logp("error in async_rw\n");
			goto end;
		}

		if(rbuf->buf && deal_with_read(rbuf, slist, conf, &backup_end))
			goto end;

		if(scanning)
		{
			if(add_to_scan_list(flist, &scanning, conf, &top_level))
			{
				ret=-1;
				break;
			}
		}

		if(slist->head)
		{
			if(add_to_blks_list(conf, slist, win, &bindex))
			{
				ret=-1;
				break;
			}
			// Hack - the above can return without having got
			// anything when it runs out of file to read.
			// So have another go.
			// Maybe.
		}
		else
		{
			//printf("enough blocks: %d>=%d\n",
			//	blkgrps_queue, blkgrps_queue_max);
		}

		// FIX THIS
		//else break;
	}

	if(async_write_str(CMD_GEN, "scan_end"))
	{
		ret=-1;
		goto end;
	}

end:
	find_files_free();
	win_free(win);
	slist_free(flist);
	slist_free(slist);
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
int do_backup_client(struct config *conf, enum action act)
{
	int ret=0;

	if(act==ACTION_ESTIMATE)
		logp("do estimate client\n");
	else
		logp("do backup client\n");

#if defined(HAVE_WIN32)
	win32_enable_backup_privileges();
#if defined(WIN32_VSS)
	if((ret=win32_start_vss(conf))) return ret;
#endif
	if(act==ACTION_BACKUP_TIMED)
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
	if(!ret) ret=backup_client(conf, act==ACTION_ESTIMATE);

	if(act==ACTION_ESTIMATE)
		print_filecounters(conf->p1cntr, conf->cntr, ACTION_ESTIMATE);

#if defined(HAVE_WIN32)
	if(act==ACTION_BACKUP_TIMED)
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
