#include "burp.h"
#include "prog.h"
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

static int deal_with_read(char rcmd, char **rbuf, size_t rlen, struct sbuf **shead, struct sbuf **stail, struct config *conf, int *backup_end, struct sbuf **genhead, struct sbuf **sighead)
{
	int ret=0;
	switch(rcmd)
	{
		case CMD_FILE:
		{
			struct sbuf *sb;
			if(!(sb=sbuf_init())) goto error;
			sb->path=*rbuf;
			sb->plen=rlen;
			*rbuf=NULL;
			sbuf_add_to_list(sb, shead, stail, genhead, sighead);
printf("got request for: %s\n", sb->path);
			return 0;
		}
		case CMD_WARNING:
			logp("WARNING: %s\n", rbuf);
			do_filecounter(conf->cntr, rcmd, 0);
			goto end;
		case CMD_GEN:
			if(!strcmp(*rbuf, "backup_end"))
			{
				*backup_end=1;
				goto end;
			}
			break;
	}

	logp("unexpected cmd in %s, got '%c:%s'\n", __FUNCTION__, rcmd, *rbuf);
error:
	ret=-1;
end:
	if(*rbuf) { free(*rbuf); *rbuf=NULL; }
	return ret;
}

static int add_to_scan_list(struct sbuf **fhead, struct sbuf **ftail, int *scanning, struct config *conf, bool *top_level)
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
		sbuf_add_to_list(sb, fhead, ftail, NULL, NULL);
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

static int add_to_blks_list(struct config *conf, struct sbuf *shead, struct sbuf *stail, struct win *win, struct sbuf **genhead, int *blkgrps_queue)
{
	struct blkgrp *bnew=NULL;
	if(!*genhead) return 0;
printf("get for: %s\n", (*genhead)->path);
	if(!(*genhead)->opened)
	{
		if(sbuf_open_file(*genhead, conf)) return -1;
	}
	if(blks_generate(&bnew, &conf->rconf, *genhead, win)) return -1;
	if(!bnew || !bnew->b)
	{
		// Inefficiency - a whole blkgrp was allocated and then
		// not used. FIX THIS.
		blkgrp_free(bnew);
		// No more to read from the file. Close it and move to the
		// next file in the list.
		sbuf_close_file(*genhead);
		*genhead=(*genhead)->next;
	}
	else
	{
		// Got another group of blks.
		if((*genhead)->bhead)
		{
			// Add to the end of the list.
			// Each entry keeps a count of its position in the
			// list for this file.
			bnew->path_index=(*genhead)->btail->path_index+1;
			(*genhead)->btail->next=bnew;
			(*genhead)->btail=bnew;
		}
		else
		{
			// Start new list.
			(*genhead)->bhead=bnew;
			(*genhead)->btail=bnew;
			(*genhead)->bsighead=bnew;
		}
		// So as to not use up all the memory, keep track of how many
		// groups of blocks have been loaded.
		(*blkgrps_queue)++;
	}
	return 0;
}

static void get_wbuf_from_blks(char *wcmd, char **wbuf, size_t *wlen, struct sbuf **shead, struct sbuf **stail, struct sbuf **sighead, int *blkgrps_queue)
{
	static int i=0;
	static char buf[48];
	struct blk *blk;
	struct blkgrp *blkgrp;
	struct sbuf *sb=*sighead;

	if(!sb
	  || !(blkgrp=sb->bsighead))
		return;

	if(!sb->sent_stat)
	{
		*wcmd=CMD_ATTRIBS_SIGS;
		*wbuf=sb->attribs;
		*wlen=sb->alen;
		sb->sent_stat=1;
		return;
	}
	else if(!sb->sent_path)
	{
		*wcmd=CMD_PATH_SIGS;
		*wbuf=sb->path;
		*wlen=sb->plen;
		sb->sent_path=1;
		return;
	}

	blk=blkgrp->blks[i];
// Check return of this - maybe should be done elsewhere.
	blk_md5_update(blk);
	snprintf(buf, sizeof(buf),
		// Fingerprint is 4 bytes.
		"%016lX"
		// MD5sum is 32 characters long.
		"%s"
		,
		blk->fingerprint,
		blk_get_md5sum_str(blk->md5sum)
		);
	printf("%s (%d)\n", sb->path, blkgrp->b);
	printf("%s\n", buf);
	*wcmd=CMD_SIG;
	*wlen=strlen(buf);
	*wbuf=buf;

	// Move on.
	if(++i<blkgrp->b) return;
	(*blkgrps_queue)--;
	i=0;
	sb->bsighead=blkgrp->next;

// Free stuff for now. FIX THIS: It should not actually be freed until the
// actual data blocks have been dealt with.
	blkgrp_free(blkgrp);
	if(sb->bsighead) return;
	*sighead=sb->next;
}

static void get_wbuf_from_scan(char *wcmd, char **wbuf, size_t *wlen, struct sbuf **fhead, struct sbuf **ftail)
{
	struct sbuf *sb=*fhead;
	if(!sb) return;
	if(!sb->sent_stat)
	{
		*wcmd=CMD_ATTRIBS;
		*wbuf=sb->attribs;
		*wlen=sb->alen;
		sb->sent_stat=1;
	}
	else if(!sb->sent_path)
	{
		*wcmd=sb->cmd;
		*wbuf=sb->path;
		*wlen=sb->plen;
		sb->sent_path=1;
	}
	else if(sb->linkto && !sb->sent_link)
	{
		*wcmd=sb->cmd;
		*wbuf=sb->linkto;
		*wlen=sb->alen;
		sb->sent_link=1;
	}
	else
	{
		*fhead=(*fhead)->next;
		sbuf_free(sb);
		if(*fhead)
		{
			// Go ahead and get the next one from the list.
			get_wbuf_from_scan(wcmd, wbuf, wlen, fhead, ftail);
		}
		else *ftail=NULL;
	}
}

static int backup_client(struct config *conf, int estimate)
{
	int ret=0;
	bool top_level=true;
	int scanning=1;
	char wcmd=CMD_ERROR;
	char *wbuf=NULL;
	size_t wlen=0;
	struct sbuf *shead=NULL;
	struct sbuf *stail=NULL;
	struct sbuf *fhead=NULL;
	struct sbuf *ftail=NULL;
	char rcmd=CMD_ERROR;
	char *rbuf=NULL;
	size_t rlen=0;
	int backup_end=0;
	struct win *win=NULL; // Rabin sliding window.
	int blkgrps_queue_max=10;
	int blkgrps_queue=0;
	struct sbuf *genhead=NULL;
	struct sbuf *sighead=NULL;

	logp("Backup begin\n");

	if(find_files_init()
	  || !(win=win_alloc(&conf->rconf)))
		goto end;

	while(!backup_end)
	{
		if(!wlen)
		{
			get_wbuf_from_blks(&wcmd, &wbuf, &wlen,
				&shead, &stail, &sighead, &blkgrps_queue);
			if(!wlen)
			{
				get_wbuf_from_scan(&wcmd, &wbuf, &wlen,
					&fhead, &ftail);
			}
		}

		if(async_rw(&rcmd, &rbuf, &rlen, wcmd, wbuf, &wlen))
		{
			logp("error in async_rw\n");
			goto end;
		}

		if(rbuf && deal_with_read(rcmd, &rbuf, rlen,
			&shead, &stail, conf, &backup_end, &genhead, &sighead))
				goto end;

		if(scanning)
		{
			if(add_to_scan_list(&fhead, &ftail,
				&scanning, conf, &top_level))
			{
				ret=-1;
				break;
			}
		}

		if(blkgrps_queue<blkgrps_queue_max && shead)
		{
			printf("get more blocks: %d<%d\n",
				blkgrps_queue, blkgrps_queue_max);
			if(add_to_blks_list(conf, shead, stail,
				win, &genhead, &blkgrps_queue))
			{
				ret=-1;
				break;
			}
			// Hack - the above can return without having got
			// anything when it runs out of file to read.
			// So have another go.
			if(!blkgrps_queue && genhead
			  && add_to_blks_list(conf, shead, stail,
				win, &genhead, &blkgrps_queue))
			{
				ret=-1;
				break;
			}
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
	sbuf_free_list(fhead); fhead=NULL;

	print_endcounter(conf->p1cntr);
	//print_filecounters(conf->p1cntr, conf->cntr, ACTION_BACKUP);
	if(ret) logp("Error in backup\n");
	logp("Backup end\n");

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
