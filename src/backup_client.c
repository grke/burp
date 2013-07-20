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
/*
static int send_blocks(struct sbuf *sb, struct config *conf, struct cntr *cntr)
{
	int ret;
	BFILE bfd;
	FILE *fp=NULL;
#ifdef HAVE_WIN32
        if(win32_lstat(sb->path, &sb->statp, &sb->winattr))
#else
        if(lstat(sb->path, &sb->statp))
#endif
	{
		// This file is no longer available.
		logw(cntr, "%s has vanished\n", sb->path);
		return 0;
	}
	encode_stat(sb, conf->compression);

	if(open_file_for_send(
#ifdef HAVE_WIN32
		&bfd, NULL,
#else
		NULL, &fp,
#endif
		sb->path, sb->winattr, cntr))
	{
		logw(cntr, "Could not open %s\n", sb->path);
		return 0;
	}

	if(async_write_str(CMD_ATTRIBS_BLKS, sb->attribs)
	  || async_write_str(sb->cmd, sb->path))
	{
		close_file_for_send(&bfd, &fp);
		return -1;
	}

	ret=blks_generate(&conf->rconf,
#ifdef HAVE_WIN32
		&bfd, NULL
#else
		NULL, fp
#endif
		);

	close_file_for_send(&bfd, &fp);

	return ret;
}
*/

/*
static int deal_with_buf(struct sbuf *sb, char cmd, char *buf, size_t len, int *backup_end, struct config *conf, struct cntr *cntr)
{
	if(cmd==CMD_ATTRIBS)
	{
		//if(sbuf_fill_ng(sb, buf, len))
		//	return -1;
		if(send_blocks(sb, conf, cntr))
		{
			printf("send_blocks returned error\n");
			return -1;
		}
		printf("\nserver wants: %s", sb->path);
	//	free_sbuf(sb);
		return 0;
	}
	else if(cmd==CMD_WARNING)
	{
		logp("WARNING: %s\n", buf);
		do_filecounter(cntr, cmd, 0);
		if(buf) { free(buf); buf=NULL; }
		return 0;
	}
	else if(cmd==CMD_GEN)
	{
		if(backup_end && !strcmp(buf, "backup_end"))
		{
			*backup_end=1;
			return 0;
		}
	}

	logp("unexpected cmd in %s, got '%c:%s'\n", __FUNCTION__, cmd, buf);
	if(buf) { free(buf); buf=NULL; }
	return -1;
}
*/

static int add_to_scan_list(struct sbuf **fhead, struct sbuf **ftail, int *scanning, struct config *conf, bool *top_level, struct cntr *p1cntr)
{
	int ff_ret;
	struct sbuf *sb;
	if(!(sb=sbuf_init())) return -1;
	if(!(ff_ret=find_file_next(sb, conf, top_level)))
	{
		// Got something.
		if(ftype_to_cmd(sb, conf, p1cntr, *top_level))
		{
			// It is not something we really want to send.
			sbuf_free(sb);
			return 0;
		}

		if(*ftail)
		{
			// Add to the end of the list.
			(*ftail)->next=sb;
			*ftail=sb;
		}
		else
		{
			// Start the list.
			*fhead=sb;
			*ftail=sb;
		}
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

static void get_wbuf_from_blks(char *wcmd, char **wbuf, size_t *wlen, struct sbuf **shead, struct sbuf **stail)
{
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
		if(!*fhead) *ftail=NULL;
	}
}

static int backup_client(struct config *conf, int estimate, struct cntr *p1cntr, struct cntr *cntr)
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

	logp("Backup begin\n");

	if(find_files_init()) goto end;

	while(1)
	{
		if(!wlen)
		{
			get_wbuf_from_blks(&wcmd, &wbuf, &wlen,
				&shead, &stail);
			if(!wlen)
			{
				get_wbuf_from_scan(&wcmd, &wbuf, &wlen,
					&fhead, &ftail);
			}
		}

		if(wlen)
		{
			printf("%d %c:%s\n", (int)wlen, wcmd, wbuf);
			wlen=0;
		}

		if(scanning)
		{
			if(add_to_scan_list(&fhead, &ftail,
				 &scanning, conf, &top_level, p1cntr))
			{
				ret=-1;
				break;
			}
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
/*
{
	struct sbuf *xb;
	for(xb=fhead; xb; xb=xb->next)
		send_attribs_and_symbol(xb, p1cntr);
	
}
*/
	sbuf_free_list(fhead); fhead=NULL;

	print_endcounter(p1cntr);
	//print_filecounters(p1cntr, cntr, ACTION_BACKUP);
	if(ret) logp("Error in backup\n");
	logp("Backup end\n");

	return ret;
}

// Return 0 for OK, -1 for error, 1 for timer conditions not met.
int do_backup_client(struct config *conf, enum action act, struct cntr *p1cntr, struct cntr *cntr)
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
	if(!ret) ret=backup_client(conf, act==ACTION_ESTIMATE, p1cntr, cntr);

	if(act==ACTION_ESTIMATE)
		print_filecounters(p1cntr, cntr, ACTION_ESTIMATE);

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
