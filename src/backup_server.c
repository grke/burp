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
#include "auth_server.h"
#include "backup_server.h"
#include "current_backups_server.h"
#include "attribs.h"

static int write_incexc(const char *realworking, const char *incexc)
{
	int ret=-1;
	FILE *fp=NULL;
	char *path=NULL;
	if(!(path=prepend_s(realworking, "incexc", strlen("incexc"))))
		goto end;
	if(!(fp=open_file(path, "wb")))
		goto end;
	fprintf(fp, "%s", incexc);
	ret=0;
end:
	if(close_fp(&fp))
	{
		logp("error writing to %s in write_incexc\n", path);
		ret=-1;
	}
	if(path) free(path);
	return ret;
}

static int open_log(const char *realworking, const char *client, const char *cversion, struct config *conf)
{
	char *logpath=NULL;

	if(!(logpath=prepend_s(realworking, "log", strlen("log"))))
	{
		log_and_send_oom(__FUNCTION__);
		return -1;
	}
	if(set_logfp(logpath, conf))
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg),
				"could not open log file: %s", logpath);
		log_and_send(msg);
		free(logpath);
		return -1;
	}
	free(logpath);

	logp("Client version: %s\n", cversion?:"");
	// Make sure a warning appears in the backup log.
	// The client will already have been sent a message with logw.
	// This time, prevent it sending a logw to the client by specifying
	// NULL for cntr.
	if(conf->version_warn)
		version_warn(NULL, client, cversion);

	return 0;
}

static int split_sig(const char *buf, unsigned int s, char *weak, char *strong)
{
	if(s!=48)
	{
		fprintf(stderr, "Signature wrong length: %u\n", s);
		return -1;
	}
	memcpy(weak, buf, 16);
	memcpy(strong, buf+16, 32);
	return 0;
}

static int deal_with_read(struct iobuf *rbuf, struct slist *slist, struct config *conf, int *backup_end)
{
	int ret=0;
	static struct sbuf *snew=NULL;
	static struct sbuf *inew=NULL;

	if(!inew && !(inew=sbuf_init())) goto error;

	switch(rbuf->cmd)
	{
		case CMD_ATTRIBS_SIGS:
			// New set of stuff incoming. Clean up.
			if(inew->attribs) free(inew->attribs);
			sbuf_from_iobuf_attr(inew, rbuf);
			inew->no=decode_file_no(inew);
			rbuf->buf=NULL;

			// Need to go through slist to find the matching
			// entry.
			{
				struct sbuf *sb;
				for(sb=slist->mark2; sb; sb=sb->next)
				{
					if(!sb->no) continue;
					if(inew->no==sb->no) break;
				}
				if(!sb)
				{
					logp("Could not find %d in request list %d\n", inew->no, sb->no);
					goto error;
				}
				// Replace the attribs with the more recent
				// values.
				free(sb->attribs);
				sb->attribs=inew->attribs;
				sb->alen=inew->alen;
				inew->attribs=NULL;
				slist->mark2=sb;
				// Incoming sigs now need to get added to mark2
			}
			return 0;
		case CMD_SIG:
		{
			// Goes on slist->mark2
			struct blk *blk;
			struct blkgrp *blkgrp;
			struct sbuf *sb=slist->mark2;
			if(!sb->btail)
			{
				// Need the first blkgrp.
				struct blkgrp *bnew;
				if(!(bnew=blkgrp_alloc(&conf->rconf)))
					goto error;
				sb->bhead=bnew;
				sb->btail=bnew;
				sb->bsighead=bnew;
			}
			else if(sb->btail->b==SIG_MAX)
			{
				// Need to add a new blkgrp.
				struct blkgrp *bnew;
				if(!(bnew=blkgrp_alloc(&conf->rconf)))
					goto error;
				bnew->path_index=sb->btail->path_index+1;
				sb->btail->next=bnew;
				sb->btail=bnew;
			}
			// Now, just add the new sig to the end.
			blkgrp=sb->btail;

			blk=blkgrp->blks[blkgrp->b];
			// FIX THIS: Should not just load into strings.
			if(split_sig(rbuf->buf, rbuf->len,
				blk->weak, blk->strong))
					goto error;
			printf("Need data for %d %d %d %s\n",
				sb->no, blkgrp->path_index,  blkgrp->b,
				slist->mark2->path);
/*
			printf("bg %d blk %d, %s %s\n",
				blkgrp->path_index,
				blkgrp->b,
				blk->weak, blk->strong);
*/

			// Get space ready for the next one.
			if(!(blkgrp->blks[++blkgrp->b]=blk_alloc()))
				goto error;
			goto end;
		}

		case CMD_ATTRIBS:
		{
			// Attribs should come first, so if we already
			// set up snew, it is an error.
			if(snew) break;
			if(!(snew=sbuf_init())) goto error;
			sbuf_from_iobuf_attr(snew, rbuf);
			snew->need_path=1;
			rbuf->buf=NULL;
			return 0;
		}
		case CMD_FILE:
		case CMD_DIRECTORY:
		case CMD_SOFT_LINK:
		case CMD_HARD_LINK:
		case CMD_SPECIAL:
			// Attribs should come first, so if we have not
			// already set up snew, it is an error.
			if(!snew) goto error;
			if(snew->need_path)
			{
				sbuf_from_iobuf_path(snew, rbuf);
				snew->need_path=0;
				rbuf->buf=NULL;
			printf("got request for: %s\n", snew->path);
				if(cmd_is_link(rbuf->cmd))
					snew->need_link=1;
				else
				{
					sbuf_add_to_list(snew, slist);
					snew=NULL;
				}
				return 0;
			}
			else if(snew->need_link)
			{
				sbuf_from_iobuf_link(snew, rbuf);
				snew->need_link=0;
				rbuf->buf=NULL;
				sbuf_add_to_list(snew, slist);
				snew=NULL;
				return 0;
			}
			break;
		case CMD_WARNING:
			logp("WARNING: %s\n", rbuf);
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

	logp("unexpected cmd in %s, got '%c:%s'\n", __FUNCTION__, rcmd, *rbuf);
error:
	ret=-1;
	sbuf_free(inew); inew=NULL;
	sbuf_free(snew); snew=NULL;
end:
	if(rbuf->buf) { free(rbuf->buf); rbuf->buf=NULL; }
	return ret;
}

static void get_wbuf_from_sigs(struct iobuf *wbuf, struct slist *slist)
{
}

static int backup_needed(struct sbuf *sb, gzFile cmanfp)
{
	if(sb->cmd==CMD_FILE) return 1;
	// TODO: Check previous manifest and modification time.
	return 0;
}

static void get_wbuf_from_files(struct iobuf *wbuf, struct slist *slist, gzFile cmanfp)
{
	static uint64_t file_no=1;
	struct sbuf *sb=slist->mark1;
	if(!sb) return;

	if(sb->sent_path || !backup_needed(sb, cmanfp))
	{
		slist->mark1=sb->next;
		return;
	}

	// Only need to request the path at this stage.
	iobuf_from_sbuf_path(wbuf, sb);
	sb->sent_path=1;
	sb->no=file_no++;
}

static int backup_server(gzFile cmanfp, const char *manifest, const char *client, struct config *conf)
{
	int ret=-1;
	gzFile mzp=NULL;
	int backup_end=0;
	struct slist *slist=NULL;
	struct iobuf *rbuf=NULL;
	struct iobuf *wbuf=NULL;

	logp("Begin backup\n");

	if(!(slist=slist_init())
	  || !(wbuf=iobuf_init())
	  || !(rbuf=iobuf_init())
	  || !(mzp=gzopen_file(manifest, comp_level(conf))))
		goto end;

	while(!backup_end)
	{
		if(!wbuf->len)
		{
			get_wbuf_from_sigs(wbuf, slist);
			if(!wbuf->len)
			{
				get_wbuf_from_files(wbuf, slist, cmanfp);
			}
		}

		if(wbuf->len) printf("send request: %s\n", wbuf->buf);
		if(async_rw_ng(rbuf, wbuf))
		{
			logp("error in async_rw\n");
			goto end;
		}

		if(rbuf->buf && deal_with_read(rbuf, slist, conf, &backup_end))
			goto end;
	}
	ret=0;

end:
	if(gzclose(mzp))
	{
		logp("error closing %s in %s\n", manifest, __FUNCTION__);
		ret=-1;
	}
	logp("End backup\n");
	slist_free(slist);
	iobuf_free(rbuf);
	// Write buffer did not allocate 'buf'. 
	wbuf->buf=NULL;
	iobuf_free(wbuf);
	return ret;
}

int do_backup_server(const char *basedir, const char *current, const char *working, const char *currentdata, const char *finishing, struct config *cconf, const char *manifest, const char *client, const char *cversion, const char *incexc)
{
	int ret=0;
	char msg[256]="";
	// The timestamp file of this backup
	char *timestamp=NULL;
	// path to the last manifest
	char *cmanifest=NULL;
	// Real path to the working directory
	char *realworking=NULL;
	char tstmp[64]="";
	struct dpth dpth;
	gzFile cmanfp=NULL;
	struct stat statp;

	logp("in do_backup_server\n");

	if(!(timestamp=prepend_s(working, "timestamp", strlen("timestamp")))
	  || !(cmanifest=prepend_s(current, "manifest.gz", strlen("manifest.gz"))))
	{
		log_and_send_oom(__FUNCTION__);
		goto error;
	}

	if(init_dpth(&dpth, currentdata, cconf))
	{
		log_and_send("could not init_dpth\n");
		goto error;
	}

	if(get_new_timestamp(cconf, basedir, tstmp, sizeof(tstmp)))
		goto error;
	if(!(realworking=prepend_s(basedir, tstmp, strlen(tstmp))))
	{
		log_and_send_oom(__FUNCTION__);
		goto error;
	}
	// Add the working symlink before creating the directory.
	// This is because bedup checks the working symlink before
	// going into a directory. If the directory got created first,
	// bedup might go into it in the moment before the symlink
	// gets added.
	if(symlink(tstmp, working)) // relative link to the real work dir
	{
		snprintf(msg, sizeof(msg),
		  "could not point working symlink to: %s",
		  realworking);
		log_and_send(msg);
		goto error;
	}
	else if(mkdir(realworking, 0777))
	{
		snprintf(msg, sizeof(msg),
		  "could not mkdir for next backup: %s", working);
		log_and_send(msg);
		unlink(working);
		goto error;
	}
	else if(open_log(realworking, client, cversion, cconf))
	{
		goto error;
	}
	else if(write_timestamp(timestamp, tstmp))
	{
		snprintf(msg, sizeof(msg),
		  "unable to write timestamp %s", timestamp);
		log_and_send(msg);
		goto error;
	}
	else if(incexc && *incexc && write_incexc(realworking, incexc))
	{
		snprintf(msg, sizeof(msg), "unable to write incexc");
		log_and_send(msg);
		goto error;
	}

	// Open the previous (current) manifest.
	if(!lstat(cmanifest, &statp))
	{
		if(!(cmanfp=gzopen_file(cmanifest, "rb")))
		{
			logp("could not open old manifest %s\n", cmanifest);
			goto error;
		}
	}

	if(backup_server(cmanfp, manifest, client, cconf))
	{
		logp("error in backup\n");
		goto error;
	}

	async_write_str(CMD_GEN, "backup_end");
	logp("Backup ending - disconnect from client.\n");

	// Close the connection with the client, the rest of the job
	// we can do by ourselves.
	async_free();

	// Move the symlink to indicate that we are now finished.
	if(do_rename(working, current)) goto error;

	goto end;
error:
	ret=-1;
end:
	gzclose_fp(&cmanfp);
	if(timestamp) free(timestamp);
	if(cmanifest) free(cmanifest);
	set_logfp(NULL, cconf); // does an fclose on logfp.
	return ret;
}
