#include "burp.h"
#include "prog.h"
#include "base64.h"
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
#include "hash.h"

static int fprint_tag(FILE *fp, char cmd, unsigned int s)
{
	if(fprintf(fp, "%c%04X", cmd, s)!=5)
	{
		logp("Short fprintf\n");
		return -1;
	}
	return 0;
}

static int fwrite_buf(char cmd, const char *buf, unsigned int s, FILE *fp)
{
	static size_t bytes;
	if(fprint_tag(fp, cmd, s)) return -1;
	if((bytes=fwrite(buf, 1, s, fp))!=s)
	{
		logp("Short write: %d\n", (int)bytes);
		return -1;
	}
	return 0;
}

static FILE *file_open_w(const char *path, const char *mode)
{
	FILE *fp;
	if(build_path_w(path)) return NULL;
	fp=open_file(path, "wb");
	return fp;
}

static int fwrite_dat(char cmd, const char *buf, unsigned int s, struct dpth *dpth)
{
	if(!dpth->dfp && !(dpth->dfp=file_open_w(dpth->path_dat, "wb")))
		return -1;
	return fwrite_buf(cmd, buf, s, dpth->dfp);
}

static int fwrite_sig(char cmd, const char *buf, unsigned int s, struct dpth *dpth)
{
	if(!dpth->sfp && !(dpth->sfp=file_open_w(dpth->path_sig, "wb")))
		return -1;
	return fwrite_buf(cmd, buf, s, dpth->sfp);
}

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

static int backup_needed(struct sbuf *sb, gzFile cmanfp)
{
	if(sb->cmd==CMD_FILE) return 1;
	// TODO: Check previous manifest and modification time.
	return 0;
}

static char *get_fq_path(const char *path)
{
	static char fq_path[24];
	snprintf(fq_path, sizeof(fq_path), "%s\n", path);
	return fq_path;
}

static int already_got_block(struct blk *blk, struct dpth *dpth)
{
	static struct weak_entry *weak_entry;

	blk->fingerprint=strtoull(blk->weak, 0, 16);
	// If already got, need to overwrite the references.
	if((weak_entry=find_weak_entry(blk->fingerprint)))
	{
		struct strong_entry *strong_entry;
		if((strong_entry=find_strong_entry(weak_entry, blk->strong)))
		{
			if(!(blk->data=strdup(get_fq_path(strong_entry->path))))
			{
				log_out_of_memory(__FUNCTION__);
				return -1;
			}
			blk->length=strlen(blk->data);
	printf("FOUND: %s %s\n", blk->weak, blk->strong);
			blk->got=1;
		}
/*
		else
		{
			logp("COLLISION: %s %s\n", weak, strong);
			collisions++;
		}
*/
	}

	return 0;
}

static int add_data_to_store(struct blist *blist, struct iobuf *rbuf, struct dpth *dpth)
{
	char tmp[64];
	static struct blk *blk=NULL;
	static uint64_t data_index=1;
//	static struct weak_entry *weak_entry;

	printf("Got data %lu (%lu)!\n", rbuf->len, data_index);
	data_index++;

	// Find the first one in the list that was requested.
	// FIX THIS: Going up the list here, and then later
	// when writing to the manifest is not efficient.
	if(!blk) blk=blist->head;
	for(; blk && !blk->requested; blk=blk->next) { }
	if(!blk)
	{
		logp("Received data but could not find next requested block.\n");
		return -1;
	}

	// Add it to the data store straight away.
	if(fwrite_dat(CMD_DATA, rbuf->buf, rbuf->len, dpth)) return -1;

	// argh
	snprintf(tmp, sizeof(tmp), "%s%s\n", blk->weak, blk->strong);
	if(fwrite_sig(CMD_SIG, tmp, strlen(tmp), dpth)) return -1;


	// Add to hash table.
//	if(!(weak_entry=add_weak_entry(blk->fingerprint))) return -1;
//	if(!(weak_entry->strong=add_strong_entry(weak_entry, blk->strong, dpth)))
//		return -1;


	// Need to write the refs to the manifest too.
	// Mark that we have got the block, and write it to
	// the manifest later.
	if(!(blk->data=strdup(get_fq_path(dpth_mk(dpth)))))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}

	if(dpth_incr_sig(dpth)) return -1;

	blk->length=strlen(blk->data);
	blk->got=1;
	blk=blk->next;

	return 0;
}

static int set_up_for_sig_info(struct slist *slist, struct blist *blist, struct sbuf *inew)
{
	struct sbuf *sb;

	for(sb=slist->add_sigs_here; sb; sb=sb->next)
	{
		if(!sb->index) continue;
		if(inew->index==sb->index) break;
	}
	if(!sb)
	{
		logp("Could not find %lu in request list %d\n", inew->index, sb->index);
		return -1;
	}
	// Replace the attribs with the more recent
	// values.
	free(sb->attribs);
	sb->attribs=inew->attribs;
	sb->alen=inew->alen;
	inew->attribs=NULL;

	// Mark the end of the previous file.
	slist->add_sigs_here->bend=blist->tail;

	slist->add_sigs_here=sb;

	// Incoming sigs now need to get added to 'add_sigs_here'
	return 0;
}

static int add_to_sig_list(struct slist *slist, struct blist *blist, struct iobuf *rbuf, struct dpth *dpth)
{
	// Goes on slist->add_sigs_here
	struct blk *blk;
	struct sbuf *sb;

	printf("CMD_SIG: %s\n", rbuf->buf);

	sb=slist->add_sigs_here;
	if(!(blk=blk_alloc())) return -1;

	blk_add_to_list(blk, blist);
	if(!sb->bstart) sb->bstart=blk;
	if(!sb->bsighead) sb->bsighead=blk;

	// FIX THIS: Should not just load into strings.
	if(split_sig(rbuf->buf, rbuf->len, blk->weak, blk->strong)) return -1;

	// If already got, this function will set blk->data
	// to be the location of the already got block.
	if(already_got_block(blk, dpth)) return -1;

	if(!blk->got) printf("Need data for %lu %lu %s\n", sb->index,
		blk->index, slist->add_sigs_here->path);

	return 0;
}

static int deal_with_read(struct iobuf *rbuf, struct slist *slist, struct blist *blist, struct config *conf, int *scan_end, int *sigs_end, int *backup_end, gzFile cmanfp, struct dpth *dpth)
{
	int ret=0;
	static struct sbuf *snew=NULL;
	static struct sbuf *inew=NULL;

	if(!inew && !(inew=sbuf_init())) goto error;

	switch(rbuf->cmd)
	{
		/* Incoming block data. */
		case CMD_DATA:
			if(add_data_to_store(blist, rbuf, dpth)) goto error;
			goto end;

		/* Incoming block signatures. */
		case CMD_ATTRIBS_SIGS:
			// New set of stuff incoming. Clean up.
			if(inew->attribs) free(inew->attribs);
			sbuf_from_iobuf_attr(inew, rbuf);
			inew->index=decode_file_no(inew);
			rbuf->buf=NULL;

			// Need to go through slist to find the matching
			// entry.
			if(set_up_for_sig_info(slist, blist, inew)) goto error;
			return 0;
		case CMD_SIG:
			if(add_to_sig_list(slist, blist, rbuf, dpth))
				goto error;
			goto end;

		/* Incoming scan information. */
		case CMD_ATTRIBS:
			// Attribs should come first, so if we already
			// set up snew, it is an error.
			if(snew) break;
			if(!(snew=sbuf_init())) goto error;
			sbuf_from_iobuf_attr(snew, rbuf);
			snew->need_path=1;
			rbuf->buf=NULL;
			return 0;
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
					if(backup_needed(snew, cmanfp))
						snew->changed=1;
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

		/* Incoming control/message stuff. */
		case CMD_WARNING:
			logp("WARNING: %s\n", rbuf);
			do_filecounter(conf->cntr, rbuf->cmd, 0);
			goto end;
		case CMD_GEN:
			if(!strcmp(rbuf->buf, "scan_end"))
			{
printf("SCAN END\n");
				*scan_end=1;
				goto end;
			}
			else if(!strcmp(rbuf->buf, "sigs_end"))
			{
printf("SIGS END\n");
				*sigs_end=1;
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

	logp("unexpected cmd in %s, got '%c:%s'\n", __FUNCTION__, rbuf->cmd, rbuf->buf);
error:
	ret=-1;
	sbuf_free(inew); inew=NULL;
	sbuf_free(snew); snew=NULL;
end:
	if(rbuf->buf) { free(rbuf->buf); rbuf->buf=NULL; }
	return ret;
}

static int encode_req(struct blk *blk, char *req)
{
	char *p=req;
	p+=to_base64(blk->index, p);
	*p=0;
	return 0;
}

static void get_wbuf_from_sigs(struct iobuf *wbuf, struct slist *slist, int sigs_end, int *blk_requests_end)
{
	static char req[32]="";
	struct sbuf *sb=slist->blks_to_request;

	while(sb && !(sb->changed))
	{
		printf("Changed %d: %s\n", sb->changed, sb->path);
		sb=sb->next;
	}
	if(!sb)
	{
		slist->blks_to_request=NULL;
		return;
	}
	if(!sb->bsighead)
	{
		// Trying to move onto the next file.
		// ??? Does this really work?
		if(sb->bend) slist->blks_to_request=sb->next;
		if(sigs_end && !*blk_requests_end)
		{
			iobuf_from_str(wbuf,
				CMD_GEN, (char *)"blk_requests_end");
			*blk_requests_end=1;
		}
		return;
	}

	if(!sb->bsighead->got)
	{
		encode_req(sb->bsighead, req);
		iobuf_from_str(wbuf, CMD_DATA_REQ, req);
	printf("data request: %lu\n", sb->bsighead->index);
		sb->bsighead->requested=1;
	}

	// Move on.
	if(sb->bsighead==sb->bend)
	{
		slist->blks_to_request=sb->next;
		sb->bsighead=sb->bstart;
//		if(!sb->bsighead) printf("sb->bsighead fell off end a\n");
	}
	else
	{
		sb->bsighead=sb->bsighead->next;
//		if(!sb->bsighead) printf("sb->bsighead fell off end b\n");
	}
}

static void get_wbuf_from_files(struct iobuf *wbuf, struct slist *slist, int scan_end, int *requests_end)
{
	static uint64_t file_no=1;
	struct sbuf *sb=slist->last_requested;
	if(!sb)
	{
		if(scan_end && !*requests_end)
		{
			iobuf_from_str(wbuf, CMD_GEN, (char *)"requests_end");
			*requests_end=1;
		}
		return;
	}

	if(sb->sent_path || !sb->changed)
	{
		slist->last_requested=sb->next;
		return;
	}

	// Only need to request the path at this stage.
	iobuf_from_sbuf_path(wbuf, sb);
	sb->sent_path=1;
	sb->index=file_no++;
}

static int write_to_manifest(gzFile mzp, struct slist *slist, struct dpth *dpth)
{
	struct sbuf *sb;
	if(!slist) return 0;

	while((sb=slist->head))
	{
//printf("HEREA\n");
		if(sb->changed)
		{
			// Changed...
			struct blk *blk;
//printf("HERE\n");
			
			if(!sb->header_written_to_manifest)
			{
				if(sbuf_to_manifest(sb, NULL, mzp)) return -1;
				sb->header_written_to_manifest=1;
			}

			for(blk=sb->bstart; blk && blk->got; blk=blk->next)
			{
				gzprintf(mzp, "S%04X%s",
					blk->length, blk->data);
				if(blk==sb->bend)
				{
					slist->head=sb->next;
					// free sb?
					break;
				}

				sb->bstart=blk->next;
				// free blk?
			}
			break;
		}
		else
		{
			// No change, can go straight in.
			if(sbuf_to_manifest(sb, NULL, mzp)) return -1;

			// FIX THIS:
			// Also need to write in the unchanged sigs.

			// Move along.
			slist->head=sb->next;

			// It is possible for the markers to drop behind.
			if(slist->tail==sb) slist->tail=sb->next;
			if(slist->last_requested==sb) slist->last_requested=sb->next;
			if(slist->add_sigs_here==sb) slist->add_sigs_here=sb->next;
			if(slist->blks_to_request==sb) slist->blks_to_request=sb->next;
			sbuf_free(sb);
		}
	}
	return 0;
}

static int backup_server(gzFile cmanfp, const char *manifest, const char *client, const char *datadir, struct config *conf)
{
	int ret=-1;
	gzFile mzp=NULL;
	int scan_end=0;
	int sigs_end=0;
	int backup_end=0;
	int requests_end=0;
	int blk_requests_end=0;
	struct slist *slist=NULL;
	struct blist *blist=NULL;
	struct iobuf *rbuf=NULL;
	struct iobuf *wbuf=NULL;
	struct dpth *dpth=NULL;

	logp("Begin backup\n");
	printf("DATADIR: %s\n", datadir);

	if(!(slist=slist_init())
	  || !(blist=blist_init())
	  || !(wbuf=iobuf_init())
	  || !(rbuf=iobuf_init())
	  || !(mzp=gzopen_file(manifest, comp_level(conf)))
	  || !(dpth=dpth_alloc(datadir))
	  || dpth_init(dpth))
		goto end;

	while(!backup_end)
	{
		if(!wbuf->len)
		{
			get_wbuf_from_sigs(wbuf, slist,
				sigs_end, &blk_requests_end);
			if(!wbuf->len)
			{
				get_wbuf_from_files(wbuf, slist,
					scan_end, &requests_end);
			}
		}

		//if(wbuf->len) printf("send request: %s\n", wbuf->buf);
		if(async_rw_ng(rbuf, wbuf))
		{
			logp("error in async_rw\n");
			goto end;
		}

		if(rbuf->buf && deal_with_read(rbuf, slist, blist, conf,
			&scan_end, &sigs_end, &backup_end, cmanfp, dpth))
				goto end;

		if(write_to_manifest(mzp, slist, dpth))
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
	blist_free(blist);
	iobuf_free(rbuf);
	// Write buffer did not allocate 'buf'. 
	wbuf->buf=NULL;
	iobuf_free(wbuf);
	dpth_free(dpth);
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
	gzFile cmanfp=NULL;
	struct stat statp;
	char *datadir=NULL;

	logp("in do_backup_server\n");

	if(!(timestamp=prepend_s(working, "timestamp", strlen("timestamp")))
	  || !(cmanifest=prepend_s(current, "manifest.gz", strlen("manifest.gz")))
	  || !(datadir=prepend_s(basedir, "data", strlen("data"))))
	{
		log_and_send_oom(__FUNCTION__);
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

	if(backup_server(cmanfp, manifest, client, datadir, cconf))
	{
		logp("error in backup\n");
		goto error;
	}

	//async_write_str(CMD_GEN, "backup_end");
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
	if(datadir) free(datadir);
	set_logfp(NULL, cconf); // does an fclose on logfp.
	return ret;
}
