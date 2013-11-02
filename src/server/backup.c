#include "include.h"

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

static int fwrite_dat(struct iobuf *rbuf, struct blk *blk, struct dpth *dpth)
{
	static FILE *fp=NULL;
	static char *last_save_path=NULL;
//printf("want to write: %s\n", blk->save_path);

	if(!fp || (last_save_path && strncmp(last_save_path, blk->save_path,
		14))) // Just the first three components, excluding sig number.
	{
		char *path;
		if(!(path=prepend_s(dpth->base_path, blk->save_path, 14)))
			return -1;
		if(fp && close_fp(&fp))
			return -1;
		if(!(fp=file_open_w(path, "wb")))
		{
			free(path);
			return -1;
		}
		free(path);
		if(last_save_path) free(last_save_path);
		if(!(last_save_path=strdup(blk->save_path)))
		{
			log_out_of_memory(__FUNCTION__);
			return -1;
		}
	}
	return fwrite_buf(CMD_DATA, rbuf->buf, rbuf->len, fp);
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

static int data_needed(struct sbuf *sb)
{
	if(sb->cmd==CMD_FILE) return 1;
	return 0;
}

// Can this be merged with copy_unchanged_entry()?
static int forward_through_sigs(struct sbuf **csb, struct manio *cmanio, struct config *conf)
{
	static int ars;
	char *copy;

	if(!(copy=strdup((*csb)->path)))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}

	while(1)
	{
		if((ars=manio_sbuf_fill(cmanio, *csb,
			NULL, NULL, conf))<0) return -1;
		else if(ars>0)
		{
			// Finished.
			// blk is not getting freed. Never mind.
			sbuf_free(*csb); *csb=NULL;
			free(copy);
			return 0;
		}

		// Got something.
		if(strcmp((*csb)->path, copy))
		{
			// Found the next entry.
			free(copy);
			return 0;
		}
	}

	free(copy);
	return -1;
}

static int copy_unchanged_entry(struct sbuf **csb, struct sbuf *sb, struct blk **blk, struct manio *cmanio, struct manio *unmanio, struct config *conf)
{
	static int ars;
	static char *copy;

	// Use the most recent stat for the new manifest.
	if(manio_write_sbuf(unmanio, sb)) return -1;

	if(!(copy=strdup((*csb)->path)))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}

	while(1)
	{
		if((ars=manio_sbuf_fill(cmanio, *csb,
			*blk, NULL, conf))<0) return -1;
		else if(ars>0)
		{
			// Finished.
			sbuf_free(*csb); *csb=NULL;
			blk_free(*blk); *blk=NULL;
			free(copy);
			return 0;
		}

		// Got something.
		if(strcmp((*csb)->path, copy))
		{
			// Found the next entry.
			free(copy);
			return 0;
		}
		// Should have the next signature.
		// Write it to the unchanged file.
		manio_write_sig_and_path(unmanio, *blk);
	}

	free(copy);
	return -1;
}

// Return -1 for error, 0 for entry not changed, 1 for entry changed (or new).
static int entry_changed(struct sbuf *sb, struct manio *cmanio, struct manio *unmanio, struct config *conf)
{
	static int finished=0;
	static struct sbuf *csb=NULL;
	static struct blk *blk=NULL;

	if(finished) return 1;

	if(!csb && !(csb=sbuf_alloc())) return -1;

	if(csb->path)
	{
		// Already have an entry.
	}
	else
	{
		static int ars;
		// Need to read another.
		if(!blk && !(blk=blk_alloc())) return -1;
		if((ars=manio_sbuf_fill(cmanio, csb, blk, NULL, conf))<0)
			return -1;
		else if(ars>0)
		{
			// Reached the end.
			sbuf_free(csb); csb=NULL;
			blk_free(blk); blk=NULL;
			finished=1;
			return 1;
		}
		if(!csb->path)
		{
			logp("Should have an path at this point, but do not, in %s\n", __FUNCTION__);
			return -1;
		}
		// Got an entry.
	}

	while(1)
	{
		static int pcmp;
		static int sbret;

		if(!(pcmp=sbuf_pathcmp(csb, sb)))
		{
			// Located the entry in the current manifest.
			// If the file type changed, I think it is time to back
			// it up again (for example, EFS changing to normal
			// file, or back again).
			if(csb->cmd!=sb->cmd)
			{
//				printf("got changed: %c %s %c %s %lu %lu\n", csb->cmd, csb->path, sb->cmd, sb->path, csb->statp.st_mtime, sb->statp.st_mtime);
				if(forward_through_sigs(&csb, cmanio, conf))
					return -1;
				return 1;
			}

			// mtime is the actual file data.
			// ctime is the attributes or meta data.
			if(csb->statp.st_mtime==sb->statp.st_mtime
			  && csb->statp.st_ctime==sb->statp.st_ctime)
			{
				// Got an unchanged file.
//				printf("got unchanged: %c %s %c %s %lu %lu\n", csb->cmd, csb->path, sb->cmd, sb->path, csb->statp.st_mtime, sb->statp.st_mtime);
				if(copy_unchanged_entry(&csb, sb, &blk,
					cmanio, unmanio, conf))
						return -1;
				return 0;
			}

			if(csb->statp.st_mtime==sb->statp.st_mtime
			  && csb->statp.st_ctime!=sb->statp.st_ctime)
			{
				// File data stayed the same, but attributes or
				// meta data changed. We already have the
				// attributes, but may need to get extra meta
				// data.
				// FIX THIS
//				printf("got unchanged b: %c %s %c %s %lu %lu\n", csb->cmd, csb->path, sb->cmd, sb->path, csb->statp.st_mtime, sb->statp.st_mtime);
				if(copy_unchanged_entry(&csb, sb, &blk,
					cmanio, unmanio, conf))
						return -1;
				return 0;
			}

//			printf("got changed: %c %s %c %s %lu %lu\n", csb->cmd, csb->path, sb->cmd, sb->path, csb->statp.st_mtime, sb->statp.st_mtime);

			// File data changed.
			if(forward_through_sigs(&csb, cmanio, conf))
				return -1;
			return 1;
		}
		else if(pcmp>0)
		{
			// Ahead - this is a new file.
//			printf("got new file: %c %s\n", sb->cmd, sb->path);
			return 1;
		}
		else
		{
			// Behind - need to read more data from the old
			// manifest.
		}

		if((sbret=manio_sbuf_fill(cmanio, csb, blk, NULL, conf))<0)
			return -1;
		else if(sbret>0)
		{
			// Reached the end.
			sbuf_free(csb); csb=NULL;
			blk_free(blk); blk=NULL;
			return 1;
		}
		// Got something, go back around the loop.
	}

	return 0;
}

static int add_data_to_store(struct blist *blist, struct iobuf *rbuf, struct dpth *dpth)
{
	static struct blk *blk=NULL;
//	struct blk *blk=NULL;
//	static struct weak_entry *weak_entry;

//	printf("Got data %lu!\n", rbuf->len);

	// Find the first one in the list that was requested.
	// FIX THIS: Going up the list here, and then later
	// when writing to the manifest is not efficient.
	//if(!blk)
		blk=blist->head;
	for(; blk && (!blk->requested || blk->got==GOT); blk=blk->next)
	{
		logp("try: %d %d\n", blk->index, blk->got);
	}
	if(!blk)
	{
		logp("Received data but could not find next requested block.\n");
		if(!blist->head) logp("and blist->head is null\n");
		else logp("head index: %d\n", blist->head->index);
		return -1;
	}
//	printf("Got blk %lu!\n", blk->index);

	// Add it to the data store straight away.
	if(fwrite_dat(rbuf, blk, dpth)) return -1;

	blk->got=GOT;
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
	// Replace the attribs with the more recent values.
	if(sb->attribs) free(sb->attribs);
	sb->attribs=inew->attribs;
	sb->alen=inew->alen;
	inew->attribs=NULL;

	// Mark the end of the previous file.
	slist->add_sigs_here->bend=blist->tail;

	slist->add_sigs_here=sb;

	// Incoming sigs now need to get added to 'add_sigs_here'
	return 0;
}

/*
static void dump_blks(const char *msg, struct blk *b)
{
	struct blk *xx;
	for(xx=b; xx; xx=xx->next)
		printf("%s: %d %d %p\n", msg, xx->index, xx->got, xx);
}
*/

static int add_to_sig_list(struct slist *slist, struct blist *blist, struct iobuf *rbuf, struct dpth *dpth, uint64_t *wrap_up, struct config *conf)
{
	int ia;
	// Goes on slist->add_sigs_here
	struct blk *blk;
        struct sbuf *sb;

	//printf("CMD_SIG: %s\n", rbuf->buf);

	if(!(blk=blk_alloc())) return -1;
	blk_add_to_list(blk, blist);

	sb=slist->add_sigs_here;
        if(!sb->bstart) sb->bstart=blk;
        if(!sb->bsighead) sb->bsighead=blk;

	// FIX THIS: Should not just load into strings.
	if(split_sig(rbuf->buf, rbuf->len, blk->weak, blk->strong)) return -1;

	if((ia=deduplicate_maybe(blk, dpth, conf, wrap_up))<0)
	{
//		printf("dm -1\n");
		return -1;
	}
	else if(!ia)
	{
//		printf("dm 0\n");
		return 0; // Nothing to do for now.
	}

//	printf("dm post\n");
	return 0;
}

static int deal_with_read(struct iobuf *rbuf, struct slist *slist, struct blist *blist, struct config *conf, int *scan_end, int *sigs_end, int *backup_end, struct manio *cmanio, struct manio *unmanio, struct dpth *dpth, uint64_t *wrap_up, const char *data_dir)
{
	int ret=0;
	static int ec=0;
	static int compression; // currently unused
	static struct sbuf *snew=NULL;
	static struct sbuf *inew=NULL;

	if(!inew && !(inew=sbuf_alloc())) goto error;

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
			if(add_to_sig_list(slist, blist,
				rbuf, dpth, wrap_up, conf))
					goto error;
			goto end;

		/* Incoming scan information. */
		case CMD_ATTRIBS:
			// Attribs should come first, so if we already
			// set up snew, it is an error.
			if(snew) break;
			if(!(snew=sbuf_alloc())) goto error;
			sbuf_from_iobuf_attr(snew, rbuf);
			attribs_decode(snew, &compression);
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
//			printf("got request for: %s\n", snew->path);
				if(cmd_is_link(rbuf->cmd))
					snew->need_link=1;
				else
				{
					if(!(ec=entry_changed(snew, cmanio,
							unmanio, conf)))
						sbuf_free(snew);
					else if(ec<0)
						goto error;
					else
					{
						snew->need_data=data_needed(snew);
						sbuf_add_to_list(snew, slist);
					}
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
printf("GOT SCAN END\n");
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

static int get_wbuf_from_sigs(struct iobuf *wbuf, struct slist *slist, struct blist *blist, int sigs_end, int *blk_requests_end, struct dpth *dpth, struct config *conf, uint64_t *wrap_up)
{
	static char req[32]="";
	struct sbuf *sb=slist->blks_to_request;
//printf("get wbuf from sigs: %p\n", sb);

	while(sb && !sb->need_data)
	{
//		printf("Do not need data %d: %s\n", sb->need_data, sb->path);
		sb=sb->next;
	}
	if(!sb)
	{
		slist->blks_to_request=NULL;
		if(sigs_end && !*blk_requests_end)
		{
			iobuf_from_str(wbuf,
				CMD_GEN, (char *)"blk_requests_end");
			*blk_requests_end=1;
		}
		return 0;
	}
	if(!sb->bsighead)
	{
//printf("HERE X %d %d: %s\n", sigs_end, *blk_requests_end, sb->path);
		// Trying to move onto the next file.
		// ??? Does this really work?
		if(sb->bend)
		{
			slist->blks_to_request=sb->next;
			printf("move to next\n");
		}
		if(sigs_end && !*blk_requests_end)
		{
			iobuf_from_str(wbuf,
				CMD_GEN, (char *)"blk_requests_end");
			*blk_requests_end=1;
		}
		return 0;
	}
//printf("HERE Y %p %p %lu %d\n", sb->bsighead, sb->bsighead->next, sb->bsighead->index, sb->bsighead->got);

//printf("check: %p %s\n", sb->bsighead, sb->path); fflush(stdout);
	if(sb->bsighead->got==INCOMING)
	{
		if(sigs_end
		  && deduplicate(sb->bsighead, dpth, conf, wrap_up))
			return -1;
		return 0;
	}

	if(sb->bsighead->got==NOT_GOT)
	{
		encode_req(sb->bsighead, req);
		iobuf_from_str(wbuf, CMD_DATA_REQ, req);
//printf("DATA REQUEST: %lu %04lX %s\n",
//	sb->bsighead->index, sb->bsighead->index, sb->bsighead->weak);
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
//printf("end get_wbuf_fs\n");
	return 0;
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

	if(sb->sent_path || !sb->need_data)
	{
		slist->last_requested=sb->next;
		return;
	}

	// Only need to request the path at this stage.
	iobuf_from_sbuf_path(wbuf, sb);
//printf("want sigs for: %s\n", sb->path);
	sb->sent_path=1;
	sb->index=file_no++;
}

static void sanity_before_sbuf_free(struct slist *slist, struct sbuf *sb)
{
	// It is possible for the markers to drop behind.
	if(slist->tail==sb) slist->tail=sb->next;
	if(slist->last_requested==sb) slist->last_requested=sb->next;
	if(slist->add_sigs_here==sb) slist->add_sigs_here=sb->next;
	if(slist->blks_to_request==sb) slist->blks_to_request=sb->next;
}

static int write_to_changed_file(struct manio *chmanio, struct slist *slist, struct blist *blist, struct dpth *dpth, int backup_end, struct config *conf)
{
	struct sbuf *sb;
	if(!slist) return 0;

	while((sb=slist->head))
	{
//printf("consider: %s\n", sb->path);
		if(sb->need_data)
		{
			int hack=0;
			// Need data...
			struct blk *blk;

			if(!sb->header_written_to_manifest)
			{
				if(manio_write_sbuf(chmanio, sb)) return -1;
				sb->header_written_to_manifest=1;
			}

			while((blk=sb->bstart)
				&& blk->got==GOT
				&& (blk->next || backup_end))
			{
				if(*(blk->save_path))
				{
					if(manio_write_sig_and_path(chmanio,
						blk)) return -1;
					if(chmanio->sig_count==0)
					{
						// Have finished a manifest
						// file. Want to start using
						// it as a dedup candidate
						// now.
						printf("START USING: %s\n",
							chmanio->fpath);
						if(add_fresh_candidate(
							chmanio->fpath,
							conf)) return -1;
					}
				}
/*
				else
				{
					// This gets hit if there is a zero
					// length file.
					printf("!!!!!!!!!!!!! no data; %s\n",
						sb->path);
					exit(1);
				}
*/

				if(blk==sb->bend)
				{
//printf("blk==sb->bend END FILE\n");
					slist->head=sb->next;
					//break;
					if(!(blist->head=sb->bstart))
						blist->tail=NULL;
					sanity_before_sbuf_free(slist, sb);
					sbuf_free(sb);
					hack=1;
					break;
				}

				if(sb->bsighead==sb->bstart)
					sb->bsighead=blk->next;
				sb->bstart=blk->next;
				blk_free(blk);
			}
			if(hack) continue;
			if(!(blist->head=sb->bstart))
				blist->tail=NULL;
			break;
		}
		else
		{
			// No change, can go straight in.
			if(manio_write_sbuf(chmanio, sb)) return -1;

			// Move along.
//printf("END FILE\n");
			slist->head=sb->next;

			sanity_before_sbuf_free(slist, sb);
			sbuf_free(sb);
		}
	}
	return 0;
}

static void get_wbuf_from_wrap_up(struct iobuf *wbuf, uint64_t *wrap_up)
{
	static char *p;
	static char tmp[32];
	if(!*wrap_up) return;
	p=tmp;
	p+=to_base64(*wrap_up, tmp);
	*p='\0';
	iobuf_from_str(wbuf, CMD_WRAP_UP, tmp);
	*wrap_up=0;
}

/*
static void dump_slist(struct slist *slist, const char *msg)
{
	struct sbuf *sb;
	printf("%s\n", msg);
	for(sb=slist->head; sb; sb=sb->next)
		printf("%s\n", sb->path);
}
*/

static int backup_server(const char *cmanifest_dir, const char *changed_dir, const char *unchanged_dir, const char *client, const char *data_dir, const char *manifest_dir, struct config *conf)
{
	int ret=-1;
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
	struct manio *cmanio=NULL;	// current manifest
	struct manio *chmanio=NULL;	// changed manifest
	struct manio *unmanio=NULL;	// unchanged manifest
	// This is used to tell the client that a number of consecutive blocks
	// have been found and can be freed.
	uint64_t wrap_up=0;

	logp("Begin backup\n");
	printf("DATADIR: %s\n", data_dir);

	if(champ_chooser_init(data_dir, conf)
	  || !(cmanio=manio_alloc())
	  || !(chmanio=manio_alloc())
	  || !(unmanio=manio_alloc())
	  || manio_init_read(cmanio, cmanifest_dir)
	  || manio_init_write(chmanio, changed_dir)
	  || manio_init_write(unmanio, unchanged_dir)
	  || !(slist=slist_alloc())
	  || !(blist=blist_alloc())
	  || !(wbuf=iobuf_alloc())
	  || !(rbuf=iobuf_alloc())
	  || !(dpth=dpth_alloc(data_dir))
	  || dpth_init(dpth))
		goto end;

	while(!backup_end)
	{
//printf("loop a: %d %d %d %d %d\n",
//	backup_end, scan_end, sigs_end, requests_end, blk_requests_end);
		if(!wbuf->len)
		{
			get_wbuf_from_wrap_up(wbuf, &wrap_up);
			if(!wbuf->len)
			{
				if(get_wbuf_from_sigs(wbuf, slist, blist,
					sigs_end, &blk_requests_end, dpth,
						conf, &wrap_up))
							goto end;
				if(!wbuf->len)
				{
					get_wbuf_from_files(wbuf, slist,
						scan_end, &requests_end);
				}
			}
		}

//		if(wbuf->len) printf("send request: %s\n", wbuf->buf);
		if(async_rw_ng(rbuf, wbuf))
		{
			logp("error in async_rw in %s()\n", __FUNCTION__);
			goto end;
		}

		if(rbuf->buf && deal_with_read(rbuf, slist, blist, conf,
			&scan_end, &sigs_end, &backup_end,
			cmanio, unmanio, dpth, &wrap_up, data_dir))
				goto end;

		if(write_to_changed_file(chmanio,
			slist, blist, dpth, backup_end, conf))
				goto end;
	}

	if(blist->head)
	{
		printf("FINISHING but still want block: %lu\n",
			blist->head->index);
		goto end;
	}

	// Flush to disk and set up for read.
	if(manio_set_mode_read(chmanio)
	  || manio_set_mode_read(unmanio))
		goto end;

	if(phase3(chmanio, unmanio, manifest_dir, data_dir, conf))
		goto end;

	ret=0;
end:
	logp("End backup\n");
	slist_free(slist);
	blist_free(blist);
	iobuf_free(rbuf);
	// Write buffer did not allocate 'buf'. 
	if(wbuf) wbuf->buf=NULL;
	iobuf_free(wbuf);
	dpth_free(dpth);
	manio_free(cmanio);
	manio_free(chmanio);
	manio_free(unmanio);
	return ret;
}

// Clean mess left over from a previously interrupted backup.
static int clean_rubble(const char *basedir, const char *working)
{
	int len=0;
	char *real=NULL;
	char lnk[32]="";
	if((len=readlink(working, lnk, sizeof(lnk)-1))<0)
		return 0;
	else if(!len)
	{
		unlink(working);
		return 0;
	}
	lnk[len]='\0';
	if(!(real=prepend_s(basedir, lnk, strlen(lnk))))
	{
		log_and_send_oom(__FUNCTION__);
		return -1;
	}
	if(recursive_delete(real, "", 1))
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg), "Could not remove interrupted directory: %s", real);
		log_and_send(msg);
		return -1;
	}
	unlink(working);
	return 0;
}

int do_backup_server(const char *basedir, const char *current, const char *working, const char *currentdata, const char *finishing, struct config *cconf, const char *client, const char *cversion, const char *incexc)
{
	int ret=0;
	char msg[256]="";
	// The timestamp file of this backup
	char *timestamp=NULL;
	// path to the last manifest directory
	char *cmanifest_dir=NULL;
	// Real path to the working directory
	char *realworking=NULL;
	// Real path to the manifest directory
	char *manifest_dir=NULL;
	char tstmp[64]="";
	char *data_dir=NULL;
	char *changed_dir=NULL;
	char *unchanged_dir=NULL;

	logp("in do_backup_server\n");

	if(!(timestamp=prepend_s(working, "timestamp", strlen("timestamp")))
	  || !(cmanifest_dir=prepend_s(current, "manifest", strlen("manifest")))
	  || !(data_dir=prepend_s(basedir, "data", strlen("data")))
	  || !(changed_dir=prepend_s(working, "changed", strlen("changed")))
	  || !(unchanged_dir=prepend_s(working, "unchanged", strlen("unchanged"))))
	{
		log_and_send_oom(__FUNCTION__);
		goto error;
	}

	if(get_new_timestamp(cconf, basedir, tstmp, sizeof(tstmp)))
		goto error;
	if(!(realworking=prepend_s(basedir, tstmp, strlen(tstmp)))
	 || !(manifest_dir=prepend_s(realworking, "manifest", strlen("manifest"))))
	{
		log_and_send_oom(__FUNCTION__);
		goto error;
	}

	if(clean_rubble(basedir, working)) goto error;

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

	if(backup_server(cmanifest_dir, changed_dir, unchanged_dir,
		client, data_dir, manifest_dir, cconf))
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
	if(timestamp) free(timestamp);
	if(cmanifest_dir) free(cmanifest_dir);
	if(data_dir) free(data_dir);
	if(changed_dir) free(changed_dir);
	if(unchanged_dir) free(unchanged_dir);
	if(manifest_dir) free(manifest_dir);
	set_logfp(NULL, cconf); // does an fclose on logfp.
	return ret;
}
