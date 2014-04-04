#include "include.h"

static int write_incexc(const char *realworking, const char *incexc)
{
	int ret=-1;
	FILE *fp=NULL;
	char *path=NULL;
	if(!(path=prepend_s(realworking, "incexc")))
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

// Used by the burp1 stuff.
int open_log(const char *realworking, struct conf *cconf)
{
	char *logpath=NULL;

	if(!(logpath=prepend_s(realworking, "log")))
	{
		log_and_send_oom(__FUNCTION__);
		return -1;
	}
	if(set_logfp(logpath, cconf))
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg),
				"could not open log file: %s", logpath);
		log_and_send(msg);
		free(logpath);
		return -1;
	}
	free(logpath);

	logp("Client version: %s\n", cconf->peer_version?:"");
	logp("Protocol: %d\n", cconf->protocol);
	// Make sure a warning appears in the backup log.
	// The client will already have been sent a message with logw.
	// This time, prevent it sending a logw to the client by specifying
	// NULL for cntr.
	if(cconf->version_warn) version_warn(NULL, cconf);

	return 0;
}

static int data_needed(struct sbuf *sb)
{
	if(sb->path.cmd==CMD_FILE) return 1;
	return 0;
}

// Can this be merged with copy_unchanged_entry()?
static int forward_through_sigs(struct sbuf **csb, struct manio *cmanio, struct conf *conf)
{
	static int ars;
	char *copy;

	if(!(copy=strdup((*csb)->path.buf)))
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
		if(strcmp((*csb)->path.buf, copy))
		{
			// Found the next entry.
			free(copy);
			return 0;
		}
	}

	free(copy);
	return -1;
}

static int copy_unchanged_entry(struct sbuf **csb, struct sbuf *sb, struct blk **blk, struct manio *cmanio, struct manio *unmanio, struct conf *conf)
{
	static int ars;
	static char *copy;

	// Use the most recent stat for the new manifest.
	if(manio_write_sbuf(unmanio, sb)) return -1;

	if(!(copy=strdup((*csb)->path.buf)))
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
		if(strcmp((*csb)->path.buf, copy))
		{
			// Found the next entry.
			free(copy);
			return 0;
		}
		// Should have the next signature.
		// Write it to the unchanged file.
		if(manio_write_sig_and_path(unmanio, *blk))
		{
			free(copy);
			return -1;
		}
	}

	free(copy);
	return -1;
}

// Return -1 for error, 0 for entry not changed, 1 for entry changed (or new).
static int entry_changed(struct sbuf *sb, struct manio *cmanio, struct manio *unmanio, struct conf *conf)
{
	static int finished=0;
	static struct sbuf *csb=NULL;
	static struct blk *blk=NULL;

	if(finished) return 1;

	if(!csb && !(csb=sbuf_alloc(conf))) return -1;

	if(csb->path.buf)
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
		if(!csb->path.buf)
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
			if(csb->path.cmd!=sb->path.cmd)
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

static int add_data_to_store(struct conf *conf,
	struct blist *blist, struct iobuf *rbuf, struct dpth *dpth)
{
	static struct blk *blk=NULL;

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
	if(dpth_fwrite(dpth, rbuf, blk)) return -1;

	cntr_add(conf->cntr, CMD_DATA, 0);
	cntr_add_recvbytes(conf->cntr, blk->length);

	blk->got=GOT;
	blk=blk->next;

	return 0;
}

static int set_up_for_sig_info(struct slist *slist, struct blist *blist, struct sbuf *inew)
{
	struct sbuf *sb;

	for(sb=slist->add_sigs_here; sb; sb=sb->next)
	{
		if(!sb->burp2->index) continue;
		if(inew->burp2->index==sb->burp2->index) break;
	}
	if(!sb)
	{
		logp("Could not find %lu in request list %d\n",
			inew->burp2->index, sb->burp2->index);
		return -1;
	}
	// Replace the attribs with the more recent values.
	if(sb->attr.buf) free(sb->attr.buf);
	sb->attr.buf=inew->attr.buf;
	sb->attr.len=inew->attr.len;
	inew->attr.buf=NULL;

	// Mark the end of the previous file.
	slist->add_sigs_here->burp2->bend=blist->tail;

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

static int add_to_sig_list(struct slist *slist, struct blist *blist, struct iobuf *rbuf, struct dpth *dpth, uint64_t *wrap_up, struct conf *conf)
{
	int ia;
	// Goes on slist->add_sigs_here
	struct blk *blk;
        struct sbuf *sb;

	//printf("CMD_SIG: %s\n", rbuf->buf);

	if(!(blk=blk_alloc())) return -1;
	blk_add_to_list(blk, blist);

	sb=slist->add_sigs_here;
        if(!sb->burp2->bstart) sb->burp2->bstart=blk;
        if(!sb->burp2->bsighead) sb->burp2->bsighead=blk;

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

static int deal_with_read(struct iobuf *rbuf,
	struct slist *slist, struct blist *blist, struct conf *conf,
	int *sigs_end, int *backup_end, struct dpth *dpth, uint64_t *wrap_up)
{
	int ret=0;
	static struct sbuf *inew=NULL;

	if(!inew && !(inew=sbuf_alloc(conf))) goto error;

	switch(rbuf->cmd)
	{
		/* Incoming block data. */
		case CMD_DATA:
			if(add_data_to_store(conf, blist, rbuf, dpth))
				goto error;
			goto end;

		/* Incoming block signatures. */
		case CMD_ATTRIBS_SIGS:
			// New set of stuff incoming. Clean up.
			if(inew->attr.buf) free(inew->attr.buf);
			iobuf_copy(&inew->attr, rbuf);
			inew->burp2->index=decode_file_no(inew);
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

		/* Incoming control/message stuff. */
		case CMD_WARNING:
			logp("WARNING: %s\n", rbuf);
			cntr_add(conf->cntr, rbuf->cmd, 0);
			goto end;
		case CMD_GEN:
			if(!strcmp(rbuf->buf, "sigs_end"))
			{
//printf("SIGS END\n");
				*sigs_end=1;
				goto end;
			}
			else if(!strcmp(rbuf->buf, "backup_end"))
			{
//printf("BACKUP END\n");
				*backup_end=1;
				goto end;
			}
			break;
	}

	iobuf_log_unexpected(rbuf, __FUNCTION__);
error:
	ret=-1;
	sbuf_free(inew); inew=NULL;
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

static int get_wbuf_from_sigs(struct iobuf *wbuf, struct slist *slist, struct blist *blist, int sigs_end, int *blk_requests_end, struct dpth *dpth, struct conf *conf, uint64_t *wrap_up)
{
	static char req[32]="";
	struct sbuf *sb=slist->blks_to_request;
//printf("get wbuf from sigs: %p\n", sb);

	while(sb && !(sb->flags & SBUF_NEED_DATA))
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
	if(!sb->burp2->bsighead)
	{
//printf("HERE X %d %d: %s\n", sigs_end, *blk_requests_end, sb->path);
		// Trying to move onto the next file.
		// ??? Does this really work?
		if(sb->burp2->bend)
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
//printf("HERE Y %p %p %lu %d\n", sb->burp2->bsighead, sb->burp2->bsighead->next, sb->burp2->bsighead->index, sb->burp2->bsighead->got);

//printf("check: %p %s\n", sb->burp2->bsighead, sb->path); fflush(stdout);
	if(sb->burp2->bsighead->got==INCOMING)
	{
		if(sigs_end
		  && deduplicate(sb->burp2->bsighead, dpth, conf, wrap_up))
			return -1;
		return 0;
	}

	if(sb->burp2->bsighead->got==NOT_GOT)
	{
		encode_req(sb->burp2->bsighead, req);
		iobuf_from_str(wbuf, CMD_DATA_REQ, req);
//printf("DATA REQUEST: %lu %04lX %s\n",
//	sb->burp2->bsighead->index, sb->burp2->bsighead->index, sb->burp2->bsighead->weak);
		sb->burp2->bsighead->requested=1;
	}

	// Move on.
	if(sb->burp2->bsighead==sb->burp2->bend)
	{
		slist->blks_to_request=sb->next;
		sb->burp2->bsighead=sb->burp2->bstart;
//		if(!sb->burp2->bsighead) printf("sb->burp2->bsighead fell off end a\n");
	}
	else
	{
		sb->burp2->bsighead=sb->burp2->bsighead->next;
//		if(!sb->burp2->bsighead) printf("sb->burp2->bsighead fell off end b\n");
	}
//printf("end get_wbuf_fs\n");
	return 0;
}

static void get_wbuf_from_files(struct iobuf *wbuf, struct slist *slist, struct manio *p1manio, int *requests_end)
{
	static uint64_t file_no=1;
	struct sbuf *sb=slist->last_requested;
	if(!sb)
	{
		if(manio_closed(p1manio) && !*requests_end)
		{
			iobuf_from_str(wbuf, CMD_GEN, (char *)"requests_end");
			*requests_end=1;
		}
		return;
	}

	if(sb->flags & SBUF_SENT_PATH || !(sb->flags & SBUF_NEED_DATA))
	{
		slist->last_requested=sb->next;
		return;
	}

	// Only need to request the path at this stage.
	iobuf_copy(wbuf, &sb->path);
//printf("want sigs for: %s\n", sb->path.buf);
	sb->flags |= SBUF_SENT_PATH;
	sb->burp2->index=file_no++;
}

static void sanity_before_sbuf_free(struct slist *slist, struct sbuf *sb)
{
	// It is possible for the markers to drop behind.
	if(slist->tail==sb) slist->tail=sb->next;
	if(slist->last_requested==sb) slist->last_requested=sb->next;
	if(slist->add_sigs_here==sb) slist->add_sigs_here=sb->next;
	if(slist->blks_to_request==sb) slist->blks_to_request=sb->next;
}

static int write_to_changed_file(struct manio *chmanio, struct slist *slist, struct blist *blist, struct dpth *dpth, int backup_end, struct conf *conf)
{
	struct sbuf *sb;
	if(!slist) return 0;

	while((sb=slist->head))
	{
//printf("consider: %s %d\n", sb->path.buf, sb->need_data);
		if(sb->flags & SBUF_NEED_DATA)
		{
			int hack=0;
			// Need data...
			struct blk *blk;

			if(!(sb->flags & SBUF_HEADER_WRITTEN_TO_MANIFEST))
			{
				if(manio_write_sbuf(chmanio, sb)) return -1;
				sb->flags |= SBUF_HEADER_WRITTEN_TO_MANIFEST;
			}

			while((blk=sb->burp2->bstart)
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
						//printf("START USING: %s\n",
						//	chmanio->fpath);
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

				if(blk==sb->burp2->bend)
				{
//printf("blk==sb->burp2->bend END FILE\n");
					slist->head=sb->next;
					//break;
					if(!(blist->head=sb->burp2->bstart))
						blist->tail=NULL;
					sanity_before_sbuf_free(slist, sb);
					sbuf_free(sb);
					hack=1;
					break;
				}

				if(sb->burp2->bsighead==sb->burp2->bstart)
					sb->burp2->bsighead=blk->next;
				sb->burp2->bstart=blk->next;
				blk_free(blk);
			}
			if(hack) continue;
			if(!(blist->head=sb->burp2->bstart))
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
//printf("no more shead\n");
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

static int maybe_add_from_scan(struct manio *p1manio, struct manio *cmanio,
	struct manio *unmanio, struct slist *slist, struct conf *conf)
{
	int ret=-1;
	static int ars;
	static int ec=0;
	struct sbuf *snew=NULL;

	while(1)
	{
		if(manio_closed(p1manio)) return 0;
		// Limit the amount loaded into memory at any one time.
		if(slist && slist->head)
		{
//			printf("%d %d\n", slist->head->burp2->index,
//				slist->tail->burp2->index>4096);
			if(slist->head->burp2->index
			  - slist->tail->burp2->index>4096)
				return 0;
		}
		if(!(snew=sbuf_alloc(conf))) goto end;

		if((ars=manio_sbuf_fill(p1manio, snew, NULL, NULL, conf))<0)
			goto end;
		else if(ars>0) return 0; // Finished.

		if(!(ec=entry_changed(snew, cmanio, unmanio, conf)))
		{
			// No change, no need to add to slist.
			continue;
		}
		else if(ec<0) goto end; // Error.

		if(data_needed(snew)) snew->flags|=SBUF_NEED_DATA;

		sbuf_add_to_list(snew, slist);
	}
	return 0;
end:
	sbuf_free(snew);
	return ret;
}

static int do_backup_phase2_server(struct sdirs *sdirs,
	const char *manifest_dir, int resume, struct conf *conf)
{
	int ret=-1;
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
	struct manio *p1manio=NULL;	// phase1 scan manifest
	struct manio *chmanio=NULL;	// changed manifest
	struct manio *unmanio=NULL;	// unchanged manifest
	// This is used to tell the client that a number of consecutive blocks
	// have been found and can be freed.
	uint64_t wrap_up=0;

	logp("Phase 2 begin (recv backup data)\n");

	if(champ_chooser_init(sdirs->data, conf)
	  || !(cmanio=manio_alloc())
	  || !(p1manio=manio_alloc())
	  || !(chmanio=manio_alloc())
	  || !(unmanio=manio_alloc())
	  || manio_init_read(cmanio, sdirs->cmanifest)
	  || manio_init_read(p1manio, sdirs->phase1data)
	  || manio_init_write(chmanio, sdirs->changed)
	  || manio_init_write(unmanio, sdirs->unchanged)
	  || !(slist=slist_alloc())
	  || !(blist=blist_alloc())
	  || !(wbuf=iobuf_alloc())
	  || !(rbuf=iobuf_alloc())
	  || !(dpth=dpth_alloc(sdirs->data))
	  || dpth_init(dpth))
		goto end;

	// The phase1 manifest looks the same as a burp1 one.
	manio_set_protocol(p1manio, PROTO_BURP1);

//printf("after inits\n");

	while(!backup_end)
	{
//printf("loop a: %d %d %d %d\n",
//	backup_end, sigs_end, requests_end, blk_requests_end);

		if(maybe_add_from_scan(p1manio, cmanio, unmanio, slist, conf))
			goto end;

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
						p1manio, &requests_end);
				}
			}
		}

//		if(wbuf->len) printf("send request: %s\n", wbuf->buf);
		if(async_rw(rbuf, wbuf))
		{
			logp("error in async_rw in %s()\n", __FUNCTION__);
			goto end;
		}

		if(rbuf->buf && deal_with_read(rbuf, slist, blist, conf,
			&sigs_end, &backup_end, dpth, &wrap_up))
				goto end;

		if(write_to_changed_file(chmanio,
			slist, blist, dpth, backup_end, conf))
				goto end;
	}

	// Hack: If there are some entries left after the last entry that
	// contains block data, it will not be written to the changed file
	// yet because the last entry of block data has not had
	// sb->burp2->bend set.
	if(slist->head && slist->head->next)
	{
		slist->head=slist->head->next;
		if(write_to_changed_file(chmanio,
			slist, blist, dpth, backup_end, conf))
				goto end;
	}

	if(blist->head)
	{
		logp("ERROR: finishing but still want block: %lu\n",
			blist->head->index);
		goto end;
	}

	// Need to release the last left. There should be one at most.
	if(dpth->head && dpth->head->next)
	{
		logp("ERROR: More data locks remaining after: %s\n",
			dpth->head->save_path);
		goto end;
	}
	if(dpth_release_all(dpth)) goto end;

	// Flush to disk and set up for read.
	if(manio_set_mode_read(chmanio)
	  || manio_set_mode_read(unmanio))
		goto end;

	if(phase3(chmanio, unmanio, manifest_dir, sdirs->data, conf))
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
	dpth_release_all(dpth);
	dpth_free(dpth);
	manio_free(cmanio);
	manio_free(p1manio);
	manio_free(chmanio);
	manio_free(unmanio);
	return ret;
}

// Clean mess left over from a previously interrupted backup.
static int clean_rubble(struct sdirs *sdirs)
{
	int len=0;
	char *real=NULL;
	char lnk[32]="";
	if((len=readlink(sdirs->working, lnk, sizeof(lnk)-1))<0)
		return 0;
	else if(!len)
	{
		unlink(sdirs->working);
		return 0;
	}
	lnk[len]='\0';
	if(!(real=prepend_s(sdirs->client, lnk)))
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
	unlink(sdirs->working);
	return 0;
}

int do_backup_server(struct sdirs *sdirs, struct conf *cconf,
	const char *incexc, int resume)
{
	int ret=0;
	char msg[256]="";
	// Real path to the working directory
	char *realworking=NULL;
	// Real path to the manifest directory
	char *manifest_dir=NULL;
	char tstmp[64]="";

	logp("in do_backup_server\n");

	if(get_new_timestamp(sdirs, cconf, tstmp, sizeof(tstmp)))
		goto error;
	if(!(realworking=prepend_s(sdirs->client, tstmp))
	 || !(manifest_dir=prepend_s(realworking, "manifest")))
	{
		log_and_send_oom(__FUNCTION__);
		goto error;
	}

	if(clean_rubble(sdirs)) goto error;

	// Add the working symlink before creating the directory.
	// This is because bedup checks the working symlink before
	// going into a directory. If the directory got created first,
	// bedup might go into it in the moment before the symlink
	// gets added.
	if(symlink(tstmp, sdirs->working)) // relative link to the real work dir
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
		  "could not mkdir for next backup: %s", sdirs->working);
		log_and_send(msg);
		unlink(sdirs->working);
		goto error;
	}
	else if(open_log(realworking, cconf))
	{
		goto error;
	}
	else if(write_timestamp(sdirs->timestamp, tstmp))
	{
		snprintf(msg, sizeof(msg),
		  "unable to write timestamp %s", sdirs->timestamp);
		log_and_send(msg);
		goto error;
	}
	else if(incexc && *incexc && write_incexc(realworking, incexc))
	{
		snprintf(msg, sizeof(msg), "unable to write incexc");
		log_and_send(msg);
		goto error;
	}

	if(backup_phase1_server(sdirs, cconf))
	{
		logp("error in phase1\n");
		goto error;
	}

	if(do_backup_phase2_server(sdirs, manifest_dir, resume, cconf))
	{
		logp("error in backup\n");
		goto error;
	}

	// Close the connection with the client, the rest of the job
	// we can do by ourselves.
	async_free();

	cntr_stats_to_file(cconf->cntr, sdirs->working, ACTION_BACKUP);

	// Move the symlink to indicate that we are now finished.
	if(do_rename(sdirs->working, sdirs->current)) goto error;

	cntr_print(cconf->cntr, ACTION_BACKUP);

	logp("Backup completed.\n");

	set_logfp(NULL, cconf); // does an fclose on logfp.
	compress_filename(sdirs->current, "log", "log.gz", cconf);

	if(cconf->keep>0)
	{
		//ret=remove_old_backups(sdirs, cconf);
		// FIX THIS: Need to figure out which data files can be
		// deleted.
	}

	goto end;
error:
	ret=-1;
end:
	set_logfp(NULL, cconf);
	if(manifest_dir) free(manifest_dir);
	if(realworking) free(realworking);
	return ret;
}
