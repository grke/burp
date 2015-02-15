#include "include.h"
#include "../cmd.h"
#include "../linkhash.h"
#include "burp1/restore.h"
#include "burp2/dpth.h"
#include "burp2/restore.h"
#include "burp2/restore_spool.h"

static enum asl_ret restore_end_func(struct asfd *asfd,
	struct conf *conf, void *param)
{
	if(!strcmp(asfd->rbuf->buf, "restoreend_ok"))
		return ASL_END_OK;
	iobuf_log_unexpected(asfd->rbuf, __func__);
	return ASL_END_ERROR;
}

static int restore_end(struct asfd *asfd, struct conf *conf)
{
	if(asfd->write_str(asfd, CMD_GEN, "restoreend")) return -1;
	return asfd->simple_loop(asfd,
		conf, NULL, __func__, restore_end_func);
}


static int srestore_matches(struct strlist *s, const char *path)
{
	int r=0;
	if(!s->flag) return 0; // Do not know how to do excludes yet.
	if((r=strncmp_w(path, s->path))) return 0; // no match
	if(!r) return 1; // exact match
	if(*(path+strlen(s->path)+1)=='/')
		return 1; // matched directory contents
	return 0; // no match
}

// Used when restore is initiated from the server.
static int check_srestore(struct conf *conf, const char *path)
{
	struct strlist *l;

	// If no includes specified, restore everything.
	if(!conf->incexcdir) return 1;

	for(l=conf->incexcdir; l; l=l->next)
		if(srestore_matches(l, path))
			return 1;
	return 0;
}

int want_to_restore(int srestore, struct sbuf *sb,
	regex_t *regex, struct conf *cconf)
{
	return (!srestore || check_srestore(cconf, sb->path.buf))
	  && check_regex(regex, sb->path.buf);
}

static int setup_cntr(struct asfd *asfd, const char *manifest,
        regex_t *regex, int srestore,
        enum action act, char status, struct conf *cconf)
{
	int ars=0;
	int ret=-1;
	gzFile zp;
	struct sbuf *sb=NULL;

// FIX THIS: this is only trying to work for burp1.
	if(cconf->protocol!=PROTO_BURP1) return 0;

	if(!(sb=sbuf_alloc(cconf))) goto end;
	if(!(zp=gzopen_file(manifest, "rb")))
	{
		log_and_send(asfd, "could not open manifest");
		goto end;
	}
	while(1)
	{
		if((ars=sbufl_fill(sb, asfd, NULL, zp, cconf->cntr)))
		{
			if(ars<0) goto end;
			// ars==1 means end ok
			break;
		}
		else
		{
			if(want_to_restore(srestore, sb, regex, cconf))
			{
				cntr_add_phase1(cconf->cntr, sb->path.cmd, 0);
				if(sb->burp1->endfile.buf)
					cntr_add_val(cconf->cntr,
						CMD_BYTES_ESTIMATED,
						strtoull(sb->burp1->endfile.buf,
							NULL, 10), 0);
			}
		}
		sbuf_free_content(sb);
	}
	ret=0;
end:
	sbuf_free(&sb);
	gzclose_fp(&zp);
	return ret;
}

static int restore_sbuf(struct asfd *asfd, struct sbuf *sb, struct bu *bu,
	enum action act, struct sdirs *sdirs, enum cntr_status cntr_status,
	struct conf *cconf, int *need_data, const char *manifest,
	struct slist *slist);

// Used when restoring a hard link that we have not restored the destination
// for. Read through the manifest from the beginning and substitute the path
// and data to the new location.
static int hard_link_substitution(struct asfd *asfd,
	struct sbuf *sb, struct f_link *lp,
	struct bu *bu, enum action act, struct sdirs *sdirs,
	enum cntr_status cntr_status, struct conf *cconf,
	const char *manifest, struct slist *slist)
{
	int ret=-1;
	int need_data=0;
	int last_ent_was_dir=0;
	struct sbuf *hb=NULL;
	struct manio *manio=NULL;
	struct blk *blk=NULL;
	struct dpth *dpth=NULL;
	int pcmp;

	if(!(manio=manio_alloc())
	  || manio_init_read(manio, manifest)
	  || !(hb=sbuf_alloc(cconf)))
		goto end;
	manio_set_protocol(manio, cconf->protocol);

	if(cconf->protocol==PROTO_BURP2)
	{
		  if(!(blk=blk_alloc())
		    || !(dpth=dpth_alloc(sdirs->data)))
                	goto end;
	}

	while(1)
	{
		switch(manio_sbuf_fill(manio, asfd,
			hb, need_data?blk:NULL, dpth, cconf))
		{
			case 0: break; // Keep going.
			case 1: ret=0; goto end; // Finished OK.
			default: goto end; // Error;
		}

		if(cconf->protocol==PROTO_BURP2)
		{
			if(blk->data)
			{
				if(burp2_extra_restore_stream_bits(asfd, blk,
					slist, need_data, last_ent_was_dir,
					cconf)) goto end;
				continue;
			}
			need_data=0;
		}

		pcmp=pathcmp(lp->name, hb->path.buf);

		if(!pcmp && sbuf_is_filedata(hb))
		{
			// Copy the path from sb to hb.
			free_w(&hb->path.buf);
			if(!(hb->path.buf=strdup_w(sb->path.buf, __func__)))
				goto end;
			// Should now be able to restore the original data
			// to the new location.
			ret=restore_sbuf(asfd, hb, bu, act, sdirs,
			  cntr_status, cconf, &need_data, manifest, slist);
			// May still need to get burp2 data.
			if(!ret && need_data) continue;
			break;
		}

		sbuf_free_content(hb);
		// Break out once we have gone past the entry that we are
		// interested in.
		if(pcmp<0) break;
	}
end:
	blk_free(&blk);
	sbuf_free(&hb);
	manio_free(&manio);
	return ret;
}

static int restore_sbuf(struct asfd *asfd, struct sbuf *sb, struct bu *bu,
	enum action act, struct sdirs *sdirs, enum cntr_status cntr_status,
	struct conf *cconf, int *need_data, const char *manifest,
	struct slist *slist)
{
	//printf("%s: %s\n", act==ACTION_RESTORE?"restore":"verify", sb->path.buf);
	if(write_status(cntr_status, sb->path.buf, cconf)) return -1;

	if(sb->path.cmd==CMD_HARD_LINK)
	{
		struct f_link *lp=NULL;
		struct f_link **bucket=NULL;
		if((lp=linkhash_search(&sb->statp, &bucket)))
		{
			// It is in the list of stuff that is in the manifest,
			// but was skipped on this restore.
			// Need to go through the manifest from the beginning,
			// and substitute in the data to restore to this
			// location.
			return hard_link_substitution(asfd, sb, lp,
				bu, act, sdirs, cntr_status, cconf, manifest,
				slist);
			// FIX THIS: Would be nice to remember the new link
			// location so that further hard links would link to
			// it instead of doing the hard_link_substitution
			// business over again.
		}
	}

	if(cconf->protocol==PROTO_BURP1)
	{
		return restore_sbuf_burp1(asfd, sb, bu,
		  act, sdirs, cntr_status, cconf);
	}
	else
	{
		return restore_sbuf_burp2(asfd, sb,
		  act, cntr_status, cconf, need_data);
	}
}

int restore_ent(struct asfd *asfd,
	struct sbuf **sb,
	struct slist *slist,
	struct bu *bu,
	enum action act,
	struct sdirs *sdirs,
	enum cntr_status cntr_status,
	struct conf *cconf,
	int *need_data,
	int *last_ent_was_dir,
	const char *manifest)
{
	int ret=-1;
	struct sbuf *xb;

	if(!(*sb)->path.buf)
	{
		logp("Got NULL path!\n");
		return -1;
	}

	// Check if we have any directories waiting to be restored.
	while((xb=slist->head))
	{
		if(is_subdir(xb->path.buf, (*sb)->path.buf))
		{
			// We are still in a subdir.
			break;
		}
		else
		{
			// Can now restore xb because nothing else is fiddling
			// in a subdirectory.
			if(restore_sbuf(asfd, xb, bu,
			  act, sdirs, cntr_status, cconf, need_data, manifest,
			  slist))
				goto end;
			slist->head=xb->next;
			sbuf_free(&xb);
		}
	}

	/* If it is a directory, need to remember it and restore it later, so
	   that the permissions come out right. */
	/* Meta data of directories will also have the stat stuff set to be a
	   directory, so will also come out at the end. */
	/* FIX THIS: for Windows, need to read and remember the blocks that
	   go with the directories. Probably have to do the same for metadata
	   that goes with directories. */
	if(S_ISDIR((*sb)->statp.st_mode))
	{
		// Add to the head of the list instead of the tail.
		(*sb)->next=slist->head;
		slist->head=*sb;

		*last_ent_was_dir=1;

		// Allocate a new sb.
		if(!(*sb=sbuf_alloc(cconf))) goto end;
	}
	else
	{
		*last_ent_was_dir=0;
		if(restore_sbuf(asfd, *sb, bu,
		  act, sdirs, cntr_status, cconf, need_data, manifest,
		  slist))
			goto end;
	}
	ret=0;
end:
	return ret;
}

static int restore_remaining_dirs(struct asfd *asfd, struct bu *bu,
	struct slist *slist, enum action act, struct sdirs *sdirs,
	enum cntr_status cntr_status, struct conf *cconf)
{
	struct sbuf *sb;
	// Restore any directories that are left in the list.
	for(sb=slist->head; sb; sb=sb->next)
	{
		if(cconf->protocol==PROTO_BURP1)
		{
			if(restore_sbuf_burp1(asfd, sb, bu, act,
				sdirs, cntr_status, cconf))
					return -1;
		}
		else
		{
			int need_data=0; // Unused.
			if(restore_sbuf_burp2(asfd, sb, act,
				cntr_status, cconf, &need_data))
					return -1;
		}
	}
	return 0;
}

static int restore_stream(struct asfd *asfd, struct sdirs *sdirs,
        struct slist *slist, struct bu *bu, const char *manifest,
	regex_t *regex, int srestore, struct conf *cconf, enum action act,
        enum cntr_status cntr_status)
{
	int ret=-1;
	int need_data=0;
	int last_ent_was_dir=0;
	struct sbuf *sb=NULL;
	struct iobuf *rbuf=asfd->rbuf;
	struct manio *manio=NULL;
	struct blk *blk=NULL;
	struct dpth *dpth=NULL;

	if(cconf->protocol==PROTO_BURP2)
	{
		if(asfd->write_str(asfd, CMD_GEN, "restore_stream")
		  || asfd->read_expect(asfd, CMD_GEN, "restore_stream_ok")
		  || !(blk=blk_alloc())
		  || !(dpth=dpth_alloc(sdirs->data)))
                	goto end;
	}

	if(!(manio=manio_alloc())
	  || manio_init_read(manio, manifest)
	  || !(sb=sbuf_alloc(cconf)))
		goto end;
	manio_set_protocol(manio, cconf->protocol);

	while(1)
	{
		iobuf_free_content(rbuf);
		if(asfd->as->read_quick(asfd->as))
		{
			logp("read quick error\n");
			goto end;
		}
		if(rbuf->buf) switch(rbuf->cmd)
		{
			case CMD_WARNING:
				logp("WARNING: %s\n", rbuf->buf);
				cntr_add(cconf->cntr, rbuf->cmd, 0);
				continue;
			case CMD_INTERRUPT:
				// Client wanted to interrupt the
				// sending of a file. But if we are
				// here, we have already moved on.
				// Ignore.
				continue;
			default:
				iobuf_log_unexpected(rbuf, __func__);
				goto end;
		}

		switch(manio_sbuf_fill(manio, asfd,
			sb, need_data?blk:NULL, dpth, cconf))
		{
			case 0: break; // Keep going.
			case 1: ret=0; goto end; // Finished OK.
			default: goto end; // Error;
		}

		if(cconf->protocol==PROTO_BURP2)
		{
			if(blk->data)
			{
				if(burp2_extra_restore_stream_bits(asfd, blk,
					slist, need_data, last_ent_was_dir,
					cconf)) goto end;
				continue;
			}
			need_data=0;
		}

		if(want_to_restore(srestore, sb, regex, cconf))
		{
			if(restore_ent(asfd, &sb, slist,
				bu, act, sdirs, cntr_status, cconf,
				&need_data, &last_ent_was_dir, manifest))
					goto end;
		}
		else if(sbuf_is_filedata(sb))
		{
			// Add it to the list of filedata that was not
			// restored.
			struct f_link **bucket=NULL;
			if(!linkhash_search(&sb->statp, &bucket)
			  && linkhash_add(sb->path.buf, &sb->statp, bucket))
				goto end;
		}

		sbuf_free_content(sb);
	}
end:
	blk_free(&blk);
	sbuf_free(&sb);
	iobuf_free_content(rbuf);
	manio_free(&manio);
	dpth_free(&dpth);
	return ret;
}

static int actual_restore(struct asfd *asfd, struct bu *bu,
	const char *manifest, regex_t *regex, int srestore, enum action act,
	struct sdirs *sdirs, enum cntr_status cntr_status, struct conf *cconf)
{
        int ret=-1;
	int do_restore_stream=1;
        // For out-of-sequence directory restoring so that the
        // timestamps come out right:
        struct slist *slist=NULL;

	if(linkhash_init()
          || !(slist=slist_alloc()))
                goto end;

	if(cconf->protocol==PROTO_BURP2)
	{
		switch(maybe_restore_spool(asfd, manifest, sdirs, bu,
			srestore, regex, cconf, slist, act, cntr_status))
		{
			case 1: do_restore_stream=0; break;
			case 0: do_restore_stream=1; break;
			default: goto end; // Error;
		}
	}
	if(do_restore_stream && restore_stream(asfd, sdirs, slist,
		bu, manifest, regex,
		srestore, cconf, act, cntr_status))
			goto end;

	if(restore_remaining_dirs(asfd, bu, slist,
		act, sdirs, cntr_status, cconf)) goto end;

        // Restore has nearly completed OK.

        ret=restore_end(asfd, cconf);

	cntr_print(cconf->cntr, act);
	cntr_stats_to_file(cconf->cntr, bu->path, act, cconf);
end:
        slist_free(&slist);
	linkhash_free();
        return ret;
}

static int get_logpaths(struct bu *bu, const char *file,
	char **logpath, char **logpathz)
{
	if(!(*logpath=prepend_s(bu->path, file))
	  || !(*logpathz=prepend(*logpath, ".gz", strlen(".gz"), "")))
		return -1;
	return 0;
}

static int restore_manifest(struct asfd *asfd, struct bu *bu,
	regex_t *regex, int srestore, enum action act, struct sdirs *sdirs,
	char **dir_for_notify, struct conf *cconf)
{
	int ret=-1;
	char *manifest=NULL;
	char *logpath=NULL;
	char *logpathz=NULL;
	// For sending status information up to the server.
	enum cntr_status cntr_status=CNTR_STATUS_RESTORING;

	if(act==ACTION_RESTORE) cntr_status=CNTR_STATUS_RESTORING;
	else if(act==ACTION_VERIFY) cntr_status=CNTR_STATUS_VERIFYING;

	if((act==ACTION_RESTORE && get_logpaths(bu, "restorelog",
		&logpath, &logpathz))
	  || (act==ACTION_VERIFY && get_logpaths(bu, "verifylog",
		&logpath, &logpathz))
	  || !(manifest=prepend_s(bu->path,
		cconf->protocol==PROTO_BURP1?"manifest.gz":"manifest")))
	{
		log_and_send_oom(asfd, __func__);
		goto end;
	}

	if(set_logfp(logpath, cconf))
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg),
				"could not open log file: %s", logpath);
		log_and_send(asfd, msg);
		goto end;
	}

	*dir_for_notify=strdup_w(bu->path, __func__);

	log_restore_settings(cconf, srestore);

	// First, do a pass through the manifest to set up cntr.
	// This is the equivalent of a phase1 scan during backup.

	if(setup_cntr(asfd, manifest, regex, srestore, act, cntr_status, cconf))
		goto end;

	if(cconf->send_client_cntr && cntr_send(cconf->cntr))
		goto end;

	// Now, do the actual restore.
	ret=actual_restore(asfd, bu, manifest,
		  regex, srestore, act, sdirs, cntr_status, cconf);
end:
	set_logfp(NULL, cconf);
	compress_file(logpath, logpathz, cconf);
	if(manifest) free(manifest);
	if(logpath) free(logpath);
	if(logpathz) free(logpathz);
	return ret;
}

int do_restore_server(struct asfd *asfd, struct sdirs *sdirs,
	enum action act, int srestore,
	char **dir_for_notify, struct conf *conf)
{
	int ret=0;
	uint8_t found=0;
	struct bu *bu=NULL;
	struct bu *bu_list=NULL;
	unsigned long bno=0;
	regex_t *regex=NULL;

	logp("in do_restore\n");

	if(compile_regex(&regex, conf->regex)) return -1;

	if(bu_get_list(sdirs, &bu_list))
	{
		if(regex) { regfree(regex); free(regex); }
		return -1;
	}

	if((!conf->backup
	 || !*(conf->backup)
	 || !(bno=strtoul(conf->backup, NULL, 10)))
		&& bu_list)
	{
		found=1;
		// No backup specified, do the most recent.
		for(bu=bu_list; bu && bu->next; bu=bu->next) { }
		ret=restore_manifest(asfd, bu, regex, srestore,
				act, sdirs, dir_for_notify, conf);
	}

	if(!found) for(bu=bu_list; bu; bu=bu->next)
	{
		if(!strcmp(bu->timestamp, conf->backup)
		  || bu->bno==bno)
		{
			found=1;
			//logp("got: %s\n", bu->path);
			ret|=restore_manifest(asfd, bu, regex, srestore,
				act, sdirs, dir_for_notify, conf);
			break;
		}
	}

	bu_list_free(&bu_list);

	if(!found)
	{
		logp("backup not found\n");
		asfd->write_str(asfd, CMD_ERROR, "backup not found");
		ret=-1;
	}
	if(regex)
	{
		regfree(regex);
		free(regex);
	}
	return ret;
}
