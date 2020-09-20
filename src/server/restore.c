#include "../burp.h"
#include "../alloc.h"
#include "../asfd.h"
#include "../async.h"
#include "../bu.h"
#include "../cmd.h"
#include "../cntr.h"
#include "../cstat.h"
#include "../handy.h"
#include "../hexmap.h"
#include "../linkhash.h"
#include "../lock.h"
#include "../log.h"
#include "../pathcmp.h"
#include "../prepend.h"
#include "../protocol2/blk.h"
#include "../regexp.h"
#include "../slist.h"
#include "../strlist.h"
#include "bu_get.h"
#include "child.h"
#include "compress.h"
#include "manio.h"
#include "protocol1/restore.h"
#include "protocol2/dpth.h"
#include "protocol2/rblk.h"
#include "protocol2/restore.h"
#include "../protocol2/rabin/rabin.h"
#include "rubble.h"
#include "sdirs.h"

static enum asl_ret restore_end_func(struct asfd *asfd,
	__attribute__ ((unused)) struct conf **confs,
	__attribute__ ((unused)) void *param)
{
	if(!strcmp(asfd->rbuf->buf, "restoreend ok"))
		return ASL_END_OK;
	// Old v2 clients send something slightly different.
	if(!strcmp(asfd->rbuf->buf, "restoreend_ok"))
		return ASL_END_OK;
	iobuf_log_unexpected(asfd->rbuf, __func__);
	return ASL_END_ERROR;
}

static int restore_end(struct asfd *asfd, struct conf **confs)
{
	if(asfd->write_str(asfd, CMD_GEN, "restoreend")) return -1;
	return asfd->simple_loop(asfd, confs, NULL, __func__, restore_end_func);
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
static int srestore_check(struct conf **confs, const char *path)
{
	struct strlist *l=get_strlist(confs[OPT_INCEXCDIR]);

	// If no includes specified, restore everything.
	if(!l) return 1;

	for(; l; l=l->next)
		if(srestore_matches(l, path))
			return 1;
	return 0;
}

static int restore_list_check(
	struct asfd *asfd,
	struct cntr *cntr,
	struct fzp *rl_fzp,
	struct iobuf *rl_iobuf,
	const char *path
)
{
	char *last=NULL;

	do {
		if(!rl_iobuf->buf)
		{
			switch(iobuf_fill_from_fzp(rl_iobuf, rl_fzp))
			{
				case 0: break; // OK, read something.
				case 1: return 0; // Finished, no match.
				default: return -1; // Error.
			}
		}

		if(last && pathcmp(rl_iobuf->buf, last)!=1)
		{
			logw(asfd, cntr,
				"Input file ordering problem: '%s' '%s'",
					last, rl_iobuf->buf);
		}

		switch(pathcmp(rl_iobuf->buf, path))
		{
			case 0: return 1; // Successful match.
			case 1: return 0; // Ahead in input, no match.
			default:
				// Behind, need to read more from input.
				free_w(&last);
				last=rl_iobuf->buf;
				rl_iobuf->buf=NULL;
		}
	} while (1);

	return 0;
}

static int want_to_restore(
	struct asfd *asfd,
	int srestore,
	struct fzp *input_fzp,
	struct iobuf *input_iobuf,
	struct sbuf *sb,
	regex_t *regex,
	enum action act,
	struct conf **cconfs
) {
	if(act==ACTION_RESTORE)
	{
		// Do not send VSS data to non-windows, or to windows client
		// that asked us not to send it.
		if(!get_int(cconfs[OPT_CLIENT_IS_WINDOWS])
		  || get_int(cconfs[OPT_VSS_RESTORE])!=VSS_RESTORE_ON)
		{
			if(sbuf_is_vssdata(sb))
				return 0;
			// Do not send VSS directory data to non-windows.
			if(S_ISDIR(sb->statp.st_mode)
			  && sbuf_is_filedata(sb)
			  && !sbuf_is_metadata(sb))
				return 0;
		}
	}
	return
	  (!input_fzp
		|| restore_list_check(asfd, get_cntr(cconfs),
			input_fzp, input_iobuf, sb->path.buf))
	  && (!srestore
		|| srestore_check(cconfs, sb->path.buf))
	  && (!regex
		|| regex_check(regex, sb->path.buf));
}

static int maybe_open_restore_list(
	struct conf **cconfs,
	struct fzp **rl_fzp,
	struct iobuf **rl_iobuf,
	struct sdirs *sdirs
) {
	if(!get_string(cconfs[OPT_RESTORE_LIST]))
		return 0;

	if(!(*rl_fzp=fzp_open(sdirs->restore_list, "rb"))
	  || !(*rl_iobuf=iobuf_alloc()))
		return -1;

	return 0;
}

static int setup_cntr(struct asfd *asfd, const char *manifest,
	regex_t *regex, int srestore, struct conf **cconfs, enum action act,
	struct bu *bu, struct sdirs *sdirs)
{
	int ars=0;
	int ret=-1;
	struct fzp *fzp=NULL;
	struct sbuf *sb=NULL;
	struct cntr *cntr=NULL;
	struct fzp *rl_fzp=NULL;
	struct iobuf *rl_iobuf=NULL;

	cntr=get_cntr(cconfs);
	if(!cntr) return 0;
	cntr->bno=(int)bu->bno;

// FIX THIS: this is only trying to work for protocol1.
	if(get_protocol(cconfs)!=PROTO_1) return 0;

	if(maybe_open_restore_list(cconfs, &rl_fzp, &rl_iobuf, sdirs))
		goto end;

	if(!(sb=sbuf_alloc(PROTO_1))) goto end;
	if(!(fzp=fzp_gzopen(manifest, "rb")))
	{
		log_and_send(asfd, "could not open manifest");
		goto end;
	}
	while(1)
	{
		if((ars=sbuf_fill_from_file(sb, fzp, NULL)))
		{
			if(ars<0) goto end;
			// ars==1 means end ok
			break;
		}
		else
		{
			if(want_to_restore(asfd, srestore,
				rl_fzp, rl_iobuf,
				sb, regex, act, cconfs))
			{
				cntr_add_phase1(cntr, sb->path.cmd, 0);
				if(sb->endfile.buf)
				  cntr_add_val(cntr,
					CMD_BYTES_ESTIMATED,
					strtoull(sb->endfile.buf,
						NULL, 10));
			}
		}
		sbuf_free_content(sb);
	}
	ret=0;
end:
	iobuf_free(&rl_iobuf);
	fzp_close(&rl_fzp);
	sbuf_free(&sb);
	fzp_close(&fzp);
	return ret;
}

static int restore_sbuf(struct asfd *asfd, struct sbuf *sb, struct bu *bu,
	enum action act, struct sdirs *sdirs, enum cntr_status cntr_status,
	struct conf **cconfs, struct sbuf *need_data, const char *manifest,
	struct slist *slist);

static void log_missing_block(struct asfd *asfd, struct cntr *cntr,
	struct blk *blk, struct sbuf *need_data)
{
	uint16_t datno=0;
	char *savepathstr;
	savepathstr=uint64_to_savepathstr_with_sig_uint(blk->savepath, &datno);
	logw(asfd, cntr, "%s: Missing block %s:%d\n",
		iobuf_to_printable(&need_data->path), savepathstr, datno);
}

// Used when restoring a hard link that we have not restored the destination
// for. Read through the manifest from the beginning and substitute the path
// and data to the new location.
static int hard_link_substitution(struct asfd *asfd,
	struct sbuf *sb, struct f_link *lp,
	struct bu *bu, enum action act, struct sdirs *sdirs,
	enum cntr_status cntr_status, struct conf **cconfs,
	const char *manifest, struct slist *slist)
{
	int ret=-1;
	struct sbuf *need_data=NULL;
	int last_ent_was_dir=0;
	struct sbuf *hb=NULL;
	struct manio *manio=NULL;
	struct blk *blk=NULL;
	int pcmp;
	enum protocol protocol=get_protocol(cconfs);
	struct cntr *cntr=get_cntr(cconfs);

	if(!(manio=manio_open(manifest, "rb", protocol))
	  || !(need_data=sbuf_alloc(protocol))
	  || !(hb=sbuf_alloc(protocol)))
		goto end;

	if(protocol==PROTO_2)
	{
		  if(!(blk=blk_alloc()))
			goto end;
	}

	while(1)
	{
		if(blk)
			blk->got_save_path=0;
		switch(manio_read_with_blk(manio,
			hb, need_data->path.buf?blk:NULL))
		{
			case 0: break; // Keep going.
			case 1: ret=0; goto end; // Finished OK.
			default: goto end; // Error;
		}

		if(protocol==PROTO_2)
		{
			if(hb->endfile.buf)
			{
				sbuf_free_content(hb);
				continue;
			}
			if(blk->got_save_path)
			{
				blk->got_save_path=0;
				if(rblk_retrieve_data(asfd, cntr,
					blk, sdirs->data))
				{
					log_missing_block(asfd, cntr,
						blk, need_data);
					continue;
				}
			}
			if(blk->data)
			{
				if(protocol2_extra_restore_stream_bits(asfd,
					blk, slist, act, need_data,
					last_ent_was_dir, cntr)) goto end;
				continue;
			}
			sbuf_free_content(need_data);
		}

		pcmp=pathcmp(lp->name, hb->path.buf);

		if(!pcmp && (sbuf_is_filedata(hb) || sbuf_is_vssdata(hb)))
		{
			// Copy the path from sb to hb.
			free_w(&hb->path.buf);
			if(!(hb->path.buf=strdup_w(sb->path.buf, __func__)))
				goto end;
			hb->path.len = sb->path.len;
			// Should now be able to restore the original data
			// to the new location.
			ret=restore_sbuf(asfd, hb, bu, act, sdirs,
			  cntr_status, cconfs, need_data, manifest, slist);
			// May still need to get protocol2 data.
			if(!ret && need_data->path.buf) continue;
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
	manio_close(&manio);
	return ret;
}

static int restore_sbuf(struct asfd *asfd, struct sbuf *sb, struct bu *bu,
	enum action act, struct sdirs *sdirs, enum cntr_status cntr_status,
	struct conf **cconfs, struct sbuf *need_data, const char *manifest,
	struct slist *slist)
{
	//printf("%s: %s\n", act==ACTION_RESTORE?"restore":"verify",
	//  iobuf_to_printable(&sb->path));
	if(timed_operation_status_only(cntr_status, sb->path.buf, cconfs))
		return -1;

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
				bu, act, sdirs,
				cntr_status, cconfs, manifest, slist);
			// FIX THIS: Would be nice to remember the new link
			// location so that further hard links would link to
			// it instead of doing the hard_link_substitution
			// business over again.
		}
	}

	if(get_protocol(cconfs)==PROTO_1)
	{
		return restore_sbuf_protocol1(asfd, sb, bu,
		  act, sdirs, cconfs);
	}
	else
	{
		return restore_sbuf_protocol2(asfd, sb,
		  act, get_cntr(cconfs), need_data);
	}
}

static int restore_ent(struct asfd *asfd,
	struct sbuf **sb,
	struct slist *slist,
	struct bu *bu,
	enum action act,
	struct sdirs *sdirs,
	enum cntr_status cntr_status,
	struct conf **cconfs,
	struct sbuf *need_data,
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
			  act, sdirs, cntr_status, cconfs, need_data, manifest,
			  slist))
				goto end;
			if(get_protocol(cconfs)==PROTO_2
			  && sbuf_is_filedata(xb)
			  && get_int(cconfs[OPT_CLIENT_IS_WINDOWS]))
			{
				// Windows directories need endfile to be sent.
				if(asfd->write(asfd, &xb->endfile))
					goto end;
			}
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
	if(S_ISDIR((*sb)->statp.st_mode)
	  // Hack for metadata for now - just do it straight away.
	  && !sbuf_is_metadata(*sb))
	{
		// Add to the head of the list instead of the tail.
		(*sb)->next=slist->head;
		slist->head=*sb;

		*last_ent_was_dir=1;

		// Allocate a new sb.
		if(!(*sb=sbuf_alloc(get_protocol(cconfs)))) goto end;
	}
	else
	{
		*last_ent_was_dir=0;
		if(restore_sbuf(asfd, *sb, bu,
		  act, sdirs, cntr_status, cconfs, need_data, manifest,
		  slist))
			goto end;
	}
	ret=0;
end:
	return ret;
}

static int restore_remaining_dirs(struct asfd *asfd, struct bu *bu,
	struct slist *slist, enum action act, struct sdirs *sdirs,
	struct conf **cconfs)
{
	int ret=-1;
	struct sbuf *sb;
	struct sbuf *need_data=NULL;
	if(!(need_data=sbuf_alloc(get_protocol(cconfs)))) goto end;
	// Restore any directories that are left in the list.
	for(sb=slist->head; sb; sb=sb->next)
	{
		if(get_protocol(cconfs)==PROTO_1)
		{
			if(restore_sbuf_protocol1(asfd, sb, bu, act,
				sdirs, cconfs))
					goto end;
		}
		else
		{
			if(restore_sbuf_protocol2(asfd, sb, act,
				get_cntr(cconfs), NULL))
					goto end;
			if(sbuf_is_filedata(sb)
			  && get_int(cconfs[OPT_CLIENT_IS_WINDOWS]))
			{
				// Windows directories need endfile to be sent.
				if(asfd->write(asfd, &sb->endfile))
					goto end;
			}
		}
	}
	ret=0;
end:
	sbuf_free(&need_data);
	return ret;
}

static int restore_stream(struct asfd *asfd, struct sdirs *sdirs,
	struct slist *slist, struct bu *bu, const char *manifest,
	regex_t *regex, int srestore, struct conf **cconfs, enum action act,
	enum cntr_status cntr_status)
{
	int ret=-1;
	int last_ent_was_dir=0;
	int last_ent_was_skipped=0;
	struct sbuf *sb=NULL;
	struct iobuf *rbuf=asfd->rbuf;
	struct manio *manio=NULL;
	struct blk *blk=NULL;
	struct sbuf *need_data=NULL;
	enum protocol protocol=get_protocol(cconfs);
	struct cntr *cntr=get_cntr(cconfs);
	struct iobuf interrupt;
	struct fzp *rl_fzp=NULL;
	struct iobuf *rl_iobuf=NULL;

	iobuf_init(&interrupt);

	if(protocol==PROTO_2)
	{
		static int rs_sent=0;
		if(!(blk=blk_alloc()))
			goto end;
		if(!rs_sent)
		{
			rs_sent=1;
			if(asfd->write_str(asfd,
				CMD_GEN, "restore_stream")
			  || asfd_read_expect(asfd,
				CMD_GEN, "restore_stream_ok"))
					goto end;
		}
	}

	if(maybe_open_restore_list(cconfs, &rl_fzp, &rl_iobuf, sdirs))
		goto end;

	if(!(manio=manio_open(manifest, "rb", protocol))
	  || !(need_data=sbuf_alloc(protocol))
	  || !(sb=sbuf_alloc(protocol)))
		goto end;

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
			case CMD_MESSAGE:
			case CMD_WARNING:
			{
				log_recvd(rbuf, cntr, 0);
				continue;
			}
			case CMD_INTERRUPT:
				if(protocol==PROTO_2)
				{
					iobuf_free_content(&interrupt);
					iobuf_move(&interrupt, rbuf);
				}
				// PROTO_1:
				// Client wanted to interrupt the
				// sending of a file. But if we are
				// here, we have already moved on.
				// Ignore.
				continue;
			default:
				iobuf_log_unexpected(rbuf, __func__);
				goto end;
		}

		if(blk)
			blk->got_save_path=0;
		switch(manio_read_with_blk(manio,
			sb, need_data->path.buf?blk:NULL))
		{
			case 0: break; // Keep going.
			case 1: ret=0; goto end; // Finished OK.
			default: goto end; // Error;
		}

		if(protocol==PROTO_2)
		{
			if(sb->endfile.buf)
			{
				if(act==ACTION_RESTORE && !last_ent_was_skipped)
				{
					if(last_ent_was_dir)
					{
						// Delay sending endfile until
						// we actually send the
						// directory.
						struct sbuf *xb=slist->head;
						iobuf_free_content(&xb->endfile);
						iobuf_move(&xb->endfile,
							&sb->endfile);
					}
					else
					{
						if(asfd->write(asfd,
							&sb->endfile))
								goto end;
					}
				}
				sbuf_free_content(sb);
				iobuf_free_content(&interrupt);
				continue;
			}
			if(interrupt.buf)
			{
				if(!need_data->path.buf)
				{
					iobuf_free_content(&interrupt);
				}
				else if(!iobuf_pathcmp(&need_data->path,
					&interrupt))
				{
					continue;
				}
			}
			if(blk->got_save_path)
			{
				blk->got_save_path=0;
				if(rblk_retrieve_data(asfd, cntr,
					blk, sdirs->data))
				{
					log_missing_block(asfd, cntr,
						blk, need_data);
					continue;
				}
			}
			if(blk->data)
			{
				if(protocol2_extra_restore_stream_bits(asfd,
					blk, slist, act, need_data,
					last_ent_was_dir, cntr)) goto end;
				continue;
			}
			sbuf_free_content(need_data);
		}

		if(want_to_restore(asfd, srestore, rl_fzp, rl_iobuf,
			sb, regex, act, cconfs))
		{
			last_ent_was_skipped=0;
			if(restore_ent(asfd, &sb, slist,
				bu, act, sdirs, cntr_status, cconfs,
				need_data, &last_ent_was_dir, manifest))
					goto end;
		}
		else
		{
			last_ent_was_skipped=1;
			if(sbuf_is_filedata(sb) || sbuf_is_vssdata(sb))
			{
				// Add it to the list of filedata that was not
				// restored.
				struct f_link **bucket=NULL;
				if(!linkhash_search(&sb->statp, &bucket)
				  && linkhash_add(sb->path.buf, &sb->statp, bucket))
					goto end;
			}
		}

		sbuf_free_content(sb);
	}
end:
	iobuf_free(&rl_iobuf);
	fzp_close(&rl_fzp);
	blk_free(&blk);
	sbuf_free(&sb);
	sbuf_free(&need_data);
	iobuf_free_content(rbuf);
	iobuf_free_content(&interrupt);
	manio_close(&manio);
	return ret;
}

static int actual_restore(struct asfd *asfd, struct bu *bu,
	const char *manifest, regex_t *regex, int srestore, enum action act,
	struct sdirs *sdirs, enum cntr_status cntr_status, struct conf **cconfs)
{
	int ret=-1;
	// For out-of-sequence directory restoring so that the
	// timestamps come out right:
	struct slist *slist=NULL;
	struct cntr *cntr=NULL;

	if(linkhash_init()
	  || !(slist=slist_alloc()))
		goto end;

	if(get_protocol(cconfs)==PROTO_2)
		rblks_init(get_uint64_t(cconfs[OPT_RBLK_MEMORY_MAX]));

	if(restore_stream(asfd, sdirs, slist,
		bu, manifest, regex,
		srestore, cconfs, act, cntr_status))
			goto end;

	if(restore_remaining_dirs(asfd, bu, slist,
		act, sdirs, cconfs)) goto end;

	if(cconfs) cntr=get_cntr(cconfs);
	cntr_set_bytes(cntr, asfd);
	cntr_print(cntr, act);
	if(cntr_stats_to_file(cntr, bu->path, act))
		goto end;
	ret=0;
end:
	slist_free(&slist);
	linkhash_free();
	rblks_free();
	return ret;
}

static int get_logpaths(struct bu *bu, const char *file,
	char **logpath, char **logpathz)
{
	if(!(*logpath=prepend_s(bu->path, file))
	  || !(*logpathz=prepend(*logpath, ".gz")))
		return -1;
	return 0;
}

static void parallelism_warnings(struct asfd *asfd, struct conf **cconfs,
	struct sdirs *sdirs, struct bu *bu, enum protocol protocol)
{
	struct bu *b;

	if(lock_test(sdirs->lock_storage_for_write->path))
	{
		logm(asfd, cconfs, "Another process is currently backing up or deleting for this client.\n");
		return;
	}

	if(!check_for_rubble(sdirs))
		return;

	for(b=bu; b && b->next; b=b->next)
	{
		if(b->flags & BU_CURRENT)
			break; // Warning.
		if(protocol==PROTO_2)
			return; // No warning.
		if(b->flags & BU_HARDLINKED)
			return; // No warning.
	}

	logw(asfd, get_cntr(cconfs),
		"The latest backup needs recovery, but continuing anyway.\n");
}

static int restore_manifest(struct asfd *asfd, struct bu *bu,
	regex_t *regex, int srestore, enum action act, struct sdirs *sdirs,
	char **dir_for_notify, struct conf **cconfs)
{
	int ret=-1;
	char *manifest=NULL;
	char *logpath=NULL;
	char *logpathz=NULL;
	enum protocol protocol;
	enum cntr_status cntr_status;
	struct lock *lock=NULL;
	char *lockfile=NULL;
	static int manifest_count=0;

	protocol=get_protocol(cconfs);
	if(protocol==PROTO_2
	  && blks_generate_init())
		goto end;

	if(!(lockfile=prepend_s(bu->path, "lockfile.read"))
	  || !(lock=lock_alloc_and_init(lockfile)))
		goto end;
	lock_get(lock);
	if(lock->status!=GET_LOCK_GOT)
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg), "Another process is restoring or verifying backup %s.\n", bu->timestamp);
		log_and_send(asfd, msg);
		goto end;
	}

	// For sending status information up to the server.
	cntr_status=CNTR_STATUS_RESTORING;

	if(act==ACTION_RESTORE) cntr_status=CNTR_STATUS_RESTORING;
	else if(act==ACTION_VERIFY) cntr_status=CNTR_STATUS_VERIFYING;

	if((act==ACTION_RESTORE && get_logpaths(bu, "restorelog",
		&logpath, &logpathz))
	  || (act==ACTION_VERIFY && get_logpaths(bu, "verifylog",
		&logpath, &logpathz))
	  || !(manifest=prepend_s(bu->path,
		get_protocol(cconfs)==PROTO_1?
			"manifest.gz":"manifest")))
	{
		log_and_send_oom(asfd);
		goto end;
	}

	if(log_fzp_set(logpath, cconfs))
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg),
				"could not open log file: %s", logpath);
		log_and_send(asfd, msg);
		goto end;
	}

	*dir_for_notify=strdup_w(bu->path, __func__);

	log_restore_settings(cconfs, srestore);

	// First, do a pass through the manifest to set up cntr.
	// This is the equivalent of a phase1 scan during backup.

	if(setup_cntr(asfd, manifest,
		regex, srestore, cconfs, act, bu, sdirs))
			goto end;

	if(!manifest_count)
	{
		// FIX THIS: Only send the counters once, otherwise the
		// client will break on '-b a' because it does not expect
		// multiple sets of counters to turn up.
		// This means that the client side 'expected' counter will be
		// confusing in that case. Live with it for now.
		// However, the server side log will be OK.
		if(cntr_send_bu(asfd, bu, cconfs, cntr_status))
			goto end;
	}

	parallelism_warnings(asfd, cconfs, sdirs, bu, protocol);

	// Now, do the actual restore.
	ret=actual_restore(asfd, bu, manifest,
		  regex, srestore, act, sdirs, cntr_status, cconfs);
end:
	log_fzp_set(NULL, cconfs);
	if(logpath && logpathz)
		compress_file(logpath, logpathz,
			get_int(cconfs[OPT_COMPRESSION]));
	free_w(&manifest);
	free_w(&logpath);
	free_w(&logpathz);
	if(protocol==PROTO_2)
		blks_generate_free();
	free_w(&lockfile);
	lock_release(lock);
	lock_free(&lock);
	manifest_count++;
	return ret;
}

int do_restore_server(struct asfd *asfd, struct sdirs *sdirs,
	enum action act, int srestore,
	char **dir_for_notify, struct conf **confs)
{
	int ret=-1;
	uint8_t found=0;
	struct bu *bu=NULL;
	struct bu *bu_list=NULL;
	unsigned long bno=0;
	regex_t *regex=NULL;
	const char *regexstr=get_string(confs[OPT_REGEX]);
	const char *backup=get_string(confs[OPT_BACKUP]);
	int regex_case_insensitive=get_int(confs[OPT_REGEX_CASE_INSENSITIVE]);

	logp("in do_restore\n");

	if(regexstr
	  && *regexstr
	  && !(regex=regex_compile_restore(regexstr, regex_case_insensitive)))
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg), "unable to compile regex: %s\n",
			regexstr);
		log_and_send(asfd, msg);
		goto end;
	}

	if(bu_get_list(sdirs, &bu_list))
		goto end;

	if(bu_list &&
	   (!backup
	 || !*backup
	 || (!(bno=strtoul(backup, NULL, 10)) && *backup!='a')))
	{
		found=1;
		// No backup specified, do the most recent.
		for(bu=bu_list; bu && bu->next; bu=bu->next) { }
		ret=restore_manifest(asfd, bu, regex, srestore,
				act, sdirs, dir_for_notify, confs);
	}

	if(!found) for(bu=bu_list; bu; bu=bu->next)
	{
		if(!strcmp(bu->timestamp, backup)
		  || bu->bno==bno || (backup && *backup=='a'))
		{
			found=1;
			//logp("got: %s\n", bu->path);
			ret|=restore_manifest(asfd, bu, regex, srestore,
				act, sdirs, dir_for_notify, confs);
			if(backup && *backup=='a')
				continue;
			break;
		}
	}

	bu_list_free(&bu_list);


	if(found)
	{
		// Restore has nearly completed OK.
		ret=restore_end(asfd, confs);
	}
	else
	{
		logp("backup not found\n");
		asfd->write_str(asfd, CMD_ERROR, "backup not found");
		ret=-1;
	}
end:
	regex_free(&regex);
	return ret;
}
