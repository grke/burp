#include "../../burp.h"
#include "../../alloc.h"
#include "../../asfd.h"
#include "../../async.h"
#include "../../cmd.h"
#include "../../cntr.h"
#include "../../conf.h"
#include "../../cstat.h"
#include "../../fsops.h"
#include "../../fzp.h"
#include "../../handy.h"
#include "../../log.h"
#include "../../prepend.h"
#include "../../sbuf.h"
#include "../../strlist.h"
#include "../child.h"
#include "../compress.h"
#include "../timestamp.h"
#include "blocklen.h"
#include "deleteme.h"
#include "fdirs.h"
#include "link.h"
#include "zlibio.h"
#include "backup_phase4.h"

#include <librsync.h>

// Also used by restore.c.
// FIX THIS: This stuff is very similar to make_rev_delta, can maybe share
// some code.
int do_patch(const char *dst, const char *del,
	const char *upd, bool gzupd, int compression)
{
	struct fzp *dstp=NULL;
	struct fzp *delfzp=NULL;
	struct fzp *upfzp=NULL;
	rs_result result=RS_IO_ERROR;

	if(!(dstp=fzp_open(dst, "rb"))) goto end;

	if(!(delfzp=fzp_gzopen(del, "rb")))
		goto end;

	if(gzupd)
		upfzp=fzp_gzopen(upd, comp_level(compression));
	else
		upfzp=fzp_open(upd, "wb");

	if(!upfzp) goto end;

	if((result=rs_patch_gzfile(dstp, delfzp, upfzp))!=RS_DONE)
	{
		logp("rs_patch_gzfile returned %d %s\n",
			result, rs_strerror(result));
	}
end:
	fzp_close(&dstp);
	fzp_close(&delfzp);
	if(fzp_close(&upfzp))
	{
		logp("error closing %s in %s\n", upd, __func__);
		result=RS_IO_ERROR;
	}
	return result;
}

static int make_rev_sig(const char *dst, const char *sig, const char *endfile,
	int compression, struct conf **confs)
{
	int ret=-1;
	rs_result result;
	struct fzp *dstfzp=NULL;
	struct fzp *sigp=NULL;
//logp("make rev sig: %s %s\n", dst, sig);

	if(dpth_protocol1_is_compressed(compression, dst))
		dstfzp=fzp_gzopen(dst, "rb");
	else
		dstfzp=fzp_open(dst, "rb");

	if(!dstfzp
	  || !(sigp=fzp_open(sig, "wb")))
		goto end;
	
	if((result=rs_sig_gzfile(dstfzp, sigp,
		get_librsync_block_len(endfile),
		PROTO1_RS_STRONG_LEN, confs)!=RS_DONE))
	{
		logp("rs_sig_gzfile returned %d %s\n",
			result, rs_strerror(result));
		goto end;
	}
	ret=0;
end:
//logp("end of make rev sig\n");
	fzp_close(&dstfzp);
	if(fzp_close(&sigp))
	{
		logp("error closing %s in %s\n", sig, __func__);
		return -1;
	}
	return ret;
}

static int make_rev_delta(const char *src, const char *sig, const char *del,
	int compression, struct conf **cconfs)
{
	int ret=-1;
	rs_result result;
	struct fzp *srcfzp=NULL;
	struct fzp *delfzp=NULL;
	struct fzp *sigp=NULL;
	rs_signature_t *sumset=NULL;

//logp("make rev delta: %s %s %s\n", src, sig, del);
	if(!(sigp=fzp_open(sig, "rb"))) goto end;

	if((result=rs_loadsig_fzp(sigp, &sumset))!=RS_DONE)
	{
		logp("rs_loadsig_fzp returned %d %s\n",
			result, rs_strerror(result));
		goto end;
	}
	if((result=rs_build_hash_table(sumset))!=RS_DONE)
	{
		logp("rs_build_hash_table returned %d %s\n",
			result, rs_strerror(result));
		goto end;
	}

//logp("make rev deltb: %s %s %s\n", src, sig, del);

	if(dpth_protocol1_is_compressed(compression, src))
		srcfzp=fzp_gzopen(src, "rb");
	else
		srcfzp=fzp_open(src, "rb");

	if(!srcfzp) goto end;

	if(get_int(cconfs[OPT_COMPRESSION]))
		delfzp=fzp_gzopen(del,
			comp_level(get_int(cconfs[OPT_COMPRESSION])));
	else
		delfzp=fzp_open(del, "wb");
	if(!delfzp) goto end;

	if((result=rs_delta_gzfile(sumset, srcfzp, delfzp))!=RS_DONE)
	{
		logp("rs_delta_gzfile returned %d %s\n",
			result, rs_strerror(result));
		goto end;
	}
	ret=0;
end:
	if(sumset) rs_free_sumset(sumset);
	fzp_close(&srcfzp);
	fzp_close(&sigp);
	if(fzp_close(&delfzp))
	{
		logp("error closing delfzp %s in %s\n", del, __func__);
		ret=-1;
	}
	return ret;
}

static int gen_rev_delta(const char *sigpath, const char *deltadir,
	const char *oldpath, const char *finpath, const char *path,
	struct sbuf *sb, struct conf **cconfs)
{
	int ret=-1;
	char *delpath=NULL;
	if(!(delpath=prepend_s(deltadir, path)))
	{
		log_out_of_memory(__func__);
		goto end;
	}
	//logp("Generating reverse delta...\n");
/*
	logp("delpath: %s\n", delpath);
	logp("finpath: %s\n", finpath);
	logp("sigpath: %s\n", sigpath);
	logp("oldpath: %s\n", oldpath);
*/
	if(mkpath(&delpath, deltadir))
	{
		logp("could not mkpaths for: %s\n", delpath);
		goto end;
	}
	else if(make_rev_sig(finpath, sigpath,
		sb->endfile.buf, sb->compression, cconfs))
	{
		logp("could not make signature from: %s\n", finpath);
		goto end;
	}
	else if(make_rev_delta(oldpath, sigpath,
		delpath, sb->compression, cconfs))
	{
		logp("could not make delta from: %s\n", oldpath);
		goto end;
	}
	else unlink(sigpath);	

	ret=0;
end:
	free_w(&delpath);
	return ret;
}

static int inflate_oldfile(const char *opath, const char *infpath,
	struct stat *statp, struct cntr *cntr)
{
	int ret=0;

	if(!statp->st_size)
	{
		struct fzp *dest=NULL;
		// Empty file - cannot inflate.
		// just close the destination and we have duplicated a
		// zero length file.
		if(!(dest=fzp_open(infpath, "wb"))) goto end;
		logp("asked to inflate zero length file: %s\n", opath);
		if(fzp_close(&dest))
			logp("error closing %s in %s\n", infpath, __func__);
	}
	else if(zlib_inflate(NULL, opath, infpath, cntr))
	{
		logp("zlib_inflate returned error\n");
		ret=-1;
	}
end:
	return ret;
}

static int inflate_or_link_oldfile(const char *oldpath, const char *infpath,
	int compression, struct conf **cconfs)
{
	struct stat statp;

	if(lstat(oldpath, &statp))
	{
		logp("could not lstat %s\n", oldpath);
		return -1;
	}

	if(dpth_protocol1_is_compressed(compression, oldpath))
		return inflate_oldfile(oldpath, infpath, &statp,
			get_cntr(cconfs));

	// If it was not a compressed file, just hard link it.
	// It is possible that infpath already exists, if the server
	// was interrupted on a previous run just after this point.
	return do_link(oldpath, infpath, &statp, cconfs,
		1 /* allow overwrite of infpath */);
}

static int forward_patch_and_reverse_diff(
	struct fdirs *fdirs,
	struct fzp **delfp,
	const char *deltabdir,
	const char *deltafdir,
	const char *deltafpath,
	const char *sigpath,
	const char *oldpath,
	const char *newpath,
	const char *datapth,
	const char *finpath,
	int hardlinked_current,
	struct sbuf *sb,
	struct conf **cconfs
)
{
	int lrs;
	int ret=-1;
	char *infpath=NULL;

	// Got a forward patch to do.
	// First, need to gunzip the old file, otherwise the librsync patch
	// will take forever, because it will be doing seeks all over the
	// place, and gzseeks are slow.
	if(!(infpath=prepend_s(deltafdir, "inflate")))
	{
		log_out_of_memory(__func__);
		goto end;
	}

	//logp("Fixing up: %s\n", datapth);
	if(inflate_or_link_oldfile(oldpath, infpath, sb->compression, cconfs))
	{
		logp("error when inflating old file: %s\n", oldpath);
		goto end;
	}

	if((lrs=do_patch(infpath, deltafpath, newpath,
		sb->compression, sb->compression /* from manifest */)))
	{
		logp("WARNING: librsync error when patching %s: %d\n",
			oldpath, lrs);
		cntr_add(get_cntr(cconfs), CMD_WARNING, 1);
		// Try to carry on with the rest of the backup regardless.
		// Remove anything that got written.
		unlink(newpath);

		// First, note that we want to remove this entry from
		// the manifest.
		if(!*delfp
		  && !(*delfp=fzp_open(fdirs->deletionsfile, "ab")))
		{
			// Could not mark this file as deleted. Fatal.
			goto end;
		}
		if(sbuf_to_manifest(sb, *delfp))
			goto end;
		if(fzp_flush(*delfp))
		{
			logp("error fflushing deletions file in %s: %s\n",
				__func__, strerror(errno));
			goto end;
		}
		ret=0;
		goto end;
	}

	// Need to generate a reverse diff, unless we are keeping a hardlinked
	// archive.
	if(!hardlinked_current)
	{
		if(gen_rev_delta(sigpath, deltabdir,
			oldpath, newpath, datapth, sb, cconfs))
				goto end;
	}

	// Power interruptions should be recoverable. If it happens before this
	// point, the data jiggle for this file has to be done again.
	// Once finpath is in place, no more jiggle is required.

	// Use the fresh new file.
	// Rename race condition is of no consequence, because finpath will
	// just get recreated automatically.
	if(do_rename(newpath, finpath))
		goto end;

	// Remove the forward delta, as it is no longer needed. There is a
	// reverse diff and the finished finished file is in place.
	//logp("Deleting delta.forward...\n");
	unlink(deltafpath);

	// Remove the old file. If a power cut happens just before this, the
	// old file will hang around forever.
	// FIX THIS: maybe put in something to detect this.
	// ie, both a reverse delta and the old file exist.
	if(!hardlinked_current)
	{
		//logp("Deleting oldpath...\n");
		unlink(oldpath);
	}

	ret=0;
end:
	if(infpath)
	{
		unlink(infpath);
		free_w(&infpath);
	}
	return ret;
}

static int jiggle(struct sdirs *sdirs, struct fdirs *fdirs, struct sbuf *sb,
	int hardlinked_current, const char *deltabdir, const char *deltafdir,
	const char *sigpath, struct fzp **delfp, struct conf **cconfs)
{
	int ret=-1;
	struct stat statp;
	char *oldpath=NULL;
	char *newpath=NULL;
	char *finpath=NULL;
	char *deltafpath=NULL;
	char *relinkpath=NULL;
	const char *datapth=sb->protocol1->datapth.buf;

	// If the previous backup was a hardlinked_archive, there will not be
	// a currentdup directory - just directly use the file in the previous
	// backup.
	if(!(oldpath=prepend_s(hardlinked_current?
		sdirs->currentdata:fdirs->currentdupdata, datapth))
	  || !(newpath=prepend_s(fdirs->datadirtmp, datapth))
	  || !(finpath=prepend_s(fdirs->datadir, datapth))
	  || !(deltafpath=prepend_s(deltafdir, datapth)))
		goto end;

	if(!lstat(finpath, &statp) && S_ISREG(statp.st_mode))
	{
		// Looks like an interrupted jiggle did this file already.
		static int donemsg=0;
		if(!unlink(deltafpath))
			logp("deleted unneeded forward delta: %s\n",
				deltafpath);
		if(!donemsg)
		{
			logp("skipping already present file: %s\n", finpath);
			logp("to save log space, skips of other already present files will not be logged\n");
			donemsg++;
		}
		ret=0;
		goto end;
	}

	if(mkpath(&finpath, fdirs->datadir))
	{
		logp("could not create path for: %s\n", finpath);
		goto end;
	}

	if(!lstat(deltafpath, &statp) && S_ISREG(statp.st_mode))
	{
		if(mkpath(&newpath, fdirs->datadirtmp))
		{
			logp("could not create path for: %s\n", newpath);
			goto end;
		}
		ret=forward_patch_and_reverse_diff(
			fdirs,
			delfp,
			deltabdir,
			deltafdir,
			deltafpath,
			sigpath,
			oldpath,
			newpath,
			datapth,
			finpath,
			hardlinked_current,
			sb,
			cconfs
		);
		goto end;
	}

	if(!lstat(newpath, &statp) && S_ISREG(statp.st_mode))
	{
		// Use the fresh new file.
		// This needs to happen after checking
		// for the forward delta, because the
		// patching stuff writes to newpath.

		// Rename race condition is of no consequence, because finpath
		// will just get recreated automatically.

		//logp("Using newly received file\n");
		ret=do_rename(newpath, finpath);
		goto end;
	}

	if(!lstat(oldpath, &statp) && S_ISREG(statp.st_mode))
	{
		// Use the old unchanged file.
		// Hard link it first.
		//logp("Hard linking to old file: %s\n", datapth);
		if(do_link(oldpath, finpath, &statp, cconfs,
		  0 /* do not overwrite finpath (should never need to) */))
			goto end;
		else
		{
			// If we are not keeping a hardlinked
			// archive, delete the old link.
			if(!hardlinked_current)
			{
				//logp("Unlinking old file: %s\n", oldpath);
				unlink(oldpath);
			}
		}
		ret=0;
		goto end;
	}

	if(!(relinkpath=prepend_s(sdirs->relink, datapth)))
		goto end;
	if(!lstat(relinkpath, &statp) && S_ISREG(statp.st_mode))
	{
		// Use the relinked path - something that used to be a hardlink
		// but is now the original file because the file that we
		// originally hardlinked to has been deleted.
		ret=do_rename(relinkpath, finpath);
		goto end;
	}

	logp("could not find: %s\n", oldpath);
end:
	free_w(&oldpath);
	free_w(&newpath);
	free_w(&finpath);
	free_w(&deltafpath);
	free_w(&relinkpath);
	return ret;
}

/* If OPT_HARDLINKED_ARCHIVE set, hardlink everything.
   If unset and there is more than one 'keep' value, periodically hardlink,
   based on the first 'keep' value. This is so that we have more choice
   of backups to delete than just the oldest.
*/
static int need_hardlinked_archive(struct conf **cconfs, uint64_t bno)
{
	int kp=0;
	int ret=0;
	struct strlist *keep=get_strlist(cconfs[OPT_KEEP]);
	if(get_int(cconfs[OPT_HARDLINKED_ARCHIVE]))
	{
		logp("New backup is a hardlinked_archive\n");
		return 1;
	}
	if(!keep || !keep->next)
	{
		logp("New backup is not a hardlinked_archive\n");
		return 0;
	}

	// If they have specified more than one 'keep' value, need to
	// periodically hardlink, based on the first 'keep' value.
	kp=keep->flag;

	logp("First keep value: %d, backup: %" PRIu64 " (%" PRIu64 "-1=%" PRIu64 ")\n",
			kp, bno, bno, bno-1);

	ret=(bno-1)%kp;
	logp("New backup is %sa hardlinked_archive (%" PRIu64 "%%%d=%d)\n",
		ret?"not ":"", bno-1, kp, ret);

	return !ret;
}

static int maybe_delete_files_from_manifest(const char *manifesttmp,
	struct fdirs *fdirs, struct conf **cconfs)
{
	int ars=0;
	int ret=-1;
	int pcmp=0;
	struct fzp *dfp=NULL;
	struct fzp *nmzp=NULL;
	struct fzp *omzp=NULL;
	struct sbuf *db=NULL;
	struct sbuf *mb=NULL;
	struct stat statp;

	if(lstat(fdirs->deletionsfile, &statp)) // No deletions, no problem.
		return 0;
	logp("Performing deletions on manifest\n");

	if(!(manifesttmp=get_tmp_filename(fdirs->manifest)))
		goto end;

        if(!(dfp=fzp_open(fdirs->deletionsfile, "rb"))
	  || !(omzp=fzp_gzopen(fdirs->manifest, "rb"))
	  || !(nmzp=fzp_gzopen(manifesttmp,
		comp_level(get_int(cconfs[OPT_COMPRESSION]))))
	  || !(db=sbuf_alloc())
	  || !(mb=sbuf_alloc()))
		goto end;

	while(omzp || dfp)
	{
		if(dfp && !db->path.buf
		  && (ars=sbuf_fill_from_file(db, dfp)))
		{
			if(ars<0) goto end;
			// ars==1 means it ended ok.
			fzp_close(&dfp);
		}
		if(omzp && !mb->path.buf
		  && (ars=sbuf_fill_from_file(mb, omzp)))
		{
			if(ars<0) goto end;
			// ars==1 means it ended ok.
			fzp_close(&omzp);
		}

		if(mb->path.buf && !db->path.buf)
		{
			if(sbuf_to_manifest(mb, nmzp)) goto end;
			sbuf_free_content(mb);
		}
		else if(!mb->path.buf && db->path.buf)
		{
			sbuf_free_content(db);
		}
		else if(!mb->path.buf && !db->path.buf)
		{
			continue;
		}
		else if(!(pcmp=sbuf_pathcmp(mb, db)))
		{
			// They were the same - do not write.
			sbuf_free_content(mb);
			sbuf_free_content(db);
		}
		else if(pcmp<0)
		{
			// Behind in manifest. Write.
			if(sbuf_to_manifest(mb, nmzp)) goto end;
			sbuf_free_content(mb);
		}
		else
		{
			// Behind in deletions file. Do not write.
			sbuf_free_content(db);
		}
	}

	ret=0;
end:
	if(fzp_close(&nmzp))
	{
		logp("error closing %s in %s\n", manifesttmp, __func__);
		ret=-1;
	}
	
	fzp_close(&dfp);
	fzp_close(&omzp);
	sbuf_free(&db);
	sbuf_free(&mb);
	if(!ret)
	{
		unlink(fdirs->deletionsfile);
		// The rename race condition is not a problem here, as long
		// as manifesttmp is the same path as that generated in the
		// atomic data jiggle.
		if(do_rename(manifesttmp, fdirs->manifest))
			return -1;
	}
	if(manifesttmp) unlink(manifesttmp);
	return ret;
}

/* Need to make all the stuff that this does atomic so that existing backups
   never get broken, even if somebody turns the power off on the server. */
static int atomic_data_jiggle(struct sdirs *sdirs, struct fdirs *fdirs,
	int hardlinked_current, struct conf **cconfs)
{
	int ret=-1;
	char *datapth=NULL;
	char *tmpman=NULL;
	struct stat statp;

	char *deltabdir=NULL;
	char *deltafdir=NULL;
	char *sigpath=NULL;
	struct fzp *zp=NULL;
	struct sbuf *sb=NULL;

	struct fzp *delfp=NULL;

	logp("Doing the atomic data jiggle...\n");

	if(!(tmpman=get_tmp_filename(fdirs->manifest)))
		goto error;
	if(lstat(fdirs->manifest, &statp))
	{
		// Manifest does not exist - maybe the server was killed before
		// it could be renamed.
		logp("%s did not exist - trying %s\n", fdirs->manifest, tmpman);
		// Rename race condition is of no consequence, because manifest
		// already does not exist.
		do_rename(tmpman, fdirs->manifest);
	}
	if(!(zp=fzp_gzopen(fdirs->manifest, "rb")))
		goto error;

	if(!(deltabdir=prepend_s(fdirs->currentdup, "deltas.reverse"))
	  || !(deltafdir=prepend_s(sdirs->finishing, "deltas.forward"))
	  || !(sigpath=prepend_s(fdirs->currentdup, "sig.tmp"))
	  || !(sb=sbuf_alloc()))
	{
		log_out_of_memory(__func__);
		goto error;
	}

	mkdir(fdirs->datadir, 0777);

	while(1)
	{
		switch(sbuf_fill_from_file(sb, zp))
		{
			case 0: break;
			case 1: goto end;
			default: goto error;
		}
		if(sb->protocol1->datapth.buf)
		{
			if(timed_operation_status_only(CNTR_STATUS_SHUFFLING,
				sb->protocol1->datapth.buf, cconfs)
			  || jiggle(sdirs, fdirs, sb, hardlinked_current,
				deltabdir, deltafdir,
				sigpath, &delfp, cconfs))
					goto error;
		}
		sbuf_free_content(sb);
	}

end:
	if(fzp_close(&delfp))
	{
		logp("error closing %s in atomic_data_jiggle\n",
			fdirs->deletionsfile);
		goto error;
	}

	if(maybe_delete_files_from_manifest(tmpman, fdirs, cconfs))
		goto error;

	// Remove the temporary data directory, we have probably removed
	// useful files from it.
	recursive_delete_dirs_only(deltafdir);

	ret=0;
error:
	fzp_close(&zp);
	fzp_close(&delfp);
	sbuf_free(&sb);
	free_w(&deltabdir);
	free_w(&deltafdir);
	free_w(&sigpath);
	free_w(&datapth);
	free_w(&tmpman);
	return ret;
}

int backup_phase4_server_protocol1(struct sdirs *sdirs, struct conf **cconfs)
{
	int ret=-1;
	struct stat statp;
	char realcurrent[256]="";
	uint64_t bno=0;
	int hardlinked_current=0;
	char tstmp[64]="";
	int previous_backup=0;
	struct fdirs *fdirs=NULL;

	readlink_w(sdirs->current, realcurrent, sizeof(realcurrent));

	if(!(fdirs=fdirs_alloc())
	  || fdirs_init(fdirs, sdirs, realcurrent))
		goto end;

	if(log_fzp_set(fdirs->logpath, cconfs))
		goto end;

	logp("Begin phase4 (shuffle files)\n");

	if(timed_operation_status_only(CNTR_STATUS_SHUFFLING, NULL, cconfs))
		goto end;

	if(!lstat(sdirs->current, &statp)) // Had a previous backup.
	{
		previous_backup++;

		if(lstat(fdirs->hlinkedcurrent, &statp))
		{
			hardlinked_current=0;
			logp("Previous backup is not a hardlinked_archive\n");
			logp(" will generate reverse deltas\n");
		}
		else
		{
			hardlinked_current=1;
			logp("Previous backup is a hardlinked_archive\n");
			logp(" will not generate reverse deltas\n");
		}

		// If current was not a hardlinked_archive, need to duplicate
		// it.
		if(!hardlinked_current && lstat(fdirs->currentdup, &statp))
		{
			// Have not duplicated the current backup yet.
			if(!lstat(fdirs->currentduptmp, &statp))
			{
				logp("Removing previous directory: %s\n",
					fdirs->currentduptmp);
				if(recursive_delete(fdirs->currentduptmp))
				{
					logp("Could not delete %s\n",
						fdirs->currentduptmp);
					goto end;
				}
			}
			logp("Duplicating current backup.\n");
			if(recursive_hardlink(sdirs->current,
				fdirs->currentduptmp, cconfs)
			// The rename race condition is of no consequence here
			// because currentdup does not exist.
			  || do_rename(fdirs->currentduptmp, fdirs->currentdup))
				goto end;
		}
	}

	if(timestamp_read(fdirs->timestamp, tstmp, sizeof(tstmp)))
	{
		logp("could not read timestamp file: %s\n",
			fdirs->timestamp);
		goto end;
	}
	// Get the backup number.
	bno=strtoull(tstmp, NULL, 10);

	// Determine whether the new backup should be a hardlinked
	// archive or not, from the confs and the backup number...
	if(need_hardlinked_archive(cconfs, bno))
	{
		// Create a file to indicate that the previous backup
		// does not have others depending on it.
		struct fzp *hfp=NULL;
		if(!(hfp=fzp_open(fdirs->hlinked, "wb"))) goto end;

		// Stick the next backup timestamp in it. It might
		// be useful one day when wondering when the next
		// backup, now deleted, was made.
		fzp_printf(hfp, "%s\n", tstmp);
		if(fzp_close(&hfp))
		{
			logp("error closing hardlinked indication\n");
			goto end;
		}
	}
	else
		unlink(fdirs->hlinked);

	if(atomic_data_jiggle(sdirs, fdirs, hardlinked_current, cconfs))
	{
		logp("could not finish up backup.\n");
		goto end;
	}

	if(timed_operation_status_only(CNTR_STATUS_SHUFFLING,
		"deleting temporary files", cconfs))
			goto end;

	// Remove the temporary data directory, we have now removed
	// everything useful from it.
	recursive_delete(fdirs->datadirtmp);

	// Clean up the currentdata directory - this is now the 'old'
	// currentdata directory. Any files that were deleted from
	// the client will be left in there, so call recursive_delete
	// with the option that makes it not delete files.
	// This will have the effect of getting rid of unnecessary
	// directories.
	recursive_delete_dirs_only_no_warnings(fdirs->currentdupdata);
	recursive_delete_dirs_only_no_warnings(sdirs->relink);

	// Rename the old current to something that we know to delete.
	if(previous_backup && !hardlinked_current)
	{
		if(deleteme_move(sdirs,
			fdirs->fullrealcurrent, realcurrent)
		// I have tested that potential race conditions on the
		// rename() are automatically recoverable here.
		  || do_rename(fdirs->currentdup, fdirs->fullrealcurrent))
			goto end;
	}

	if(deleteme_maybe_delete(cconfs, sdirs))
		goto end;

	logp("End phase4 (shuffle files)\n");

	ret=0;
end:
	fdirs_free(&fdirs);
	return ret;
}
