#include "include.h"
#include "../../cmd.h"

#include <netdb.h>
#include <librsync.h>
#include <dirent.h>

// Also used by restore.c.
// FIX THIS: This stuff is very similar to make_rev_delta, can maybe share
// some code.
int do_patch(struct asfd *asfd, const char *dst, const char *del,
	const char *upd, bool gzupd, int compression, struct conf **cconfs)
{
	FILE *dstp=NULL;
	FILE *delfp=NULL;
	gzFile delzp=NULL;
	gzFile updp=NULL;
	FILE *updfp=NULL;
	rs_result result=RS_IO_ERROR;

	//logp("patching...\n");

	if(!(dstp=open_file(dst, "rb"))) goto end;

	if(dpthl_is_compressed(compression, del))
		delzp=gzopen_file(del, "rb");
	else
		delfp=open_file(del, "rb");

	if(!delzp && !delfp) goto end;

	if(gzupd)
		updp=gzopen(upd, comp_level(cconfs));
	else
		updfp=fopen(upd, "wb");

	if(!updp && !updfp) goto end;

	result=rs_patch_gzfile(asfd,
		dstp, delfp, delzp, updfp, updp, NULL, get_cntr(cconfs[OPT_CNTR]));
end:
	close_fp(&dstp);
	gzclose_fp(&delzp);
	close_fp(&delfp);
	if(close_fp(&updfp))
	{
		logp("error closing %s in %s\n", upd, __func__);
		result=RS_IO_ERROR;
	}
	if(gzclose_fp(&updp))
	{
		logp("error gzclosing %s in %s\n", upd, __func__);
		result=RS_IO_ERROR;
	}
	return result;
}

static int make_rev_sig(const char *dst, const char *sig, const char *endfile,
	int compression, struct conf **confs)
{
	int ret=-1;
	FILE *dstfp=NULL;
	gzFile dstzp=NULL;
	FILE *sigp=NULL;
//logp("make rev sig: %s %s\n", dst, sig);

	if(dpthl_is_compressed(compression, dst))
		dstzp=gzopen_file(dst, "rb");
	else
		dstfp=open_file(dst, "rb");

	if((!dstzp && !dstfp)
	  || !(sigp=open_file(sig, "wb"))
	  || rs_sig_gzfile(NULL, dstfp, dstzp, sigp,
		get_librsync_block_len(endfile),
		RS_DEFAULT_STRONG_LEN, NULL, get_cntr(confs[OPT_CNTR]))!=RS_DONE)
			goto end;
	ret=0;
end:
//logp("end of make rev sig\n");
	gzclose_fp(&dstzp);
	close_fp(&dstfp);
	if(close_fp(&sigp))
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
	FILE *srcfp=NULL;
	FILE *delfp=NULL;
	FILE *sigp=NULL;
	gzFile srczp=NULL;
	gzFile delzp=NULL;
	rs_signature_t *sumset=NULL;

//logp("make rev delta: %s %s %s\n", src, sig, del);
	if(!(sigp=open_file(sig, "rb"))) goto end;

	if(rs_loadsig_file(sigp, &sumset, NULL)!=RS_DONE
	  || rs_build_hash_table(sumset)!=RS_DONE)
		goto end;

//logp("make rev deltb: %s %s %s\n", src, sig, del);

	if(dpthl_is_compressed(compression, src))
		srczp=gzopen_file(src, "rb");
	else
		srcfp=open_file(src, "rb");

	if(!srczp && !srcfp) goto end;

	if(get_int(cconfs[OPT_COMPRESSION]))
		delzp=gzopen_file(del, comp_level(cconfs));
	else
		delfp=open_file(del, "wb");
	if(!delzp && !delfp) goto end;

	if(rs_delta_gzfile(NULL, sumset, srcfp, srczp,
		delfp, delzp, NULL, get_cntr(cconfs[OPT_CNTR]))!=RS_DONE)
			goto end;
	ret=0;
end:
	if(sumset) rs_free_sumset(sumset);
	gzclose_fp(&srczp);
	close_fp(&srcfp);
	close_fp(&sigp);
	if(gzclose_fp(&delzp))
	{
		logp("error closing zp %s in %s\n", del, __func__);
		ret=-1;
	}
	if(close_fp(&delfp))
	{
		logp("error closing fp %s in %s\n", del, __func__);
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
		sb->protocol1->endfile.buf, sb->compression, cconfs))
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
	if(delpath) free(delpath);
	return ret;
}

static int inflate_oldfile(const char *opath, const char *infpath,
	struct stat *statp, struct conf **confs)
{
	int ret=0;

	if(!statp->st_size)
	{
		FILE *dest;
		// Empty file - cannot inflate.
		// just close the destination and we have duplicated a
		// zero length file.
		if(!(dest=open_file(infpath, "wb"))) goto end;
		logp("asked to inflate zero length file: %s\n", opath);
		if(close_fp(&dest))
			logp("error closing %s in %s\n", infpath, __func__);
	}
	else if(zlib_inflate(NULL, opath, infpath, confs))
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

	if(dpthl_is_compressed(compression, oldpath))
		return inflate_oldfile(oldpath, infpath, &statp, cconfs);

	// If it was not a compressed file, just hard link it.
	// It is possible that infpath already exists, if the server
	// was interrupted on a previous run just after this point.
	return do_link(oldpath, infpath, &statp, cconfs,
		1 /* allow overwrite of infpath */);
}

static int jiggle(struct sdirs *sdirs, struct fdirs *fdirs, struct sbuf *sb,
	int hardlinked_current, const char *deltabdir, const char *deltafdir,
	const char *sigpath, FILE **delfp, struct conf **cconfs)
{
	int ret=-1;
	struct stat statp;
	char *oldpath=NULL;
	char *newpath=NULL;
	char *finpath=NULL;
	char *deltafpath=NULL;
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
		// Looks like an interrupted jiggle
		// did this file already.
		static int donemsg=0;
		if(!lstat(deltafpath, &statp) && S_ISREG(statp.st_mode))
		{
			logp("deleting unneeded forward delta: %s\n",
				deltafpath);
			unlink(deltafpath);
		}
		if(!donemsg)
		{
			logp("skipping already present file: %s\n", finpath);
			logp("to save log space, skips of other already present files will not be logged\n");
			donemsg++;
		}
	}
	else if(mkpath(&finpath, fdirs->datadir))
	{
		logp("could not create path for: %s\n", finpath);
		goto end;
	}
	else if(mkpath(&newpath, fdirs->datadirtmp))
	{
		logp("could not create path for: %s\n", newpath);
		goto end;
	}
	else if(!lstat(deltafpath, &statp) && S_ISREG(statp.st_mode))
	{
		int lrs;
		char *infpath=NULL;

		// Got a forward patch to do.
		// First, need to gunzip the old file,
		// otherwise the librsync patch will take
		// forever, because it will be doing seeks
		// all over the place, and gzseeks are slow.
	  	if(!(infpath=prepend_s(deltafdir, "inflate")))
		{
			log_out_of_memory(__func__);
			goto end;
		}

		//logp("Fixing up: %s\n", datapth);
		if(inflate_or_link_oldfile(oldpath, infpath,
			sb->compression, cconfs))
		{
			logp("error when inflating old file: %s\n", oldpath);
			free(infpath);
			goto end;
		}

		if((lrs=do_patch(NULL, infpath, deltafpath, newpath,
			get_int(cconfs[OPT_COMPRESSION]),
			sb->compression /* from the manifest */, cconfs)))
		{
			logp("WARNING: librsync error when patching %s: %d\n",
				oldpath, lrs);
			cntr_add(get_cntr(cconfs[OPT_CNTR]), CMD_WARNING, 1);
			// Try to carry on with the rest of the backup
			// regardless.
			//ret=-1;
			// Remove anything that got written.
			unlink(newpath);
			unlink(infpath);
			free(infpath);

			// First, note that we want to remove this entry from
			// the manifest.
			if(!*delfp
			  && !(*delfp=open_file(fdirs->deletionsfile, "ab")))
			{
				// Could not mark this file as deleted. Fatal.
				goto end;
			}
			if(sbufl_to_manifest(sb, *delfp, NULL))
				goto end;
			if(fflush(*delfp))
			{
				logp("error fflushing deletions file in %s: %s\n", __func__, strerror(errno));
				goto end;
			}
	
			ret=0;
			goto end;
		}

		// Get rid of the inflated old file.
		unlink(infpath);
		free(infpath);

		// Need to generate a reverse diff, unless we are keeping a
		// hardlinked archive.
		if(!hardlinked_current)
		{
			if(gen_rev_delta(sigpath, deltabdir,
				oldpath, newpath, datapth, sb, cconfs))
					goto end;
		}

		// Power interruptions should be recoverable. If it happens
		// before this point, the data jiggle for this file has to be
		// done again.
		// Once finpath is in place, no more jiggle is required.

		// Use the fresh new file.
		// Rename race condition is of no consequence, because finpath
		// will just get recreated automatically.
		if(do_rename(newpath, finpath))
			goto end;

		// Remove the forward delta, as it is no longer needed. There
		// is a reverse diff and the finished finished file is in place.
		//logp("Deleting delta.forward...\n");
		unlink(deltafpath);

		// Remove the old file. If a power cut happens just before
		// this, the old file will hang around forever.
		// FIX THIS: maybe put in something to detect this.
		// ie, both a reverse delta and the old file exist.
		if(!hardlinked_current)
		{
			//logp("Deleting oldpath...\n");
			unlink(oldpath);
		}
	}
	else if(!lstat(newpath, &statp) && S_ISREG(statp.st_mode))
	{
		// Use the fresh new file.
		// This needs to happen after checking
		// for the forward delta, because the
		// patching stuff writes to newpath.

		// Rename race condition is of no consequence, because finpath
		// will just get recreated automatically.

		//logp("Using newly received file\n");
		if(do_rename(newpath, finpath))
			goto end;
	}
	else if(!lstat(oldpath, &statp) && S_ISREG(statp.st_mode))
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
	}
	else
	{
		logp("could not find: %s\n", oldpath);
		goto end;
	}

	ret=0;
end:
	free_w(&oldpath);
	free_w(&newpath);
	free_w(&finpath);
	free_w(&deltafpath);
	return ret;
}

/* If OPT_HARDLINKED_ARCHIVE set, hardlink everything.
   If unset and there is more than one 'keep' value, periodically hardlink,
   based on the first 'keep' value. This is so that we have more choice
   of backups to delete than just the oldest.
*/
static int need_hardlinked_archive(struct conf **cconfs, unsigned long bno)
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

	logp("First keep value: %d, backup: %lu (%lu-1=%lu)\n",
			kp, bno, bno, bno-1);

	ret=(bno-1)%kp;
	logp("New backup is %sa hardlinked_archive (%lu%%%d=%d)\n",
		ret?"not ":"", bno-1, kp, ret);

	return !ret;
}

static int maybe_delete_files_from_manifest(const char *manifesttmp,
	struct fdirs *fdirs, struct conf **cconfs)
{
	int ars=0;
	int ret=-1;
	int pcmp=0;
	FILE *dfp=NULL;
	gzFile nmzp=NULL;
	gzFile omzp=NULL;
	struct sbuf *db=NULL;
	struct sbuf *mb=NULL;
	struct stat statp;

	if(lstat(fdirs->deletionsfile, &statp)) // No deletions, no problem.
		return 0;
	logp("Performing deletions on manifest\n");

	if(!(manifesttmp=get_tmp_filename(fdirs->manifest)))
		goto end;

        if(!(dfp=open_file(fdirs->deletionsfile, "rb"))
	  || !(omzp=gzopen_file(fdirs->manifest, "rb"))
	  || !(nmzp=gzopen_file(manifesttmp, comp_level(cconfs)))
	  || !(db=sbuf_alloc(cconfs))
	  || !(mb=sbuf_alloc(cconfs)))
		goto end;

	while(omzp || dfp)
	{
		if(dfp && !db->path.buf
		  && (ars=sbufl_fill(db, NULL, dfp, NULL, get_cntr(cconfs[OPT_CNTR]))))
		{
			if(ars<0) goto end;
			// ars==1 means it ended ok.
			close_fp(&dfp);
		}
		if(omzp && !mb->path.buf
		  && (ars=sbufl_fill(mb, NULL, NULL, omzp, get_cntr(cconfs[OPT_CNTR]))))
		{
			if(ars<0) goto end;
			// ars==1 means it ended ok.
			gzclose_fp(&omzp);
		}

		if(mb->path.buf && !db->path.buf)
		{
			if(sbufl_to_manifest(mb, NULL, nmzp)) goto end;
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
			if(sbufl_to_manifest(mb, NULL, nmzp)) goto end;
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
	if(gzclose_fp(&nmzp))
	{
		logp("error closing %s in %s\n", manifesttmp, __func__);
		ret=-1;
	}
	
	close_fp(&dfp);
	gzclose_fp(&omzp);
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
	int hardlinked_current, struct conf **cconfs, unsigned long bno)
{
	int ret=-1;
	char *datapth=NULL;
	char *tmpman=NULL;
	struct stat statp;

	char *deltabdir=NULL;
	char *deltafdir=NULL;
	char *sigpath=NULL;
	gzFile zp=NULL;
	struct sbuf *sb=NULL;

	FILE *delfp=NULL;

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
	if(!(zp=gzopen_file(fdirs->manifest, "rb")))
		goto error;

	if(!(deltabdir=prepend_s(fdirs->currentdup, "deltas.reverse"))
	  || !(deltafdir=prepend_s(sdirs->finishing, "deltas.forward"))
	  || !(sigpath=prepend_s(fdirs->currentdup, "sig.tmp"))
	  || !(sb=sbuf_alloc(cconfs)))
	{
		log_out_of_memory(__func__);
		goto error;
	}

	mkdir(fdirs->datadir, 0777);

	while(1)
	{
		switch(sbufl_fill(sb,
			NULL, NULL, zp, get_cntr(cconfs[OPT_CNTR])))
		{
			case 0: break;
			case 1: goto end;
			default: goto error;
		}
		if(sb->protocol1->datapth.buf)
		{
			if(write_status(CNTR_STATUS_SHUFFLING,
				sb->protocol1->datapth.buf, cconfs)
			  || jiggle(sdirs, fdirs, sb, hardlinked_current,
				deltabdir, deltafdir,
				sigpath, &delfp, cconfs))
					goto error;
		}
		sbuf_free_content(sb);
	}

end:
	if(close_fp(&delfp))
	{
		logp("error closing %s in atomic_data_jiggle\n",
			fdirs->deletionsfile);
		goto error;
	}

	if(maybe_delete_files_from_manifest(tmpman, fdirs, cconfs))
		goto error;

	// Remove the temporary data directory, we have probably removed
	// useful files from it.
	sync(); // try to help CIFS
	recursive_delete(deltafdir, NULL, 0 /* do not del files */);

	ret=0;
error:
	gzclose_fp(&zp);
	close_fp(&delfp);
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
	ssize_t len=0;
	char realcurrent[256]="";
	unsigned long bno=0;
	int hardlinked_current=0;
	char tstmp[64]="";
	int previous_backup=0;
	struct fdirs *fdirs=NULL;

	if((len=readlink(sdirs->current, realcurrent, sizeof(realcurrent)-1))<0)
		len=0;
	realcurrent[len]='\0';

	if(!(fdirs=fdirs_alloc())
	  || fdirs_init(fdirs, sdirs, realcurrent))
		goto end;

	if(set_logfp(fdirs->logpath, cconfs))
		goto end;

	logp("Begin phase4 (shuffle files)\n");

	if(write_status(CNTR_STATUS_SHUFFLING, NULL, cconfs))
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
				if(recursive_delete(fdirs->currentduptmp,
					NULL, 1 /* del files */))
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
	bno=strtoul(tstmp, NULL, 10);

	// Determine whether the new backup should be a hardlinked
	// archive or not, from the confs and the backup number...
	if(need_hardlinked_archive(cconfs, bno))
	{
		// Create a file to indicate that the previous backup
		// does not have others depending on it.
		FILE *hfp=NULL;
		if(!(hfp=open_file(fdirs->hlinked, "wb"))) goto end;

		// Stick the next backup timestamp in it. It might
		// be useful one day when wondering when the next
		// backup, now deleted, was made.
		fprintf(hfp, "%s\n", tstmp);
		if(close_fp(&hfp))
		{
			logp("error closing hardlinked indication\n");
			goto end;
		}
	}
	else
		unlink(fdirs->hlinked);

	if(atomic_data_jiggle(sdirs, fdirs, hardlinked_current, cconfs, bno))
	{
		logp("could not finish up backup.\n");
		goto end;
	}

	if(write_status(CNTR_STATUS_SHUFFLING,
		"deleting temporary files", cconfs))
			goto end;

	// Remove the temporary data directory, we have now removed
	// everything useful from it.
	recursive_delete(fdirs->datadirtmp, NULL, 1 /* del files */);

	// Clean up the currentdata directory - this is now the 'old'
	// currentdata directory. Any files that were deleted from
	// the client will be left in there, so call recursive_delete
	// with the option that makes it not delete files.
	// This will have the effect of getting rid of unnecessary
	// directories.
	sync(); // try to help CIFS
	recursive_delete(fdirs->currentdupdata, NULL, 0 /* do not del files */);

	// Rename the old current to something that we know to delete.
	if(previous_backup && !hardlinked_current)
	{
		if(deleteme_move(sdirs->client,
			fdirs->fullrealcurrent, realcurrent, cconfs)
		// I have tested that potential race conditions on the
		// rename() are automatically recoverable here.
		  || do_rename(fdirs->currentdup, fdirs->fullrealcurrent))
			goto end;
	}

	if(deleteme_maybe_delete(cconfs, sdirs->client))
		goto end;

	logp("End phase4 (shuffle files)\n");

	ret=0;
end:
	fdirs_free(fdirs);
	return ret;
}
