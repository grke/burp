#include "include.h"

#include <netdb.h>
#include <librsync.h>
#include <dirent.h>

static int make_rev_sig(const char *dst, const char *sig, const char *endfile, int compression, struct conf *conf)
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
	  || rs_sig_gzfile(dstfp, dstzp, sigp,
		get_librsync_block_len(endfile),
		RS_DEFAULT_STRONG_LEN, NULL, conf->cntr)!=RS_DONE)
			goto end;
	ret=0;
end:
//logp("end of make rev sig\n");
	gzclose_fp(&dstzp);
	close_fp(&dstfp);
	if(close_fp(&sigp))
	{
		logp("error closing %s in %s\n", sig, __FUNCTION__);
		return -1;
	}
	return ret;
}

static int make_rev_delta(const char *src, const char *sig, const char *del, int compression, struct conf *cconf)
{
	int ret=-1;
	FILE *srcfp=NULL;
	FILE *delfp=NULL;
	FILE *sigp=NULL;
	gzFile srczp=NULL;
	gzFile delzp=NULL;
	rs_signature_t *sumset=NULL;

//logp("make rev delta: %s %s %s\n", src, sig, del);
	if(!(sigp=open_file(sig, "rb"))) return -1;
	if(rs_loadsig_file(sigp, &sumset, NULL)!=RS_DONE
	  || rs_build_hash_table(sumset)!=RS_DONE)
		goto end;

//logp("make rev deltb: %s %s %s\n", src, sig, del);

	if(dpthl_is_compressed(compression, src))
		srczp=gzopen_file(src, "rb");
	else
		srcfp=open_file(src, "rb");

	if(!srczp && !srcfp) goto end;

	if(cconf->compression)
		delzp=gzopen_file(del, comp_level(cconf));
	else
		delfp=open_file(del, "wb");
	if(!delzp && !delfp) goto end;

	if(rs_delta_gzfile(sumset, srcfp, srczp,
		delfp, delzp, NULL, cconf->cntr)!=RS_DONE)
			goto end;
	ret=0;
end:
	if(sumset) rs_free_sumset(sumset);
	gzclose_fp(&srczp);
	close_fp(&srcfp);
	close_fp(&sigp);
	if(gzclose_fp(&delzp))
	{
		logp("error closing zp %s in %s\n", del, __FUNCTION__);
		ret=-1;
	}
	if(close_fp(&delfp))
	{
		logp("error closing fp %s in %s\n", del, __FUNCTION__);
		ret=-1;
	}
	return ret;
}


static int gen_rev_delta(const char *sigpath, const char *deltadir, const char *oldpath, const char *finpath, const char *path, struct sbuf *sb, struct conf *cconf)
{
	int ret=-1;
	char *delpath=NULL;
	if(!(delpath=prepend_s(deltadir, path)))
	{
		log_out_of_memory(__FUNCTION__);
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
		sb->burp1->endfile.buf, sb->compression, cconf))
	{
		logp("could not make signature from: %s\n", finpath);
		goto end;
	}
	else if(make_rev_delta(oldpath, sigpath,
		delpath, sb->compression, cconf))
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
	struct stat *statp)
{
	int zret;
	int ret=-1;
	FILE *dest=NULL;
	FILE *source=NULL;

	if(!(dest=open_file(infpath, "wb"))) goto end;

	if(!statp->st_size)
	{
		// Empty file - cannot inflate.
		// just close the destination and we have duplicated a
		// zero length file.
		logp("asked to inflate zero length file: %s\n", opath);
		return 0;
	}
	if(!(source=open_file(opath, "rb"))) goto end;
	if((zret=zlib_inflate(source, dest))!=Z_OK)
	{
		logp("zlib_inflate returned: %d\n", zret);
		goto end;
	}
	ret=0;
end:
	close_fp(&source);
	if(close_fp(&dest))
		logp("error closing %s in %s\n", infpath, __FUNCTION__);
	return ret;
}

static int inflate_or_link_oldfile(const char *oldpath, const char *infpath,
	int compression, struct conf *cconf)
{
	struct stat statp;
	const char *opath=oldpath;

	if(lstat(opath, &statp))
	{
		logp("could not lstat %s\n", opath);
		return -1;
	}

	if(dpthl_is_compressed(compression, opath))
		return inflate_oldfile(opath, infpath, &statp);

	// If it was not a compressed file, just hard link it.
	// It is possible that infpath already exists, if the server
	// was interrupted on a previous run just after this point.
	return do_link(opath, infpath, &statp, cconf,
		TRUE /* allow overwrite of infpath */);
}

static int jiggle(struct sbuf *sb, const char *currentdata, const char *datadirtmp, const char *datadir, const char *deltabdir, const char *deltafdir, const char *sigpath, const char *deletionsfile, FILE **delfp, int hardlinked, struct conf *cconf)
{
	int ret=-1;
	struct stat statp;
	char *oldpath=NULL;
	char *newpath=NULL;
	char *finpath=NULL;
	char *deltafpath=NULL;
	const char *datapth=sb->burp1->datapth.buf;

	if(!(oldpath=prepend_s(currentdata, datapth))
	  || !(newpath=prepend_s(datadirtmp, datapth))
	  || !(finpath=prepend_s(datadir, datapth))
	  || !(deltafpath=prepend_s(deltafdir, datapth)))
	{
		log_out_of_memory(__FUNCTION__);
		goto end;
	}
	else if(!lstat(finpath, &statp) && S_ISREG(statp.st_mode))
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
	else if(mkpath(&finpath, datadir))
	{
		logp("could not create path for: %s\n", finpath);
		goto end;
	}
	else if(mkpath(&newpath, datadirtmp))
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
			log_out_of_memory(__FUNCTION__);
			goto end;
		}

		//logp("Fixing up: %s\n", datapth);
		if(inflate_or_link_oldfile(oldpath, infpath,
			sb->compression, cconf))
		{
			logp("error when inflating old file: %s\n", oldpath);
			free(infpath);
			goto end;
		}

		if((lrs=do_patch(infpath, deltafpath, newpath,
			cconf->compression,
			sb->compression /* from the manifest */, cconf)))
		{
			logp("WARNING: librsync error when patching %s: %d\n",
				oldpath, lrs);
			do_filecounter(cconf->cntr, CMD_WARNING, 1);
			// Try to carry on with the rest of the backup
			// regardless.
			//ret=-1;
			// Remove anything that got written.
			unlink(newpath);
			unlink(infpath);
			free(infpath);

			// First, note that we want to remove this entry from
			// the manifest.
			if(!*delfp && !(*delfp=open_file(deletionsfile, "ab")))
			{
				// Could not mark this file as deleted. Fatal.
				goto end;
			}
			if(sbufl_to_manifest(sb, *delfp, NULL))
				goto end;
			if(fflush(*delfp))
			{
				logp("error fflushing deletions file in jiggle: %s\n", strerror(errno));
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
		if(!hardlinked)
		{
			if(gen_rev_delta(sigpath, deltabdir,
				oldpath, newpath, datapth, sb, cconf))
					goto end;
		}

		// Power interruptions should be
		// recoverable. If it happens before
		// this point, the data jiggle for
		// this file has to be done again.
		// Once finpath is in place, no more
		// jiggle is required.

		// Use the fresh new file.
		if(do_rename(newpath, finpath))
			goto end;
		else
		{
			// Remove the forward delta, as it is
			// no longer needed. There is a
			// reverse diff and the finished
			// finished file is in place.
			//logp("Deleting delta.forward...\n");
			unlink(deltafpath);

			// Remove the old file. If a power
			// cut happens just before this,
			// the old file will hang around
			// forever.
			// TODO: Put in something to
			// detect this.
			// ie, both a reverse delta and the
			// old file exist.
			if(!hardlinked)
			{
				//logp("Deleting oldpath...\n");
				unlink(oldpath);
			}
		}
	}
	else if(!lstat(newpath, &statp) && S_ISREG(statp.st_mode))
	{
		// Use the fresh new file.
		// This needs to happen after checking
		// for the forward delta, because the
		// patching stuff writes to newpath.
		//logp("Using newly received file\n");
		if(do_rename(newpath, finpath))
			goto end;
	}
	else if(!lstat(oldpath, &statp) && S_ISREG(statp.st_mode))
	{
		// Use the old unchanged file.
		// Hard link it first.
		//logp("Hard linking to old file: %s\n", datapth);
		if(do_link(oldpath, finpath, &statp, cconf,
		  FALSE /* do not overwrite finpath (should never need to) */))
			goto end;
		else
		{
			// If we are not keeping a hardlinked
			// archive, delete the old link.
			if(!hardlinked)
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
	if(oldpath) free(oldpath);
	if(newpath) free(newpath);
	if(finpath) free(finpath);
	if(deltafpath) free(deltafpath);

	return ret;
}

/* If cconf->hardlinked_archive set, hardlink everything.
   If unset and there is more than one 'keep' value, periodically hardlink,
   based on the first 'keep' value. This is so that we have more choice
   of backups to delete than just the oldest.
*/
static int do_hardlinked_archive(struct conf *cconf, unsigned long bno)
{
	int kp=0;
	int ret=0;
	if(cconf->hardlinked_archive)
	{
		logp("need to hardlink archive\n");
		return 1;
	}
	if(!cconf->keep || !cconf->keep->next)
	{
		logp("do not need to hardlink archive\n");
		return 0;
	}

	// If they have specified more than one 'keep' value, need to
	// periodically hardlink, based on the first 'keep' value.
	kp=cconf->keep->flag;

	logp("first keep value: %d, backup: %lu (%lu-2=%lu)\n",
			kp, bno, bno, bno-2);

	ret=(bno-2)%kp;
	logp("%sneed to hardlink archive (%lu%%%d=%d)\n",
		ret?"do not ":"", bno-2, kp, ret);

	return !ret;
}

static int maybe_delete_files_from_manifest(const char *manifest, const char *deletionsfile, struct conf *cconf)
{
	int ars=0;
	int ret=-1;
	int pcmp=0;
	FILE *dfp=NULL;
	gzFile nmzp=NULL;
	gzFile omzp=NULL;
	struct sbuf *db=NULL;
	struct sbuf *mb=NULL;
	char *manifesttmp=NULL;
	struct stat statp;

	if(lstat(deletionsfile, &statp)) // No deletions, no problem.
		return 0;
	logp("Performing deletions on manifest\n");

	if(!(manifesttmp=get_tmp_filename(manifest)))
		goto end;

        if(!(dfp=open_file(deletionsfile, "rb"))
	  || !(omzp=gzopen_file(manifest, "rb"))
	  || !(nmzp=gzopen_file(manifesttmp, comp_level(cconf)))
	  || !(db=sbuf_alloc(cconf))
	  || !(mb=sbuf_alloc(cconf)))
		goto end;

	while(omzp || dfp)
	{
		if(dfp && !db->path.buf
		  && (ars=sbufl_fill(dfp, NULL, db, cconf->cntr)))
		{
			if(ars<0) goto end;
			// ars==1 means it ended ok.
			close_fp(&dfp);
		}
		if(omzp && !mb->path.buf
		  && (ars=sbufl_fill(NULL, omzp, mb, cconf->cntr)))
		{
			if(ars<0) goto end;
			// ars==1 means it ended ok.
			gzclose_fp(&omzp);
		}

		if(mb->path.buf && !db->path.buf)
		{
			if(sbufl_to_manifest(mb, NULL, nmzp)) goto end;
			sbuf_free_contents(mb);
		}
		else if(!mb->path.buf && db->path.buf)
		{
			sbuf_free_contents(db);
		}
		else if(!mb->path.buf && !db->path.buf) 
		{
			continue;
		}
		else if(!(pcmp=sbuf_pathcmp(mb, db)))
		{
			// They were the same - do not write.
			sbuf_free_contents(mb);
			sbuf_free_contents(db);
		}
		else if(pcmp<0)
		{
			// Behind in manifest. Write.
			if(sbufl_to_manifest(mb, NULL, nmzp)) goto end;
			sbuf_free_contents(mb);
		}
		else
		{
			// Behind in deletions file. Do not write.
			sbuf_free_contents(db);
		}
	}

	ret=0;
end:
	if(gzclose_fp(&nmzp))
	{
		logp("error closing %s in maybe_delete_files_from_manifest\n",
			manifesttmp);
		ret=-1;
	}
	
	close_fp(&dfp);
	gzclose_fp(&omzp);
	sbuf_free(db);
	sbuf_free(mb);
	if(!ret)
	{
		unlink(deletionsfile);
		if(do_rename(manifesttmp, manifest))
		{
			free(manifesttmp);
			return -1;
		}
	}
	if(manifesttmp)
	{
		unlink(manifesttmp);
		free(manifesttmp);
	}
	return ret;
}

/* Need to make all the stuff that this does atomic so that existing backups
   never get broken, even if somebody turns the power off on the server. */ 
static int atomic_data_jiggle(struct sdirs *sdirs, struct conf *cconf,
	const char *manifest, const char *currentdup, const char *currentdata,
	const char *datadir, const char *datadirtmp,
	const char *deletionsfile,
	int hardlinked, unsigned long bno)
{
	int ars=0;
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

	if(!(tmpman=get_tmp_filename(manifest)))
		goto end;
	if(lstat(manifest, &statp))
	{
		// Manifest does not exist - maybe the server was killed before
		// it could be renamed.
		logp("%s did not exist - trying %s\n", manifest, tmpman);
		do_rename(tmpman, manifest);
	}
	free(tmpman);
	if(!(zp=gzopen_file(manifest, "rb")))
		goto end;

	if(!(deltabdir=prepend_s(currentdup, "deltas.reverse"))
	  || !(deltafdir=prepend_s(sdirs->finishing, "deltas.forward"))
	  || !(sigpath=prepend_s(currentdup, "sig.tmp"))
	  || !(sb=sbuf_alloc(cconf)))
	{
		log_out_of_memory(__FUNCTION__);
		goto end;
	}

	mkdir(datadir, 0777);

	while(!(ars=sbufl_fill(NULL, zp, sb, cconf->cntr)))
	{
		if(sb->burp1->datapth.buf)
		{
			write_status(STATUS_SHUFFLING,
				sb->burp1->datapth.buf, cconf);

			if((ret=jiggle(sb, currentdata, datadirtmp,
				datadir, deltabdir, deltafdir,
				sigpath, deletionsfile, &delfp,
				hardlinked, cconf)))
					goto end;
		}
		sbuf_free_contents(sb);
	}
	if(ars<0) goto end;

	if(close_fp(&delfp))
	{
		logp("error closing %s in atomic_data_jiggle\n", deletionsfile);
		goto end;
	}

	if(maybe_delete_files_from_manifest(manifest, deletionsfile, cconf))
		goto end;

	// Remove the temporary data directory, we have probably removed
	// useful files from it.
	sync(); // try to help CIFS
	recursive_delete(deltafdir, NULL, FALSE /* do not del files */);

end:
	if(zp) gzclose_fp(&zp);
	if(delfp) close_fp(&delfp);
	if(deltabdir) free(deltabdir);
	if(deltafdir) free(deltafdir);
	if(sigpath) free(sigpath);
	if(datapth) free(datapth);
	if(sb) sbuf_free(sb);
	return ret;
}

int backup_phase4_server(struct sdirs *sdirs, struct conf *cconf)
{
	int ret=-1;
	struct stat statp;
	char *manifest=NULL;
	char *deletionsfile=NULL;
	char *datadir=NULL;
	char *datadirtmp=NULL;
	char *currentdup=NULL;
	char *currentduptmp=NULL;
	char *currentdupdata=NULL;
	char *timestamp=NULL;
	char *fullrealcurrent=NULL;
	char *logpath=NULL;
	char *hlinkedpath=NULL;
	int len=0;
	char realcurrent[256]="";

	unsigned long bno=0;
	int hardlinked=0;
	char tstmp[64]="";
	int newdup=0;
	int previous_backup=0;

	if((len=readlink(sdirs->current, realcurrent, sizeof(realcurrent)-1))<0)
		len=0;
	realcurrent[len]='\0';

	if(!(datadir=prepend_s(sdirs->finishing, "data"))
	  || !(datadirtmp=prepend_s(sdirs->finishing, "data.tmp"))
	  || !(manifest=prepend_s(sdirs->finishing, "manifest.gz"))
	  || !(deletionsfile=prepend_s(sdirs->finishing, "deletions"))
	  || !(currentdup=prepend_s(sdirs->finishing, "currentdup"))
	  || !(currentduptmp=prepend_s(sdirs->finishing, "currentdup.tmp"))
	  || !(currentdupdata=prepend_s(currentdup, "data"))
	  || !(timestamp=prepend_s(sdirs->finishing, "timestamp"))
	  || !(fullrealcurrent=prepend_s(sdirs->client, realcurrent))
	  || !(logpath=prepend_s(sdirs->finishing, "log"))
	  || !(hlinkedpath=prepend_s(currentdup, "hardlinked")))
		goto end;

	if(set_logfp(logpath, cconf))
		goto end;

	logp("Begin phase4 (shuffle files)\n");

	write_status(STATUS_SHUFFLING, NULL, cconf);

	if(!lstat(sdirs->current, &statp)) // Had a previous backup
	{
		previous_backup++;

		if(lstat(currentdup, &statp))
		{
			// Have not duplicated the current backup yet.
			if(!lstat(currentduptmp, &statp))
			{
				logp("Removing previous currentduptmp directory: %s\n", currentduptmp);
				if(recursive_delete(currentduptmp,
					NULL, TRUE /* del files */))
				{
					logp("Could not delete %s\n",
						currentduptmp);
					goto end;
				}
			}
			logp("Duplicating current backup.\n");
			if(recursive_hardlink(sdirs->current, currentduptmp, cconf)
			  || do_rename(currentduptmp, currentdup))
				goto end;
			newdup++;
		}

		if(read_timestamp(timestamp, tstmp, sizeof(tstmp)))
		{
			logp("could not read timestamp file: %s\n", timestamp);
			goto end;
		}
		// Get the backup number.
		bno=strtoul(tstmp, NULL, 10);

		if(newdup)
		{
			// When we have just created currentdup, determine
			// hardlinked archive from the conf and the backup
			// number...
			hardlinked=do_hardlinked_archive(cconf, bno);
		}
		else
		{
			// ...if recovering, find out what currentdup started
			// out as.
			// Otherwise it is possible that things can be messed
			// up by somebody swapping between hardlinked and
			// not hardlinked at the same time as a resume happens.
			if(lstat(hlinkedpath, &statp))
			{
				logp("previous attempt started not hardlinked\n");
				hardlinked=0;
			}
			else
			{
				logp("previous attempt started hardlinked\n");
				hardlinked=1;
			}
		}

		if(hardlinked)
		{
			// Create a file to indicate that the previous backup
			// does not have others depending on it.
			FILE *hfp=NULL;
			if(!(hfp=open_file(hlinkedpath, "wb")))
				goto end;
			// Stick the next backup timestamp in it. It might
			// be useful one day when wondering when the next
			// backup, now deleted, was made.
			fprintf(hfp, "%s\n", tstmp);
			if(close_fp(&hfp))
			{
				logp("error closing hardlinked indication\n");
				goto end;
			}
			logp(" doing hardlinked archive\n");
			logp(" will not generate reverse deltas\n");
		}
		else
		{
			logp(" not doing hardlinked archive\n");
			logp(" will generate reverse deltas\n");
			unlink(hlinkedpath);
		}
	}

	if(atomic_data_jiggle(sdirs, cconf, manifest, currentdup,
		currentdupdata, datadir, datadirtmp, deletionsfile,
		hardlinked, bno))
	{
		logp("could not finish up backup.\n");
		goto end;
	}

	write_status(STATUS_SHUFFLING, "deleting temporary files", cconf);

	// Remove the temporary data directory, we have now removed
	// everything useful from it.
	recursive_delete(datadirtmp, NULL, TRUE /* del files */);

	// Clean up the currentdata directory - this is now the 'old'
	// currentdata directory. Any files that were deleted from
	// the client will be left in there, so call recursive_delete
	// with the option that makes it not delete files.
	// This will have the effect of getting rid of unnecessary
	// directories.
	sync(); // try to help CIFS
	recursive_delete(currentdupdata, NULL, FALSE /* do not del files */);

	// Rename the old current to something that we know to
	// delete.
	if(previous_backup)
	{
		if(deleteme_move(sdirs->client, fullrealcurrent, realcurrent, cconf)
		  || do_rename(currentdup, fullrealcurrent))
			goto end;
	}

	if(deleteme_maybe_delete(cconf, sdirs->client))
		goto end;

	print_stats_to_file(cconf, sdirs->finishing, ACTION_BACKUP);

	// Rename the finishing symlink so that it becomes the current symlink
	do_rename(sdirs->finishing, sdirs->current);

	print_filecounters(cconf, ACTION_BACKUP);
	logp("Backup completed.\n");
	logp("End phase4 (shuffle files)\n");
	set_logfp(NULL, cconf); // will close logfp.

	compress_filename(sdirs->current, "log", "log.gz", cconf);

	ret=0;
end:
	if(datadir) free(datadir);
	if(datadirtmp) free(datadirtmp);
	if(manifest) free(manifest);
	if(deletionsfile) free(deletionsfile);
	if(currentdup) free(currentdup);
	if(currentduptmp) free(currentduptmp);
	if(currentdupdata) free(currentdupdata);
	if(timestamp) free(timestamp);
	if(fullrealcurrent) free(fullrealcurrent);
	if(logpath) free(logpath);
	if(hlinkedpath) free(hlinkedpath);

	return ret;
}
