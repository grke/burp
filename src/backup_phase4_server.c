#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "lock.h"
#include "rs_buf.h"
#include "handy.h"
#include "asyncio.h"
#include "zlibio.h"
#include "counter.h"
#include "dpth.h"
#include "sbuf.h"
#include "backup_phase4_server.h"
#include "current_backups_server.h"
#include "restore_server.h"

#include <netdb.h>
#include <librsync.h>

static int make_rev_sig(const char *dst, const char *sig, const char *endfile, struct cntr *cntr)
{
	FILE *dstfp=NULL;
	gzFile dstzp=NULL;
	FILE *sigp=NULL;
	rs_result result;
//logp("make rev sig: %s %s\n", dst, sig);

	if(dpth_is_compressed(dst))
		dstzp=gzopen_file(dst, "rb");
	else
		dstfp=open_file(dst, "rb");

	if((!dstzp && !dstfp)
	  || !(sigp=open_file(sig, "wb")))
	{
		gzclose_fp(&dstzp);
		close_fp(&dstfp);
		return -1;
	}
	result=rs_sig_gzfile(dstfp, dstzp, sigp,
		get_librsync_block_len(endfile),
		RS_DEFAULT_STRONG_LEN, NULL, cntr);
	gzclose_fp(&dstzp);
	close_fp(&dstfp);
	close_fp(&sigp);
//logp("end of make rev sig\n");
	return result;
}

static int make_rev_delta(const char *src, const char *sig, const char *del, struct cntr *cntr, struct config *cconf)
{
	gzFile srczp=NULL;
	FILE *srcfp=NULL;
	FILE *sigp=NULL;
	rs_result result;
	rs_signature_t *sumset=NULL;

//logp("make rev delta: %s %s %s\n", src, sig, del);
	if(!(sigp=open_file(sig, "rb"))) return -1;
	if((result=rs_loadsig_file(sigp, &sumset, NULL))
	  || (result=rs_build_hash_table(sumset)))
	{
		fclose(sigp);
		rs_free_sumset(sumset);
		return result;
	}
	fclose(sigp);

//logp("make rev deltb: %s %s %s\n", src, sig, del);

	if(dpth_is_compressed(src))
		srczp=gzopen_file(src, "rb");
	else
		srcfp=open_file(src, "rb");

	if(!srczp && !srcfp)
	{
		rs_free_sumset(sumset);
		return -1;
	}

	if(cconf->compression)
	{
		gzFile delzp=NULL;
		if(!(delzp=gzopen_file(del, comp_level(cconf))))
		{
			gzclose_fp(&srczp);
			close_fp(&srcfp);
			rs_free_sumset(sumset);
			return -1;
		}
		result=rs_delta_gzfile(sumset, srcfp, srczp, NULL, delzp, NULL, cntr);
		gzclose_fp(&delzp);
	}
	else
	{
		FILE *delfp=NULL;
		if(!(delfp=open_file(del, "wb")))
		{
			gzclose_fp(&srczp);
			close_fp(&srcfp);
			rs_free_sumset(sumset);
			return -1;
		}
		result=rs_delta_gzfile(sumset, srcfp, srczp, delfp, NULL, NULL, cntr);
		close_fp(&delfp);
	}

	rs_free_sumset(sumset);
	gzclose_fp(&srczp);
	close_fp(&srcfp);

	return result;
}


static int gen_rev_delta(const char *sigpath, const char *deltadir, const char *oldpath, const char *finpath, const char *path, const char *endfile, struct cntr *cntr, struct config *cconf)
{
	int ret=0;
	char *delpath=NULL;
	if(!(delpath=prepend_s(deltadir, path, strlen(path))))
	{
		logp("out of memory\n");
		ret=-1;
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
		ret=-1;
	}
	else if(make_rev_sig(finpath, sigpath, endfile, cntr))
	{
		logp("could not make signature from: %s\n", finpath);
		ret=-1;
	}
	else if(make_rev_delta(oldpath, sigpath, delpath, cntr, cconf))
	{
		logp("could not make delta from: %s\n", oldpath);
		ret=-1;
	}
	else unlink(sigpath);	
	if(delpath) free(delpath);
	return ret;
}

static int inflate_or_link_oldfile(const char *oldpath, const char *infpath, struct config *cconf)
{
	int ret=0;
	struct stat statp;

	if(lstat(oldpath, &statp))
	{
		logp("could not lstat %s\n", oldpath);
		return -1;
	}

	if(dpth_is_compressed(oldpath))
	{
		FILE *source=NULL;
		FILE *dest=NULL;

		//logp("inflating...\n");

		if(!(dest=open_file(infpath, "wb")))
		{
			close_fp(&dest);
			return -1;
		}

		if(!statp.st_size)
		{
			// Empty file - cannot inflate.
			// just close the destination and we have duplicated a
			// zero length file.
			logp("asked to inflate zero length file: %s\n", oldpath);
			close_fp(&dest);
			return 0;
		}
		if(!(source=open_file(oldpath, "rb")))
		{
			close_fp(&dest);
			return -1;
		}
		if((ret=zlib_inflate(source, dest))!=Z_OK)
		logp("zlib_inflate returned: %d\n", ret);
		close_fp(&source);
		close_fp(&dest);
	}
	else
	{
		// If it was not a compressed file, just hard link it.
		if(do_link(oldpath, infpath, &statp, cconf))
			ret=-1;
	
	}
	return ret;
}

static int jiggle(const char *datapth, const char *currentdata, const char *datadirtmp, const char *datadir, const char *deltabdir, const char *deltafdir, const char *sigpath, const char *endfile, int hardlinked, struct cntr *cntr, struct config *cconf)
{
	int ret=0;
	struct stat statp;
	char *oldpath=NULL;
	char *newpath=NULL;
	char *finpath=NULL;
	char *deltafpath=NULL;

	if(!(oldpath=prepend_s(currentdata, datapth, strlen(datapth)))
	  || !(newpath=prepend_s(datadirtmp, datapth, strlen(datapth)))
	  || !(finpath=prepend_s(datadir, datapth, strlen(datapth)))
	  || !(deltafpath=prepend_s(deltafdir, datapth, strlen(datapth))))
	{
		logp("out of memory\n");
		ret=-1;	
		goto cleanup;
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
		ret=-1;
		goto cleanup;
	}
	else if(mkpath(&newpath, datadirtmp))
	{
		logp("could not create path for: %s\n", newpath);
		ret=-1;
		goto cleanup;
	}
	else if(!lstat(deltafpath, &statp) && S_ISREG(statp.st_mode))
	{
		char *cp=NULL;
		char *infpath=NULL;

		// Got a forward patch to do.
		// First, need to gunzip the old file,
		// otherwise the librsync patch will take
		// forever, because it will be doing seeks
		// all over the place, and gzseeks are slow.

		if(!(infpath=strdup(deltafpath)))
		{
			logp("out of memory\n");
			ret=-1;
			goto cleanup;
		}
		else if(!(cp=strrchr(infpath, '.')))
		{
			logp("could not strip the suffix from '%s'\n", infpath);
			ret=-1;
			goto cleanup;
		}
		*cp='\0';

		//logp("Fixing up: %s\n", datapth);
		if(inflate_or_link_oldfile(oldpath, infpath, cconf))
		{
			logp("error when inflating old file: %s\n", oldpath);
			ret=-1;
			goto cleanup;
		}

		if(do_patch(infpath, deltafpath, newpath, cconf->compression,
			cntr, cconf))
		{
			logp("error when patching\n");
			ret=-1;
			// Remove anything that got written.
			unlink(newpath);
			goto cleanup;
		}

		// Get rid of the inflated old file.
		// This will also remove it if there was an
		// error.
		unlink(infpath);
		free(infpath);

		// Need to generate a reverse diff,
		// unless we are keeping a hardlinked
		// archive.
		if(!hardlinked)
		{
			if(gen_rev_delta(sigpath, deltabdir,
				oldpath, newpath, datapth, endfile,
				cntr, cconf))
			{
				ret=-1;
				goto cleanup;
			}
		}

		// Power interruptions should be
		// recoverable. If it happens before
		// this point, the data jiggle for
		// this file has to be done again.
		// Once finpath is in place, no more
		// jiggle is required.

		// Use the fresh new file.
		if(do_rename(newpath, finpath))
		{
			ret=-1;
			goto cleanup;
		}
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
		{
			ret=-1;
			goto cleanup;
		}
	}
	else if(!lstat(oldpath, &statp) && S_ISREG(statp.st_mode))
	{
		// Use the old unchanged file.
		// Hard link it first.
		//logp("Hard linking to old file: %s\n", datapth);
		if(do_link(oldpath, finpath, &statp, cconf))
		{
			ret=-1;
			goto cleanup;
		}
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
		ret=-1;
		goto cleanup;
	}

cleanup:
	if(oldpath) { free(oldpath); oldpath=NULL; }
	if(newpath) { free(newpath); newpath=NULL; }
	if(finpath) { free(finpath); finpath=NULL; }
	if(deltafpath) { free(deltafpath); deltafpath=NULL; }

	return ret;
}

/* If cconf->hardlinked_archive set, hardlink everything.
   If unset and there is more than one 'keep' value, periodically hardlink,
   based on the first 'keep' value. This is so that we have more choice
   of backups to delete than just the oldest.
*/
static int do_hardlinked_archive(struct config *cconf, unsigned long bno)
{
	int kp=0;
	int ret=0;
	if(cconf->hardlinked_archive)
	{
		logp("need to hardlink archive\n");
		return 1;
	}
	if(cconf->kpcount<=1)
	{
		logp("do not need to hardlink archive\n");
		return 0;
	}

	// If they have specified more than one 'keep' value, need to
	// periodically hardlink, based on the first 'keep' value.
	kp=cconf->keep[0]->flag;

	logp("first keep value: %d, backup: %lu (%lu-2=%lu)\n",
			kp, bno, bno, bno-2);

	ret=(bno-2)%kp;
	logp("%sneed to hardlink archive (%lu%%%d=%d)\n",
		ret?"do not ":"", bno-2, kp, ret);

	return !ret;
}

/* Need to make all the stuff that this does atomic so that existing backups
   never get broken, even if somebody turns the power off on the server. */ 
static int atomic_data_jiggle(const char *finishing, const char *working, const char *manifest, const char *current, const char *currentdata, const char *datadir, const char *datadirtmp, struct config *cconf, const char *client, int hardlinked, unsigned long bno, struct cntr *p1cntr, struct cntr *cntr)
{
	int ret=0;
	int ars=0;
	char *datapth=NULL;
	char *tmpman=NULL;
	struct stat statp;

	char *deltabdir=NULL;
	char *deltafdir=NULL;
	char *sigpath=NULL;
	gzFile zp=NULL;
	struct sbuf sb;

	logp("Doing the atomic data jiggle...\n");

	if(!(tmpman=get_tmp_filename(manifest))) return -1;
	if(lstat(manifest, &statp))
	{
		// Manifest does not exist - maybe the server was killed before
		// it could be renamed.
		logp("%s did not exist - trying %s\n", manifest, tmpman);
		do_rename(tmpman, manifest);
	}
	free(tmpman);
	if(!(zp=gzopen_file(manifest, "rb"))) return -1;

	if(!(deltabdir=prepend_s(current,
		"deltas.reverse", strlen("deltas.reverse")))
	  || !(deltafdir=prepend_s(finishing,
		"deltas.forward", strlen("deltas.forward")))
	  || !(sigpath=prepend_s(current,
		"sig.tmp", strlen("sig.tmp"))))
	{
		logp("out of memory\n");
		gzclose_fp(&zp);
		return -1;
	}

	mkdir(datadir, 0777);
	init_sbuf(&sb);
	while(!(ars=sbuf_fill(NULL, zp, &sb, cntr)))
	{
		if(sb.datapth)
		{
			write_status(client, STATUS_SHUFFLING,
				sb.datapth, p1cntr, cntr);

			if((ret=jiggle(sb.datapth, currentdata, datadirtmp,
				datadir, deltabdir, deltafdir,
				sigpath, sb.endfile,
				hardlinked, cntr, cconf))) break;
		}
		free_sbuf(&sb);
	}
	if(!ret)
	{
		if(ars>0) ret=0;
		else ret=-1;
	}
	gzclose_fp(&zp);

	if(ret)
	{
		// Remove the temporary data directory, we have now removed
		// everything useful from it.
		sync(); // try to help CIFS
		recursive_delete(deltafdir, NULL, FALSE /* do not del files */);
	}
	if(deltabdir) free(deltabdir);
	if(deltafdir) free(deltafdir);
	if(sigpath) free(sigpath);
	if(datapth) free(datapth);
	return ret;
}

int backup_phase4_server(const char *basedir, const char *working, const char *current, const char *currentdata, const char *finishing, struct config *cconf, const char *client, struct cntr *p1cntr, struct cntr *cntr)
{
	int ret=0;
	struct stat statp;
	char *manifest=NULL;
	char *datadir=NULL;
	char *datadirtmp=NULL;
	char *currentdup=NULL;
	char *currentduptmp=NULL;
	char *currentdupdata=NULL;
	char *forward=NULL;
	char *timestamp=NULL;
	char *fullrealcurrent=NULL;
	char *deleteme=NULL;
	char *logpath=NULL;
	char *hlinkedpath=NULL;
	int len=0;
	char realcurrent[256]="";
	FILE *logfp=NULL;

	if((len=readlink(current, realcurrent, sizeof(realcurrent)-1))<0)
		len=0;
	realcurrent[len]='\0';

	if(!(datadir=prepend_s(finishing, "data", strlen("data")))
	  || !(datadirtmp=prepend_s(finishing, "data.tmp", strlen("data.tmp")))
	  || !(manifest=prepend_s(finishing, "manifest.gz", strlen("manifest.gz")))
	  || !(currentdup=prepend_s(finishing, "currentdup", strlen("currentdup")))
	  || !(currentduptmp=prepend_s(finishing, "currentdup.tmp", strlen("currentdup.tmp")))
	  || !(currentdupdata=prepend_s(currentdup, "data", strlen("data")))
	  || !(forward=prepend_s(currentdup, "forward", strlen("forward")))
	  || !(timestamp=prepend_s(finishing, "timestamp", strlen("timestamp")))
	  || !(fullrealcurrent=prepend_s(basedir, realcurrent, strlen(realcurrent)))
	  || !(deleteme=prepend_s(basedir, "deleteme", strlen("deleteme")))
	  || !(logpath=prepend_s(finishing, "log", strlen("log")))
	  || !(hlinkedpath=prepend_s(currentdup, "hardlinked", strlen("hardlinked"))))
	{
		ret=-1;
		goto endfunc;
	}

	if(!(logfp=open_file(logpath, "ab")) || set_logfp(logfp, cconf))
	{
		ret=-1;
		goto endfunc;
	}

	logp("Begin phase4 (shuffle files)\n");

	write_status(client, STATUS_SHUFFLING, NULL, p1cntr, cntr);

	if(!lstat(current, &statp)) // Had a previous backup
	{
		unsigned long bno=0;
		FILE *fwd=NULL;
		int hardlinked=0;
		char tstmp[64]="";
		int newdup=0;

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
					ret=-1;
					goto endfunc;
				}
			}
			logp("Duplicating current backup.\n");
			if(recursive_hardlink(current, currentduptmp, client,
				p1cntr, cntr, cconf)
			  || do_rename(currentduptmp, currentdup))
			{
				ret=-1;
				goto endfunc;
			}
			newdup++;
		}

		if(read_timestamp(timestamp, tstmp, sizeof(tstmp)))
		{
			logp("could not read timestamp file: %s\n", timestamp);
			ret=-1;
			goto endfunc;
		}
		// Get the backup number.
		bno=strtoul(tstmp, NULL, 10);

		// Put forward reference in, indicating the timestamp of
		// the working directory (which will soon become the current
		// directory).
		if(!(fwd=open_file(forward, "wb")))
		{
			log_and_send("could not create forward file");
			ret=-1;
			goto endfunc;
		}
		fprintf(fwd, "%s\n", tstmp);
		close_fp(&fwd);

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
			{
				ret=-1;
				goto endfunc;
			}
			// Stick the next backup timestamp in it. It might
			// be useful one day when wondering when the next
			// backup, now deleted, was made.
			fprintf(hfp, "%s\n", tstmp);
			close_fp(&hfp);
			logp(" doing hardlinked archive\n");
			logp(" will not generate reverse deltas\n");
		}
		else
		{
			logp(" not doing hardlinked archive\n");
			logp(" will generate reverse deltas\n");
			unlink(hlinkedpath);
		}

		if(atomic_data_jiggle(finishing,
			working, manifest, currentdup,
			currentdupdata,
			datadir, datadirtmp, cconf, client,
			hardlinked, bno, p1cntr, cntr))
		{
			logp("could not finish up backup.\n");
			ret=-1;
			goto endfunc;
		}

		write_status(client, STATUS_SHUFFLING,
			"deleting temporary files", p1cntr, cntr);

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
		if(do_rename(fullrealcurrent, deleteme))
		{
			ret=-1;
			goto endfunc;
		}
	}
	else
	{
		// No previous backup, just put datadirtmp in the right place.
		if(do_rename(datadirtmp, datadir))
		{
			ret=-1;
			goto endfunc;
		}
	}

	if(!lstat(deleteme, &statp))
	{
		// Rename the currentdup directory...
		// IMPORTANT TODO: read the path to fullrealcurrent
		// from the deleteme timestamp.
		do_rename(currentdup, fullrealcurrent);

		recursive_delete(deleteme, NULL, TRUE /* delete all */);
	}

	// Rename the finishing symlink so that it becomes the current symlink
	do_rename(finishing, current);

	print_filecounters(p1cntr, cntr, ACTION_BACKUP, 0);
	logp("Backup completed.\n");
	logp("End phase4 (shuffle files)\n");
	set_logfp(NULL, cconf); // will close logfp.

	compress_filename(current, "log", "log.gz", cconf);

endfunc:
	if(datadir) free(datadir);
	if(datadirtmp) free(datadirtmp);
	if(manifest) free(manifest);
	if(currentdup) free(currentdup);
	if(currentduptmp) free(currentduptmp);
	if(currentdupdata) free(currentdupdata);
	if(forward) free(forward);
	if(timestamp) free(timestamp);
	if(fullrealcurrent) free(fullrealcurrent);
	if(deleteme) free(deleteme);
	if(logpath) free(logpath);
	if(hlinkedpath) free(hlinkedpath);

	return ret;
}
