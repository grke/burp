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

static int make_rev_sig(const char *dst, const char *sig, struct cntr *cntr)
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
	result=rs_sig_gzfile(dstfp, dstzp, sigp, block_len, strong_len, NULL, cntr);
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


static int gen_rev_delta(const char *sigpath, const char *deltadir, const char *oldpath, const char *finpath, const char *path, struct cntr *cntr, struct config *cconf)
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
	if(mkpath(&delpath))
	{
		logp("could not mkpaths for: %s\n", delpath);
		ret=-1;
	}
	else if(make_rev_sig(finpath, sigpath, cntr))
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

static int inflate_or_link_oldfile(const char *oldpath, const char *infpath)
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
		if(link(oldpath, infpath))
		{
			logp("could not hard link '%s' to '%s': %s\n", infpath, oldpath, strerror(errno));
			ret=-1;
		}
	
	}
	return ret;
}

/* Need to make all the stuff that this does atomic so that existing backups
   never get broken, even if somebody turns the power off on the server. */ 
static int atomic_data_jiggle(const char *finishing, const char *working, const char *manifest, const char *current, const char *currentdata, const char *datadir, const char *datadirtmp, struct config *cconf, const char *client, struct cntr *cntr)
{
	char cmd;
	int ret=0;
	size_t len=0;
	char *buf=NULL;
	char *newpath=NULL;
	char *oldpath=NULL;
	char *finpath=NULL;
	char *deltabdir=NULL;
	char *deltafdir=NULL;
	char *deltafpath=NULL;
	char *sigpath=NULL;
	struct stat statp;
	gzFile mp=NULL;

	logp("Doing the atomic data jiggle...\n");

	if(cconf->hardlinked_archive)
	{
	  logp("Hardlinked archive is on -\n");
	  logp(" will not generate reverse deltas\n");
	}
	else
	{
	  logp("Hardlinked archive is off -\n");
	  logp(" will generate reverse deltas\n");
	}

	if(!(mp=gzopen_file(manifest, "rb"))) return -1;

	if(!(deltabdir=prepend_s(current,
		"deltas.reverse", strlen("deltas.reverse")))
	  || !(deltafdir=prepend_s(finishing,
		"deltas.forward", strlen("deltas.forward")))
	  || !(sigpath=prepend_s(current,
		"sig.tmp", strlen("sig.tmp"))))
	{
		logp("out of memory\n");
		gzclose_fp(&mp);
		return -1;
	}

	mkdir(datadir, 0777);
	while(!ret)
	{
		if(async_read_fp(NULL, mp, &cmd, &buf, &len))
		{
			break;
		}
		else
		{
			if(cmd!=CMD_DATAPTH)
			{
				// ignore
				if(buf) { free(buf); buf=NULL; }
				continue;
			}
			if(buf[len]=='\n') buf[len]='\0';
			write_status(client, STATUS_SHUFFLING, buf, cntr);
			if(!(oldpath=prepend_s(currentdata,
				buf, strlen(buf)))
			  || !(newpath=prepend_s(datadirtmp,
				buf, strlen(buf)))
			  || !(finpath=prepend_s(datadir,
				buf, strlen(buf)))
			  || !(deltafpath=prepend_s(deltafdir,
				buf, strlen(buf))))
			{
				logp("out of memory\n");
				ret=-1;	
			}
			else if(!lstat(finpath, &statp)
			  && S_ISREG(statp.st_mode))
			{
				// Looks like an interrupted jiggle
				// did this file already.
				if(!lstat(deltafpath, &statp)
				  && S_ISREG(statp.st_mode))
				{
					logp("deleting unneeded forward delta: %s\n", deltafpath);
					unlink(deltafpath);
				}
				logp("skipping already present file: %s\n",
					finpath);
			}
			else if(mkpath(&finpath))
			{
				logp("could not create path for: %s\n",
					finpath);
				ret=-1;
			}
			else if(mkpath(&newpath))
			{
				logp("could not create path for: %s\n",
					newpath);
				ret=-1;
			}
			else if(!lstat(deltafpath, &statp)
			  && S_ISREG(statp.st_mode))
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
				}
				else if(!(cp=strrchr(infpath, '.')))
				{
					logp("could not strip the suffix from '%s'\n", infpath);
					ret=-1;
				}
				*cp='\0';

				//logp("Fixing up: %s\n", buf);
				if(!ret && inflate_or_link_oldfile(oldpath, infpath))
				{
					logp("error when inflating old file: %s\n", oldpath);
					ret=-1;
				}

				if(!ret && do_patch(infpath, deltafpath,
				  newpath, cconf->compression,
				  cntr, cconf))
				{
					logp("error when patching\n");
					ret=-1;
					// Remove anything that got written.
					unlink(newpath);
				}

				// Get rid of the inflated old file.
				// This will also remove it if there was an
				// error.
				unlink(infpath);
				free(infpath);

				if(!ret)
				{
					// Need to generate a reverse diff,
					// unless we are keeping a hardlinked
					// archive.
					if(!cconf->hardlinked_archive)
					{
					  if(gen_rev_delta(sigpath, deltabdir,
					    oldpath, newpath, buf, cntr, cconf))
						ret=-1;
					}

					// Power interruptions should be
					// recoverable. If it happens before
					// this point, the data jiggle for
					// this file has to be done again.
					// Once finpath is in place, no more
					// jiggle is required.

					// Use the fresh new file.
					if(!ret && do_rename(newpath, finpath))
						ret=-1;
					else if(!ret)
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
					  if(!cconf->hardlinked_archive)
					  {
					    //logp("Deleting oldpath...\n");
					    unlink(oldpath);
					  }
					}
				}
			}
			else if(!lstat(newpath, &statp)
			     && S_ISREG(statp.st_mode))
			{
				// Use the fresh new file.
				// This needs to happen after checking
				// for the forward delta, because the
				// patching stuff writes to newpath.
				//logp("Using newly received file\n");
				if(do_rename(newpath, finpath)) ret=-1;
			}
			else if(!lstat(oldpath, &statp)
			  && S_ISREG(statp.st_mode))
			{
				// Use the old unchanged file.
				// Hard link it first.
				//logp("Hard linking to old file: %s\n", buf);
				if(link(oldpath, finpath))
				{
					logp("could not hard link '%s' to '%s': %s\n", finpath, oldpath, strerror(errno));
					ret=-1;
				}
				else
				{
					// If we are not keeping a hardlinked
					// archive, delete the old link.
					if(!cconf->hardlinked_archive)
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
			}

			if(oldpath) { free(oldpath); oldpath=NULL; }
			if(newpath) { free(newpath); newpath=NULL; }
			if(finpath) { free(finpath); finpath=NULL; }
			if(deltafpath) { free(deltafpath); deltafpath=NULL; }
		}
		if(buf) { free(buf); buf=NULL; }
	}
	gzclose_fp(&mp);

	if(!ret)
	{
		// Remove the temporary data directory, we have now removed
		// everything useful from it.
		recursive_delete(deltafdir, NULL, FALSE /* do not del files */);
	}
	if(deltabdir) free(deltabdir);
	if(deltafdir) free(deltafdir);
	if(sigpath) free(sigpath);
	if(buf) { free(buf); buf=NULL; }
	return ret;
}

int backup_phase4_server(const char *basedir, const char *working, const char *current, const char *currentdata, const char *finishing, struct config *cconf, const char *client, struct cntr *cntr)
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
	  || !(logpath=prepend_s(finishing, "log", strlen("log"))))
	{
		ret=-1;
		goto endfunc;
	}

	if(!(logfp=open_file(logpath, "ab")) || set_logfp(logfp))
	{
		ret=-1;
		goto endfunc;
	}

	logp("Begin phase4 (shuffle files)\n");

	write_status(client, STATUS_SHUFFLING, NULL, cntr);

	if(!lstat(current, &statp)) // Had a previous backup
	{
		FILE *fwd=NULL;
		char tstmp[64]="";

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
			if(recursive_hardlink(current, currentduptmp, client, cntr)
			  || do_rename(currentduptmp, currentdup))
			{
				ret=-1;
				goto endfunc;
			}
		}

		if(read_timestamp(timestamp, tstmp, sizeof(tstmp)))
		{
			logp("could not read timestamp file: %s\n", timestamp);
			ret=-1;
			goto endfunc;
		}

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

		if(atomic_data_jiggle(finishing,
			working, manifest, currentdup,
			currentdupdata,
			datadir, datadirtmp, cconf, client, cntr))
		{
			logp("could not finish up backup.\n");
			ret=-1;
			goto endfunc;
		}

		write_status(client, STATUS_SHUFFLING, "deleting temporary files", cntr);

		// Remove the temporary data directory, we have now removed
		// everything useful from it.
		recursive_delete(datadirtmp, NULL, TRUE /* del files */);

		// Clean up the currentdata directory - this is now the 'old'
		// currentdata directory. Any files that were deleted from
		// the client will be left in there, so call recursive_delete
		// with the option that makes it not delete files.
		// This will have the effect of getting rid of unnecessary
		// directories.
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

	end_filecounter(cntr, 0, ACTION_BACKUP);
	logp("Backup completed.\n");
	logp("End phase4 (shuffle files)\n");
	set_logfp(NULL); // will close logfp.

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

	return ret;
}
