#include "include.h"

static int treedata(struct sbufl *sb)
{
	// Windows is sending directory data as if it is file data - this
	// cannot be saved in a tree structure.
	// So, need to decode the stat to test for whether it is a directory.
	decode_stat(sb->statbuf, &(sb->statp),
		&(sb->winattr), &(sb->compression));
	if(S_ISDIR(sb->statp.st_mode)) return 0;

	if(sb->cmd==CMD_FILE
	  || sb->cmd==CMD_ENC_FILE
	  || sb->cmd==CMD_EFS_FILE)
		return 1;
	return 0;
}

static char *set_new_datapth(struct sdirs *sdirs, struct config *cconf,
	struct sbufl *sb, struct dpthl *dpthl, int *istreedata)
{
	char *rpath=NULL;
	if(cconf->directory_tree) *istreedata=treedata(sb);

	if(*istreedata)
	{
		// We want to place this file in a directory structure like
		// the directory structure on the original client.
		if(!(sb->datapth=prepend_s("t", sb->path)))
		{
			log_and_send_oom(__FUNCTION__);
			return NULL;
		}
	}
	else
	{
		mk_dpthl(dpthl, cconf, sb->cmd);
		if(!(sb->datapth=strdup(dpthl->path))) // file data path
		{
			log_and_send_oom(__FUNCTION__);
			return NULL;
		}
	}
	if(build_path(sdirs->datadirtmp,
		sb->datapth, &rpath, sdirs->datadirtmp))
	{
		log_and_send("build path failed");
		return NULL;
	}
	return rpath;
}

static int start_to_receive_new_file(struct sdirs *sdirs, struct config *cconf,
	struct sbufl *sb, struct dpthl *dpthl)
{
	char *rpath=NULL;
	int istreedata=0;

//logp("start to receive: %s\n", sb->path);

	if(!(rpath=set_new_datapth(sdirs, cconf, sb, dpthl, &istreedata)))
		return -1;
	
	if(!(sb->fp=open_file(rpath, "wb")))
	{
		log_and_send("make file failed");
		if(rpath) free(rpath);
		return -1;
	}
	if(!istreedata) incr_dpthl(dpthl, cconf);
	if(rpath) free(rpath);
	return 0; 
}

static int filedata(char cmd)
{
	return (cmd==CMD_FILE
	  || cmd==CMD_ENC_FILE
	  || cmd==CMD_METADATA
	  || cmd==CMD_ENC_METADATA
	  || cmd==CMD_VSS
	  || cmd==CMD_ENC_VSS
	  || cmd==CMD_VSS_T
	  || cmd==CMD_ENC_VSS_T
	  || cmd==CMD_EFS_FILE);
}

static int copy_File_to_File(FILE *sp, FILE *dp)
{
	size_t b=0;
	size_t w=0;
	unsigned char in[ZCHUNK];
	while((b=fread(in, 1, ZCHUNK, sp))>0)
	{
		w=fwrite(in, 1, b, dp);
		if(w!=b)
		{
			logp("fwrite failed: %d!=%d\n", w, b);
			return -1;
		}
	}
	return 0;
}

static int copy_path_to_File(const char *src, FILE *dp)
{
	FILE *sp=NULL;

	if(!(sp=open_file(src, "rb")))
		return -1;

	if(copy_File_to_File(sp, dp))
	{
		close_fp(&sp);
		return -1;
	}

	close_fp(&sp);
	return 0;
}

static int copy_gzFile_to_gzFile(gzFile sp, gzFile dp)
{
	size_t b=0;
	size_t w=0;
	unsigned char in[ZCHUNK];

	while((b=gzread(sp, in, ZCHUNK))>0)
	{
		w=gzwrite(dp, in, b);
		if(w!=b)
		{
			logp("gzwrite failed: %d!=%d\n", w, b);
			return -1;
		}
	}
	return 0;
}

static int copy_gzpath_to_gzFile(const char *src, gzFile dp)
{
	gzFile sp=NULL;

	if(!(sp=gzopen_file(src, "rb")))
		return -1;

	if(copy_gzFile_to_gzFile(sp, dp))
	{
		gzclose(sp);
		return -1;
	}

	gzclose(sp); // expected to often give an error.
	return 0;
}

static int copy_gzFile_to_gzpath(gzFile sp, const char *dst)
{
	gzFile dp=NULL;

	if(!(dp=gzopen_file(dst, "wb")))
		return -1;
	
	if(copy_gzFile_to_gzFile(sp, dp))
	{
		gzclose_fp(&dp);
		return -1;
	}

	if(gzclose_fp(&dp))
	{
		logp("failed gzclose when copying to %s\n", dst);
		return -1;
	}

	return 0;
}

static int copy_gzpath_to_gzpath(const char *src, const char *dst)
{
	gzFile sp=NULL;

	if(!(sp=gzopen_file(src, "rb"))) return -1;

	if(copy_gzFile_to_gzpath(sp, dst))
	{
		gzclose(sp);
		return -1;
	}

	gzclose(sp); // expected to often give an error.

	return 0;
}

static int process_changed_file(struct sdirs *sdirs, struct config *cconf,
	struct sbufl *cb, struct sbufl *p1b, const char *currentdata,
	int *resume_partial);

// TODO: Some of the repeated code in this can be factored out.
static int resume_partial_changed_file(struct sdirs *sdirs,
	struct config *cconf, struct sbufl *cb,
	struct sbufl *p1b, const char *curpath)
{
	int ret=0;
	struct stat dstatp;
	struct stat cstatp;
	char *partial=NULL;
	char *partialdir=NULL;
	char *zdeltmp=NULL;
	struct sbufl xb;

	init_sbufl(&xb);
	xb.cmd=cb->cmd;
	xb.compression=cb->compression;
	xb.path=strdup(cb->path);
	xb.statbuf=strdup(cb->statbuf);
	xb.datapth=strdup(p1b->datapth);
	xb.endfile=strdup(cb->endfile);

	logp("Resume partial changed file: %s\n", xb.path);
	if(cconf->resume_partial
	     && !lstat(sdirs->deltmppath, &dstatp) && S_ISREG(dstatp.st_mode)
	     && !lstat(curpath, &cstatp) && S_ISREG(cstatp.st_mode))
	{
		int junk=0;
		gzFile dzp=NULL;
		FILE *dfp=NULL;
		struct stat pstatp;
		if(!(partialdir=prepend_s(sdirs->datadirtmp, "p"))
		  || !(partial=prepend_s(partialdir, xb.datapth))
		  || build_path(partialdir, xb.datapth, &partial, partialdir))
		{
			ret=-1;
			goto end;
		}

		if(!lstat(partial, &pstatp))
		{
			if(!S_ISREG(pstatp.st_mode))
			{
				logp("%s is not a regular file\n", partial);
				goto actuallyno;
			}
			if(pstatp.st_size>cstatp.st_size)
			{
				// Looks like a previously resumed file.
				if(xb.compression)
				{
					// Need to read and recreate it, in
					// case it was not fully created.
					if(!(zdeltmp=prepend(sdirs->deltmppath,
						".z", strlen(".z"),
						0 /* no slash */))
					  || !(dzp=gzopen_file(zdeltmp, "wb"))
					  || copy_gzpath_to_gzFile(partial,
						dzp)
					  || do_rename(zdeltmp, partial))
					{
						ret=-1;
						goto end;
					}
				}
				else
				{
					// Append to the existing one.
					if(!(dfp=open_file(partial, "ab")))
					{
						ret=-1;
						goto end;
					}
				}
			}
			else
			{
				unlink(partial);
				// Copy the whole of p1b->sigfp/sigzp to
				// partial.
				if(xb.compression)
				{
					if(!(dzp=gzopen_file(partial, "wb"))
					  || copy_gzFile_to_gzFile(p1b->sigzp,
						dzp))
					{
						ret=-1;
						goto end;
					}
				}
				else
				{
					if(!(dfp=open_file(partial, "wb"))
					  || copy_File_to_File(p1b->sigfp, dfp))
					{
						ret=-1;
						goto end;
					}
				}
			}
			// Now, copy the whole of deltmppath onto partial.
			// dzp or dfp will be open by this point.
			if(xb.compression)
			{
				if(copy_gzpath_to_gzFile(sdirs->deltmppath, dzp))
				{
					ret=-1;
					goto end;
				}
			}
			else
			{
				if(copy_path_to_File(sdirs->deltmppath, dfp))
				{
					ret=-1;
					goto end;
				}
			}
		}
		else
		{
		//	Copy the whole of p1b->sigfp/sigzp onto partial.
		//	Copy the whole of deltmppath onto partial.
			if(xb.compression)
			{
				// There is no partial, this creates it.
				if(!(dzp=gzopen_file(partial, "wb"))
				  || copy_gzFile_to_gzFile(p1b->sigzp, dzp))
				{
					ret=-1;
					goto end;
				}
			}
			else
			{
				// There is no partial, this creates it.
				if(!(dfp=open_file(partial, "wb"))
				  || copy_File_to_File(p1b->sigfp, dfp))
				{
					ret=-1;
					goto end;
				}
			}
			if(xb.compression)
			{
				if(copy_gzpath_to_gzFile(sdirs->deltmppath, dzp))
				{
					ret=-1;
					goto end;
				}
			}
			else
			{
				if(copy_path_to_File(sdirs->deltmppath, dfp))
				{
					ret=-1;
					goto end;
				}
			}
		}
		if(dfp && close_fp(&dfp))
		{
			ret=-1;
			goto end;
		}
		if(dzp && gzclose_fp(&dzp))
		{
			ret=-1;
			goto end;
		}
		// Use partial as the basis for a librsync transfer.
		
		// So, we have created a new directory beginning with 'p',
		// and moved the partial download to it.
		// We can now use the partial file as the basis of a librsync
		// transfer. 
		if(process_changed_file(sdirs, cconf, &xb, p1b, partialdir,
			&junk /* resume_partial=0 */))
		{
			ret=-1;
			goto end;
		}

		goto end;
	}

actuallyno:
	logp("Actually, no - just forget the previous delta\n");
end:
	if(partialdir) free(partialdir);
	if(partial) free(partial);
	if(zdeltmp) free(zdeltmp);
	free_sbufl(&xb);
	return ret;
}

static int process_changed_file(struct sdirs *sdirs, struct config *cconf,
	struct sbufl *cb, struct sbufl *p1b,
	const char *adir,
	int *resume_partial)
{
	size_t blocklen=0;
	char *curpath=NULL;
	//logp("need to process changed file: %s (%s)\n", cb->path, cb->datapth);

	// Move datapth onto p1b.
	if(p1b->datapth) free(p1b->datapth);
	p1b->datapth=cb->datapth;
	cb->datapth=NULL;

	if(!(curpath=prepend_s(adir, p1b->datapth)))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	if(dpthl_is_compressed(cb->compression, curpath))
		p1b->sigzp=gzopen_file(curpath, "rb");
	else
		p1b->sigfp=open_file(curpath, "rb");
	if(!p1b->sigzp && !p1b->sigfp)
	{
		logp("could not open %s: %s\n",
			curpath, strerror(errno));
		free(curpath);
		return -1;
	}

	if(*resume_partial
	  && p1b->cmd==CMD_FILE
	  && cconf->librsync)
	// compression?
	{
		if(resume_partial_changed_file(sdirs, cconf, cb, p1b, curpath))
			return -1;

		// Burp only transfers one file at a time, so
		// if there was an interruption, there is only
		// a possibility of one partial file to resume.
		*resume_partial=0;
	}
	free(curpath);

	blocklen=get_librsync_block_len(cb->endfile);
	if(!(p1b->sigjob=rs_sig_begin(blocklen, RS_DEFAULT_STRONG_LEN)))
	{
		logp("could not start signature job.\n");
		return -1;
	}
	//logp("sig begin: %s\n", p1b->datapth);
	if(!(p1b->infb=rs_filebuf_new(NULL,
		p1b->sigfp, p1b->sigzp, -1, blocklen, -1, cconf->cntr)))
	{
		logp("could not rs_filebuf_new for infb.\n");
		return -1;
	}
	if(!(p1b->outfb=rs_filebuf_new(NULL, NULL, NULL,
		async_get_fd(), ASYNC_BUF_LEN, -1, cconf->cntr)))
	{
		logp("could not rs_filebuf_new for in_outfb.\n");
		return -1;
	}

	// Flag the things that need to be sent (to the client)
	p1b->send_datapth++;
	p1b->send_stat++;
	p1b->send_path++;

	//logp("sending sig for %s\n", p1b->path);
	//logp("(%s)\n", p1b->datapth);

	return 0;
}

static int new_non_file(struct sbufl *p1b, FILE *ucfp, char cmd, struct config *cconf)
{
	// Is something that does not need more data backed up.
	// Like a directory or a link or something like that.
	// Goes into the unchanged file, so that it does not end up out of
	// order with normal files, which has to wait around for their data
	// to turn up.
	if(sbufl_to_manifest(p1b, ucfp, NULL))
		return -1;
	else
		do_filecounter(cconf->cntr, cmd, 0);
	free_sbufl(p1b);
	return 0;
}

static int changed_non_file(struct sbufl *p1b, FILE *ucfp, char cmd, struct config *cconf)
{
	// As new_non_file.
	if(sbufl_to_manifest(p1b, ucfp, NULL))
		return -1;
	else
		do_filecounter_changed(cconf->cntr, cmd);
	free_sbufl(p1b);
	return 0;
}

static int resume_partial_new_file(struct sdirs *sdirs, struct config *cconf,
	struct sbufl *p1b, struct dpthl *dpthl)
{
	int ret=0;
	int junk=0;
	struct sbufl cb;
	char *rpath=NULL;
	int istreedata=0;
	struct stat statp;
	char *partial=NULL;
	char *partialdir=NULL;
	char *zdeltmp=NULL;
	// It does not matter what this checksum is set to.
	// This is just to get an endfile string in the format that
	// process_changed_file expects.
	unsigned char checksum[18]="0123456789ABCDEF";

	// Need to set up a fake current sbufl.
	init_sbufl(&cb);
	cb.cmd=p1b->cmd;
	cb.compression=p1b->compression;
	cb.path=strdup(p1b->path);
	cb.statbuf=strdup(p1b->statbuf);
	if(!(rpath=set_new_datapth(sdirs, cconf, &cb, dpthl, &istreedata)))
	{
		ret=-1;
		goto end;
	}

	if(!(partialdir=prepend_s(sdirs->datadirtmp, "p"))
	  || !(partial=prepend_s(partialdir, cb.datapth))
	  || build_path(partialdir, cb.datapth, &partial, partialdir))
	{
		ret=-1;
		goto end;
	}

	if(cconf->resume_partial
	  && !lstat(partial, &statp) && S_ISREG(statp.st_mode))
	{
		// A previous resume was going on.
		// Need to concatenate the possible delta onto the partial
		// file.
		FILE *dfp=NULL;
		gzFile dzp=NULL;
		logp("Resume previously resumed partial new file: %s %s\n",
			cb.path, rpath);

		if(!(cb.endfile=strdup(
			get_endfile_str(statp.st_size, checksum))))
		{
			ret=-1;
			goto end;
		}
		if(cb.compression)
		{
			// Recreate partial, in case it was only partially
			// written and consequently has gz errors.
			if(!(zdeltmp=prepend(sdirs->deltmppath, ".z", strlen(".z"),
				0 /* no slash */))
			  || !(dzp=gzopen_file(zdeltmp, "wb"))
			  || copy_gzpath_to_gzFile(partial, dzp)
			  || do_rename(zdeltmp, partial))
			{
				ret=-1;
				goto end;
			}
		}
		else
		{
			// Just append to the existing one.
			if(!(dfp=open_file(partial, "ab")))
			{
				ret=-1;
				goto end;
			}
		}
		if(!lstat(sdirs->deltmppath, &statp) && S_ISREG(statp.st_mode))
		{
			if(cb.compression)
			{
				if(copy_gzpath_to_gzFile(sdirs->deltmppath, dzp))
				{
					ret=-1;
					goto end;
				}
			}
			else
			{
				if(copy_path_to_File(sdirs->deltmppath, dfp))
				{
					ret=-1;
					goto end;
				}
			}
		}
		if(dfp && close_fp(&dfp))
		{
			ret=-1;
			goto end;
		}
		if(dzp && gzclose_fp(&dzp))
		{
			ret=-1;
			goto end;
		}
		if(process_changed_file(sdirs, cconf, &cb, p1b, partialdir,
			&junk /* resume_partial=0 */))
		{
			ret=-1;
			goto end;
		}
		if(!istreedata) incr_dpthl(dpthl, cconf);

		goto end;
	}

	logp("Resume partial new file: %s %s\n", cb.path, rpath);
	if(cconf->resume_partial
	  && !lstat(rpath, &statp) && S_ISREG(statp.st_mode))
	{
		if(!(cb.endfile=strdup(
			get_endfile_str(statp.st_size, checksum))))
		{
			ret=-1;
			goto end;
		}
		// If compression is on, be careful with gzip unexpected
		// end of file errors.
		// Otherwise, just rename the whole file.
		unlink(partial);
		if(cb.compression)
		{
			if(copy_gzpath_to_gzpath(rpath, partial))
			{
				logp("Error in copy_gzpath_to_gzpath\n");
				ret=-1;
				goto end;
			}
			// delete the original.
			if(unlink(rpath))
			{
				logp("Failed to unlink %s: %s\n",
					rpath, strerror(errno));
				return -1;
			}
		}
		else
		{
			if(do_rename(rpath, partial))
			{
				ret=-1;
				goto end;
			}
		}
		// So, we have created a new directory beginning with 'p',
		// and moved the partial download to it.
		// We can now use the partial file as the basis of a librsync
		// transfer.
		if(process_changed_file(sdirs, cconf, &cb, p1b, partialdir,
			&junk /* resume_partial=0 */))
		{
			ret=-1;
			goto end;
		}
		if(!istreedata) incr_dpthl(dpthl, cconf);
		goto end;
	}

	logp("Actually, no - just treat it as completely new\n");
end:
	if(rpath) free(rpath);
	if(partialdir) free(partialdir);
	if(partial) free(partial);
	if(zdeltmp) free(zdeltmp);
	free_sbufl(&cb);
	return ret;
}

static int process_new(struct sdirs *sdirs, struct config *cconf,
	struct sbufl *p1b, FILE *ucfp, struct dpthl *dpthl, int *resume_partial)
{
	if(*resume_partial
	  && p1b->cmd==CMD_FILE
	  && cconf->librsync
	  && p1b->compression==cconf->compression)
	{
		if(resume_partial_new_file(sdirs, cconf, p1b, dpthl)) return -1;

		// Burp only transfers one file at a time, so
		// if there was an interruption, there is only
		// a possibility of one partial file to resume.
		*resume_partial=0;
	}
	if(filedata(p1b->cmd))
	{
		//logp("need to process new file: %s\n", p1b->path);
		// Flag the things that need to be sent (to the client)
		p1b->send_stat++;
		p1b->send_path++;
	}
	else
	{
		new_non_file(p1b, ucfp, p1b->cmd, cconf);
	}
	return 0;
}

static int process_unchanged_file(struct sbufl *cb, FILE *ucfp, struct config *cconf)
{
	if(sbufl_to_manifest(cb, ucfp, NULL))
	{
		free_sbufl(cb);
		return -1;
	}
	else
	{
		do_filecounter_same(cconf->cntr, cb->cmd);
	}
	if(cb->endfile) do_filecounter_bytes(cconf->cntr,
		 strtoull(cb->endfile, NULL, 10));
	free_sbufl(cb);
	return 1;
}

static int process_new_file(struct sdirs *sdirs, struct config *cconf,
	struct sbufl *cb, struct sbufl *p1b, FILE *ucfp,
	struct dpthl *dpthl, int *resume_partial)
{
	if(process_new(sdirs, cconf, p1b, ucfp, dpthl, resume_partial))
		return -1;
	free_sbufl(cb);
	return 1;
}

// return 1 to say that a file was processed
static int maybe_process_file(struct sdirs *sdirs, struct config *cconf,
	struct sbufl *cb, struct sbufl *p1b, FILE *ucfp,
	struct dpthl *dpthl, int *resume_partial)
{
	int pcmp;
//	logp("in maybe_proc %s\n", p1b->path);
	if(!(pcmp=sbufl_pathcmp(cb, p1b)))
	{
		int oldcompressed=0;

		// If the file type changed, I think it is time to back it
		// up again (for example, EFS changing to normal file, or
		// back again).
		if(cb->cmd!=p1b->cmd)
			return process_new_file(sdirs, cconf, cb, p1b, ucfp,
				dpthl, resume_partial);

		// mtime is the actual file data.
		// ctime is the attributes or meta data.
		if(cb->statp.st_mtime==p1b->statp.st_mtime
		  && cb->statp.st_ctime==p1b->statp.st_ctime)
		{
			// got an unchanged file
			//logp("got unchanged file: %s %c %c\n", cb->path, cb->cmd, p1b->cmd);
			return process_unchanged_file(cb, ucfp, cconf);
		}

		if(cb->statp.st_mtime==p1b->statp.st_mtime
		  && cb->statp.st_ctime!=p1b->statp.st_ctime)
		{
			// File data stayed the same, but attributes or meta
			// data changed. We already have the attributes, but
			// may need to get extra meta data.
			if(cb->cmd==CMD_ENC_METADATA
			  || p1b->cmd==CMD_ENC_METADATA
			// TODO: make unencrypted metadata use the librsync
			  || cb->cmd==CMD_METADATA
			  || p1b->cmd==CMD_METADATA
			  || cb->cmd==CMD_VSS
			  || p1b->cmd==CMD_VSS
			  || cb->cmd==CMD_ENC_VSS
			  || p1b->cmd==CMD_ENC_VSS
			  || cb->cmd==CMD_VSS_T
			  || p1b->cmd==CMD_VSS_T
			  || cb->cmd==CMD_ENC_VSS_T
			  || p1b->cmd==CMD_ENC_VSS_T
			  || cb->cmd==CMD_EFS_FILE
			  || p1b->cmd==CMD_EFS_FILE)
				return process_new_file(sdirs, cconf, cb,
					p1b, ucfp, dpthl, resume_partial);
			// On Windows, we have to back up the whole file if
			// ctime changed, otherwise things like permission
			// changes do not get noticed. So, in that case, fall
			// through to the changed stuff below.
			// Non-Windows clients finish here.
			else if(!cconf->client_is_windows)
				return process_unchanged_file(cb, ucfp, cconf);
		}

		// Got a changed file.
		//logp("got changed file: %s\n", p1b->path);

		// If either old or new is encrypted, or librsync is off,
		// we need to get a new file.
		if(!cconf->librsync
		  || cb->cmd==CMD_ENC_FILE
		  || p1b->cmd==CMD_ENC_FILE
		  || cb->cmd==CMD_ENC_METADATA
		  || p1b->cmd==CMD_ENC_METADATA
		  || cb->cmd==CMD_EFS_FILE
		  || p1b->cmd==CMD_EFS_FILE
		// TODO: make unencrypted metadata use the librsync
		  || cb->cmd==CMD_METADATA
		  || p1b->cmd==CMD_METADATA
		  || cb->cmd==CMD_VSS
		  || p1b->cmd==CMD_VSS
		  || cb->cmd==CMD_ENC_VSS
		  || p1b->cmd==CMD_ENC_VSS
		  || cb->cmd==CMD_VSS_T
		  || p1b->cmd==CMD_VSS_T
		  || cb->cmd==CMD_ENC_VSS_T
		  || p1b->cmd==CMD_ENC_VSS_T)
			return process_new_file(sdirs, cconf, cb, p1b, ucfp,
				dpthl, resume_partial);

		// Get new files if they have switched between compression on
		// or off.
		if(cb->datapth && dpthl_is_compressed(cb->compression, cb->datapth))
			oldcompressed=1;
		if( ( oldcompressed && !cconf->compression)
		 || (!oldcompressed &&  cconf->compression))
			return process_new_file(sdirs, cconf, cb, p1b, ucfp,
				dpthl, resume_partial);

		// Otherwise, do the delta stuff (if possible).
		if(filedata(p1b->cmd))
		{
			if(process_changed_file(sdirs, cconf, cb, p1b,
				sdirs->currentdata,
				resume_partial)) return -1;
		}
		else
		{
			if(changed_non_file(p1b, ucfp, p1b->cmd, cconf))
				return -1;
		}
		free_sbufl(cb);
		return 1;
	}
	else if(pcmp>0)
	{
		//logp("ahead: %s\n", p1b->path);
		// ahead - need to get the whole file
		if(process_new(sdirs, cconf, p1b, ucfp,
			dpthl, resume_partial)) return -1;
		// do not free
		return 1;
	}
	else
	{
		//logp("behind: %s\n", p1b->path);
		// behind - need to read more from the old
		// manifest
		// Count a deleted file - it was in the old manifest but not
		// the new.
		do_filecounter_deleted(cconf->cntr, cb->cmd);
	}
	return 0;
}

// Return 1 if there is still stuff needing to be sent.
static int do_stuff_to_send(struct sbufl *p1b, char **last_requested)
{
	static struct iobuf wbuf;
	if(p1b->send_datapth)
	{
		iobuf_from_str(&wbuf, CMD_DATAPTH, p1b->datapth);
		if(async_append_all_to_write_buffer(&wbuf)) return 1;
		p1b->send_datapth=0;
	}
	if(p1b->send_stat)
	{
		wbuf.cmd=CMD_ATTRIBS;
		wbuf.buf=p1b->statbuf;
		wbuf.len=p1b->slen;
		if(async_append_all_to_write_buffer(&wbuf)) return 1;
		p1b->send_stat=0;
	}
	if(p1b->send_path)
	{
		wbuf.cmd=p1b->cmd;
		wbuf.buf=p1b->path;
		wbuf.len=p1b->plen;
		if(async_append_all_to_write_buffer(&wbuf)) return 1;
		p1b->send_path=0;
		if(*last_requested) free(*last_requested);
		*last_requested=strdup(p1b->path);
		//if(async_rw(NULL, NULL)) return -1;
	}
	if(p1b->sigjob && !p1b->send_endofsig)
	{
		rs_result sigresult;

		sigresult=rs_async(p1b->sigjob,
			&(p1b->rsbuf), p1b->infb, p1b->outfb);
//logp("after rs_async: %d %c %s\n", sigresult, p1b->cmd, p1b->path);

		if(sigresult==RS_DONE)
		{
			p1b->send_endofsig++;
		}
		else if(sigresult==RS_BLOCKED || sigresult==RS_RUNNING)
		{
			// keep going round the loop.
			return 1;
		}
		else
		{
			logp("error in rs_async: %d\n", sigresult);
			return -1;
		}
	}
	if(p1b->send_endofsig)
	{
		iobuf_from_str(&wbuf, CMD_END_FILE, (char *)"endfile");
		if(async_append_all_to_write_buffer(&wbuf)) return 1;
		p1b->send_endofsig=0;
	}
	return 0;
}

static int start_to_receive_delta(struct sdirs *sdirs, struct config *cconf,
	struct sbufl *rb)
{
	if(cconf->compression)
	{
		if(!(rb->zp=gzopen_file(sdirs->deltmppath, comp_level(cconf))))
			return -1;
	}
	else
	{
		if(!(rb->fp=open_file(sdirs->deltmppath, "wb")))
			return -1;
	}
	rb->receive_delta++;

	return 0;
}

static int finish_delta(struct sdirs *sdirs, struct sbufl *rb)
{
	int ret=0;
	char *deltmp=NULL;
	char *delpath=NULL;
	if(!(deltmp=prepend_s("deltas.forward", rb->datapth))
	  || !(delpath=prepend_s(sdirs->working, deltmp))
	  || mkpath(&delpath, sdirs->working)
	  || do_rename(sdirs->deltmppath, delpath))
		ret=-1;
	if(delpath) free(delpath);
	if(deltmp) free(deltmp);
	return ret;
}

// returns 1 for finished ok.
static int do_stuff_to_receive(struct sdirs *sdirs, struct config *cconf,
	struct sbufl *rb, FILE *p2fp, struct dpthl *dpthl, char **last_requested)
{
	int ret=0;
	struct iobuf *rbuf=NULL;

	if(!rbuf && !(rbuf=iobuf_alloc())) return -1;

	iobuf_free_content(rbuf);
	// This also attempts to write anything in the write buffer.
	if(async_rw(rbuf, NULL))
	{
		logp("error in async_rw\n");
		return -1;
	}

	if(rbuf->buf)
	{
		if(rbuf->cmd==CMD_WARNING)
		{
			logp("WARNING: %s\n", rbuf->buf);
			do_filecounter(cconf->cntr, rbuf->cmd, 0);
		}
		else if(rb->fp || rb->zp)
		{
			// Currently writing a file (or meta data)
			if(rbuf->cmd==CMD_APPEND)
			{
				int app;
				//logp("rbuf->len: %d\n", rbuf->len);
				if((rb->zp
				  && (app=gzwrite(rb->zp, rbuf->buf, rbuf->len))<=0)
				|| (rb->fp
				  && (app=fwrite(rbuf->buf, 1, rbuf->len, rb->fp))<=0))
				{
					logp("error when appending: %d\n", app);
					async_write_str(CMD_ERROR, "write failed");
					ret=-1;
				}
				do_filecounter_recvbytes(cconf->cntr, rbuf->len);
			}
			else if(rbuf->cmd==CMD_END_FILE)
			{
				// Finished the file.
				// Write it to the phase2 file, and free the
				// buffers.

				if(close_fp(&(rb->fp)))
				{
					logp("error closing delta for %s in receive\n", rb->path);
					ret=-1;
				}
				if(gzclose_fp(&(rb->zp)))
				{
					logp("error gzclosing delta for %s in receive\n", rb->path);
					ret=-1;
				}
				rb->endfile=rbuf->buf;
				rb->elen=rbuf->len;
				rbuf->buf=NULL;
				if(!ret && rb->receive_delta
				  && finish_delta(sdirs, rb))
					ret=-1;
				else if(!ret)
				{
					if(sbufl_to_manifest(rb, p2fp, NULL))
						ret=-1;
					else
					{
					  char cmd=rb->cmd;
					  if(rb->receive_delta)
						do_filecounter_changed(
							cconf->cntr, cmd);
					  else
						do_filecounter(
							cconf->cntr, cmd, 0);
					  if(*last_requested
					  && !strcmp(rb->path, *last_requested))
					  {
						free(*last_requested);
						*last_requested=NULL;
					  }
					}
				}

				if(!ret)
				{
					char *cp=NULL;
					cp=strchr(rb->endfile, ':');
					if(rb->endfile)
					 do_filecounter_bytes(cconf->cntr,
					  strtoull(rb->endfile, NULL, 10));
					if(cp)
					{
						// checksum stuff goes here
					}
				}

				free_sbufl(rb);
			}
			else
			{
				iobuf_log_unexpected(rbuf, __FUNCTION__);
				ret=-1;
			}
		}
		// Otherwise, expecting to be told of a file to save.
		else if(rbuf->cmd==CMD_DATAPTH)
		{
			rb->datapth=rbuf->buf;
			rbuf->buf=NULL;
		}
		else if(rbuf->cmd==CMD_ATTRIBS)
		{
			rb->statbuf=rbuf->buf;
			rb->slen=rbuf->len;
			rbuf->buf=NULL;
		}
		else if(filedata(rbuf->cmd))
		{
			rb->cmd=rbuf->cmd;
			rb->plen=rbuf->len;
			rb->path=rbuf->buf;
			rbuf->buf=NULL;

			if(rb->datapth)
			{
				// Receiving a delta.
				if(start_to_receive_delta(sdirs, cconf, rb))
				{
					logp("error in start_to_receive_delta\n");
					ret=-1;
				}
			}
			else
			{
				// Receiving a whole new file.
				if(start_to_receive_new_file(sdirs, cconf, rb,
					dpthl))
				{
					logp("error in start_to_receive_new_file\n");
					ret=-1;
				}
			}
		}
		else if(rbuf->cmd==CMD_GEN && !strcmp(rbuf->buf, "okbackupphase2end"))
		{
			ret=1;
			//logp("got okbackupphase2end\n");
		}
		else if(rbuf->cmd==CMD_INTERRUPT)
		{
			// Interrupt - forget about the last requested file
			// if it matches. Otherwise, we can get stuck on the
			// select in the async stuff, waiting for something
			// that will never arrive.
			if(*last_requested && !strcmp(rbuf->buf, *last_requested))
			{
				free(*last_requested);
				*last_requested=NULL;
			}
		}
		else
		{
			iobuf_log_unexpected(rbuf, __FUNCTION__);
			ret=-1;
		}
	}

	//logp("returning: %d\n", ret);
	return ret;
}

int backup_phase2_server(struct sdirs *sdirs, struct config *cconf,
	gzFile *cmanfp, struct dpthl *dpthl, int resume)
{
	int ars=0;
	int ret=0;
	gzFile p1zp=NULL;
	char *deltmppath=NULL;
	char *last_requested=NULL;
	// Where to write phase2data.
	// Data is not getting written to a compressed file.
	// This is important for recovery if the power goes.
	FILE *p2fp=NULL;
	// unchanged data
	FILE *ucfp=NULL;
	int resume_partial=resume;

	struct sbufl cb;	// file list in current manifest
	struct sbufl p1b;	// file list from client

	struct sbufl rb;	// receiving file from client

	init_sbufl(&cb);
	init_sbufl(&p1b);
	init_sbufl(&rb);

	if(!(p1zp=gzopen_file(sdirs->phase1data, "rb")))
		goto error;

	// Open in read+write mode, so that they can be read through if
	// we need to resume.
	// First, open them in a+ mode, so that they will be created if they
	// do not exist.
	if(!(ucfp=open_file(sdirs->unchangeddata, "a+b")))
		goto error;
	if(!(p2fp=open_file(sdirs->phase2data, "a+b")))
		goto error;
	close_fp(&ucfp);
	close_fp(&p2fp);

	if(!(ucfp=open_file(sdirs->unchangeddata, "r+b")))
		goto error;
	if(!(p2fp=open_file(sdirs->phase2data, "r+b")))
		goto error;

	if(resume && do_resume(p1zp, p2fp, ucfp, dpthl, cconf))
		goto error;

	logp("Begin phase2 (receive file data)\n");

	while(1)
	{
		int sts=0;
	//	logp("in loop, %s %s %c\n",
	//		*cmanfp?"got cmanfp":"no cmanfp",
	//		rb.path?:"no rb.path", rb.path?'X':rb.cmd);
		write_status(STATUS_BACKUP, rb.path?rb.path:p1b.path, cconf);
		if((last_requested || !p1zp || writebuflen)
		  && (ars=do_stuff_to_receive(sdirs, cconf, &rb, p2fp, dpthl,
			&last_requested)))
		{
			if(ars<0) goto error;
			// 1 means ok.
			break;
		}

		if((sts=do_stuff_to_send(&p1b, &last_requested))<0)
			goto error;

		if(!sts && p1zp)
		{
		   free_sbufl(&p1b);

		   if((ars=sbufl_fill_phase1(NULL, p1zp, &p1b, cconf->cntr)))
		   {
			if(ars<0) goto error;
			// ars==1 means it ended ok.
			gzclose_fp(&p1zp);
			//logp("ended OK - write phase2end");
			if(async_write_str(CMD_GEN, "backupphase2end"))
				goto error;
		   }

		   //logp("check: %s\n", p1b.path);

		   if(!*cmanfp)
		   {
			// No old manifest, need to ask for a new file.
			//logp("no cmanfp\n");
			if(process_new(sdirs, cconf, &p1b, ucfp,
				dpthl, &resume_partial)) goto error;
		   }
		   else
		   {
			// Have an old manifest, look for it there.

			// Might already have it, or be ahead in the old
			// manifest.
			if(cb.path)
			{
				if((ars=maybe_process_file(sdirs, cconf,
					&cb, &p1b, ucfp,
					dpthl, &resume_partial)))
				{
					if(ars<0) goto error;
					// Do not free it - need to send stuff.
					continue;
				}
				//free_sbufl(&p1b);
			}

			while(*cmanfp)
			{
				free_sbufl(&cb);
				if((ars=sbufl_fill(NULL, *cmanfp, &cb, cconf->cntr)))
				{
					// ars==1 means it ended ok.
					if(ars<0) goto error;
					gzclose_fp(cmanfp);
		//logp("ran out of current manifest\n");
					if(process_new(sdirs, cconf,
						&p1b, ucfp, dpthl,
						&resume_partial))
							goto error;
					break;
				}
		//logp("against: %s\n", cb.path);
				if((ars=maybe_process_file(sdirs, cconf,
					&cb, &p1b, ucfp,
					dpthl, &resume_partial)))
				{
					if(ars<0) goto error;
					// Do not free it - need to send stuff.
					break;
				}
			}
		   }
		}
	}

	goto end;

error:
	ret=-1;
end:
	if(close_fp(&p2fp))
	{
		logp("error closing %s in backup_phase2_server\n",
			sdirs->phase2data);
		ret=-1;
	}
	if(close_fp(&ucfp))
	{
		logp("error closing %s in backup_phase2_server\n",
			sdirs->unchangeddata);
		ret=-1;
	}
	free(deltmppath);
	free_sbufl(&cb);
	free_sbufl(&p1b);
	free_sbufl(&rb);
	gzclose_fp(&p1zp);
	if(!ret) unlink(sdirs->phase1data);

	logp("End phase2 (receive file data)\n");

	return ret;
}
