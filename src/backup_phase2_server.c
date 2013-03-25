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
#include "backup_phase1_server.h" // for the resume stuff
#include "backup_phase2_server.h"
#include "current_backups_server.h"

static int treedata(struct sbuf *sb)
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

static char *set_new_datapth(struct sbuf *sb, const char *datadirtmp, struct dpth *dpth, int *istreedata, struct config *cconf)
{
	char *rpath=NULL;
	if(cconf->directory_tree) *istreedata=treedata(sb);

	if(*istreedata)
	{
		// We want to place this file in a directory structure like
		// the directory structure on the original client.
		if(!(sb->datapth=prepend_s("t", sb->path, strlen(sb->path))))
		{
			log_and_send_oom(__FUNCTION__);
			return NULL;
		}
	}
	else
	{
		mk_dpth(dpth, cconf, sb->cmd);
		if(!(sb->datapth=strdup(dpth->path))) // file data path
		{
			log_and_send_oom(__FUNCTION__);
			return NULL;
		}
	}
	if(build_path(datadirtmp, sb->datapth, strlen(sb->datapth),
		&rpath, datadirtmp))
	{
		log_and_send("build path failed");
		return NULL;
	}
	return rpath;
}

static int start_to_receive_new_file(struct sbuf *sb, const char *datadirtmp, struct dpth *dpth, struct cntr *cntr, struct config *cconf)
{
	int ret=-1;
	char *rpath=NULL;
	int istreedata=0;

//logp("start to receive: %s\n", sb->path);

	if(!(rpath=set_new_datapth(sb, datadirtmp, dpth, &istreedata, cconf)))
		return -1;
	
	if(!(sb->fp=open_file(rpath, "wb")))
	{
		log_and_send("make file failed");
		if(rpath) free(rpath);
		return -1;
	}
	if(!istreedata) incr_dpth(dpth, cconf);
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

static int copy(FILE *fp, const char *partial)
{
	size_t b=0;
	size_t w=0;
	FILE *dp=NULL;
	unsigned char in[ZCHUNK];

	if(!(dp=open_file(partial, "wb")))
		return -1;
	while((b=fread(in, 1, ZCHUNK, sp))>0)
	{
		w=fwrite(in, 1, ZCHUNK, dp);
		if(w!=b)
		{
			logp("fwrite failed: %d!=%d\n", w, b);
			close_fp(&dp);
			return -1;
		}
	}

	if(close_fp(&dp))
	{
		logp("failed close_fp when copying partial file\n");
		return -1;
	}

	return 0;
}

static int copy_gzFile(gzFile sp, gzFile dp)
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

// Interrupted files can have a gzip 'unexpected end of file error', which
// causes things to get messed up later. So, read it and truncate it at
// the point where this happens (if it happens).
static int ztruncate(gzFile sp, const char *partial)
{
	size_t b=0;
	size_t w=0;
	gzFile dp=NULL;
	unsigned char in[ZCHUNK];

	if(!(dp=gzopen_file(partial, "wb")))
		return -1;
	
	if(copy_gzFile(sp, dp))
	{
		gzclose_fp(&dp);
		return -1;
	}

	if(gzclose_fp(&dp))
	{
		logp("failed gzclose when truncating partial file\n");
		return -1;
	}

	return 0;
}

// This one is for resuming a new file.
static int ztruncate_w(const char *rpath, const char *partial)
{
	gzFile sp=NULL;

	if(!(sp=gzopen_file(rpath, "rb"))) return -1;

	if(ztruncate(sp, partial))
	{
		gzclose(sp);
		return -1;
	}

	gzclose(sp); // expected to often give an error.

	return 0;
}

static int resume_partial_changed_file(struct sbuf *cb, struct sbuf *p1b, struct cntr *cntr, const char *datadirtmp, const char *deltmppath, struct config *cconf)
{
	int ret=0;
	char *rpath=NULL;
	int istreedata=0;
	struct stat statp;
	char *partial=NULL;
	char *partialdir=NULL;

	logp("Resume partial changed file: %s %s\n", cb->path, rpath);
	if(!lstat(deltmppath, &statp) && S_ISREG(statp.st_mode)
	     && !lstat(rpath, &statp) && S_ISREG(statp.st_mode))
	{
/*
		if(!(partialdir=prepend_s(datadirtmp, "p", strlen("p")))
		  || !(partial=prepend_s(partialdir,
			cb->datapth, strlen(cb->datapth)))
		  || build_path(partialdir, cb->datapth, strlen(cb->datapth),
			&partial, partialdir))
		{
			ret=-1;
			goto end;
		}

		// Need to:
		// If (partial exists)
		// {
		//   if (partial bigger than p1b->sig)
		//   {
		//	Read and recreate (ztruncate) partial.
		//	Copy the whole of deltmppath onto partial.
		//   }
		//   else
		//   {
		//	Delete partial.
		//	Copy the whole of p1b->sigfp/sigzp onto partial.
		//	Copy the whole of deltmppath onto partial.
		//   }
		// }
		// else
		// {
		//	Copy the whole of p1b->sigfp/sigzp onto partial.
		//	Copy the whole of deltmppath onto partial.
		// }
		//
		// Use partial as the basis for a librsync transfer.
		

		// If compression is on, be careful with gzip unexpected
		// end of file errors.
		if(p1b->sigzp)
		{
			if(!(dp=gzopen_file(partial, "wb")))
				return -1;
			if(ztruncate(p1b->sigzp, partial))
			{
				logp("Error in ztruncate\n");
				ret=-1;
				goto end;
			}
			// Need a single file with the same compression.
			//
		}
		else
		{
			if(copy(p1b->sigfp, partial))
			{
				logp("Error in copy\n");
				ret=-1;
				goto end;
			}
		}
		// So, we have created a new directory beginning with 'p',
		// and moved the partial download to it.
		// We can now use the partial file as the basis of a librsync
		// transfer. 
		if(process_changed_file(&cb, p1b, partialdir, cntr))
		{
			ret=-1;
			goto end;
		}
		goto end;
*/
	}

	logp("Actually, no - just forget the previous delta\n");
end:
	if(rpath) free(rpath);
	if(partialdir) free(partialdir);
	if(partial) free(partial);
	return ret;
}

static int process_changed_file(struct sbuf *cb, struct sbuf *p1b, const char *currentdata, const char *datadirtmp, const char *deltmppath, int *resume_partial, struct cntr *cntr, struct config *cconf)
{
	size_t blocklen=0;
	char *curpath=NULL;
	//logp("need to process changed file: %s (%s)\n", cb->path, cb->datapth);

	// Move datapth onto p1b.

	if(p1b->datapth) free(p1b->datapth);
	p1b->datapth=cb->datapth;
	cb->datapth=NULL;

	if(!(curpath=prepend_s(currentdata,
		p1b->datapth, strlen(p1b->datapth))))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	if(dpth_is_compressed(cb->compression, curpath))
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
		if(resume_partial_changed_file(cb, p1b,
			cntr, datadirtmp, deltmppath, cconf)) return -1;
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
		p1b->sigfp, p1b->sigzp, -1, blocklen, -1, cntr)))
	{
		logp("could not rs_filebuf_new for infb.\n");
		return -1;
	}
	if(!(p1b->outfb=rs_filebuf_new(NULL, NULL, NULL,
		async_get_fd(), ASYNC_BUF_LEN, -1, cntr)))
	{
		logp("could not rs_filebuf_new for in_outfb.\n");
		return -1;
	}

	// Flag the things that need to be sent (to the client)
	p1b->senddatapth++;
	p1b->sendstat++;
	p1b->sendpath++;

	//logp("sending sig for %s\n", p1b->path);
	//logp("(%s)\n", p1b->datapth);

	return 0;
}

static int new_non_file(struct sbuf *p1b, FILE *ucfp, char cmd, struct cntr *cntr)
{
	// Is something that does not need more data backed up.
	// Like a directory or a link or something like that.
	// Goes into the unchanged file, so that it does not end up out of
	// order with normal files, which has to wait around for their data
	// to turn up.
	if(sbuf_to_manifest(p1b, ucfp, NULL))
		return -1;
	else
		do_filecounter(cntr, cmd, 0);
	free_sbuf(p1b);
	return 0;
}

static int changed_non_file(struct sbuf *p1b, FILE *ucfp, char cmd, struct cntr *cntr)
{
	// As new_non_file.
	if(sbuf_to_manifest(p1b, ucfp, NULL))
		return -1;
	else
		do_filecounter_changed(cntr, cmd);
	free_sbuf(p1b);
	return 0;
}

static int resume_partial_new_file(struct sbuf *p1b, struct cntr * cntr, const char *currentdata, const char *datadirtmp, struct dpth *dpth, struct config *cconf)
{
	int ret=0;
	struct sbuf cb;
	char *rpath=NULL;
	int istreedata=0;
	struct stat statp;
	char *partial=NULL;
	char *partialdir=NULL;

	// Need to set up a fake current sbuf.
	init_sbuf(&cb);
	cb.cmd=p1b->cmd;
	cb.compression=p1b->compression;
	cb.path=strdup(p1b->path);
	cb.statbuf=strdup(p1b->statbuf);
	if(!(rpath=set_new_datapth(&cb, datadirtmp, dpth, &istreedata, cconf)))
	{
		ret=-1;
		goto end;
	}
	logp("Resume partial new file: %s %s\n", cb.path, rpath);
	if(!lstat(rpath, &statp) && S_ISREG(statp.st_mode))
	{
		int junk=0;
		// It does not matter what this checksum is set to.
		// This is just to get an endfile string in the format that
		// process_changed_file expects.
		unsigned char checksum[18]="0123456789ABCDEF";

		if(!(partialdir=prepend_s(datadirtmp, "p", strlen("p")))
		  || !(partial=prepend_s(partialdir,
			cb.datapth, strlen(cb.datapth)))
		  || build_path(partialdir, cb.datapth, strlen(cb.datapth),
			&partial, partialdir)
		  || !(cb.endfile=strdup(get_endfile_str(statp.st_size, checksum))))
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
			if(ztruncate_w(rpath, partial))
			{
				logp("Error in ztruncate_w\n");
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
		if(process_changed_file(&cb, p1b, currentdata, partialdir, NULL,
			&junk /* resume_partial=0 */,
			cntr, cconf))
		{
			ret=-1;
			goto end;
		}
		if(!istreedata) incr_dpth(dpth, cconf);
		goto end;
	}

	logp("Actually, no - just treat it as completely new\n");
end:
	if(rpath) free(rpath);
	if(partialdir) free(partialdir);
	if(partial) free(partial);
	free_sbuf(&cb);
	return ret;
}

static int process_new(struct sbuf *p1b, FILE *ucfp, const char *currentdata, const char *datadirtmp, struct dpth *dpth, int *resume_partial, struct cntr *cntr, struct config *cconf)
{
	if(*resume_partial
	  && p1b->cmd==CMD_FILE
	  && cconf->librsync
	  && p1b->compression==cconf->compression)
	{
		if(resume_partial_new_file(p1b,
			cntr, currentdata, datadirtmp,
			dpth, cconf)) return -1;
		// Burp only transfers one file at a time, so
		// if there was an interruption, there is only
		// a possibility of one partial file to resume.
		*resume_partial=0;
	}
	if(filedata(p1b->cmd))
	{
		//logp("need to process new file: %s\n", p1b->path);
		// Flag the things that need to be sent (to the client)
		p1b->sendstat++;
		p1b->sendpath++;
	}
	else
	{
		new_non_file(p1b, ucfp, p1b->cmd, cntr);
	}
	return 0;
}

static int process_unchanged_file(struct sbuf *cb, FILE *ucfp, struct cntr *cntr)
{
	if(sbuf_to_manifest(cb, ucfp, NULL))
	{
		free_sbuf(cb);
		return -1;
	}
	else
	{
		do_filecounter_same(cntr, cb->cmd);
	}
	if(cb->endfile) do_filecounter_bytes(cntr,
		 strtoull(cb->endfile, NULL, 10));
	free_sbuf(cb);
	return 1;
}

static int process_new_file(struct sbuf *cb, struct sbuf *p1b, FILE *ucfp, const char *currentdata, const char *datadirtmp, struct dpth *dpth, int *resume_partial, struct cntr *cntr, struct config *cconf)
{
	if(process_new(p1b, ucfp, currentdata, datadirtmp, dpth,
		resume_partial, cntr, cconf)) return -1;
	free_sbuf(cb);
	return 1;
}

// return 1 to say that a file was processed
static int maybe_process_file(struct sbuf *cb, struct sbuf *p1b, FILE *ucfp, const char *currentdata, const char *datadirtmp, const char *deltmppath, struct dpth *dpth, int *resume_partial, struct cntr *cntr, struct config *cconf)
{
	int pcmp;
//	logp("in maybe_proc %s\n", p1b->path);
	if(!(pcmp=sbuf_pathcmp(cb, p1b)))
	{
		int oldcompressed=0;

		// If the file type changed, I think it is time to back it
		// up again (for example, EFS changing to normal file, or
		// back again).
		if(cb->cmd!=p1b->cmd)
			return process_new_file(cb, p1b, ucfp, currentdata,
				datadirtmp, dpth, resume_partial,
				cntr, cconf);

		// mtime is the actual file data.
		// ctime is the attributes or meta data.
		if(cb->statp.st_mtime==p1b->statp.st_mtime
		  && cb->statp.st_ctime==p1b->statp.st_ctime)
		{
			// got an unchanged file
			//logp("got unchanged file: %s %c %c\n", cb->path, cb->cmd, p1b->cmd);
			return process_unchanged_file(cb, ucfp, cntr);
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
				return process_new_file(cb,
					p1b, ucfp, currentdata,
					datadirtmp, dpth, resume_partial,
					cntr, cconf);
			else
				return process_unchanged_file(cb, ucfp, cntr);
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
			return process_new_file(cb, p1b, ucfp, currentdata,
				datadirtmp, dpth, resume_partial,
				cntr, cconf);

		// Get new files if they have switched between compression on
		// or off.
		if(cb->datapth && dpth_is_compressed(cb->compression, cb->datapth))
			oldcompressed=1;
		if( ( oldcompressed && !cconf->compression)
		 || (!oldcompressed &&  cconf->compression))
			return process_new_file(cb, p1b, ucfp, currentdata,
				datadirtmp, dpth, resume_partial,
				cntr, cconf);

		// Otherwise, do the delta stuff (if possible).
		if(filedata(p1b->cmd))
		{
			if(process_changed_file(cb, p1b, currentdata,
				datadirtmp, deltmppath, resume_partial,
				cntr, cconf)) return -1;
		}
		else
		{
			if(changed_non_file(p1b, ucfp, p1b->cmd, cntr))
				return -1;
		}
		free_sbuf(cb);
		return 1;
	}
	else if(pcmp>0)
	{
		//logp("ahead: %s\n", p1b->path);
		// ahead - need to get the whole file
		if(process_new(p1b, ucfp, currentdata, datadirtmp,
			dpth, resume_partial, cntr, cconf)) return -1;
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
		do_filecounter_deleted(cntr, cb->cmd);
	}
	return 0;
}

// Return 1 if there is still stuff needing to be sent.
static int do_stuff_to_send(struct sbuf *p1b, char **last_requested)
{
	//size_t junk=0;
	if(p1b->senddatapth)
	{
		size_t l=strlen(p1b->datapth);
		if(async_append_all_to_write_buffer(CMD_DATAPTH, p1b->datapth, &l))
			return 1;
		p1b->senddatapth=0;
		//if(async_rw(NULL, NULL, NULL, NULL, NULL, &junk)) return -1;
	}
	if(p1b->sendstat)
	{
		size_t l=p1b->slen;
		if(async_append_all_to_write_buffer(CMD_STAT, p1b->statbuf, &l))
			return 1;
		p1b->sendstat=0;
		//if(async_rw(NULL, NULL, NULL, NULL, NULL, &junk)) return -1;
	}
	if(p1b->sendpath)
	{
		size_t l=p1b->plen;
		if(async_append_all_to_write_buffer(p1b->cmd,
			p1b->path, &l)) return 1;
		p1b->sendpath=0;
		if(*last_requested) free(*last_requested);
		*last_requested=strdup(p1b->path);
		//if(async_rw(NULL, NULL, NULL, NULL, NULL, &junk)) return -1;
	}
	if(p1b->sigjob && !p1b->sendendofsig)
	{
		rs_result sigresult;

		sigresult=rs_async(p1b->sigjob,
			&(p1b->rsbuf), p1b->infb, p1b->outfb);
//logp("after rs_async: %d %c %s\n", sigresult, p1b->cmd, p1b->path);

		if(sigresult==RS_DONE)
		{
			p1b->sendendofsig++;
			//if(async_rw(NULL, NULL, NULL, NULL, NULL, &junk))
			//	return -1;
		}
		else if(sigresult==RS_BLOCKED || sigresult==RS_RUNNING)
		{
			// keep going round the loop.
			//if(async_rw(NULL, NULL, NULL, NULL, NULL, &junk))
			//	return -1;
			return 1;
		}
		else
		{
			logp("error in rs_async: %d\n", sigresult);
			return -1;
		}
	}
	if(p1b->sendendofsig)
	{
		size_t l;
		const char *endfile="endfile";
		l=strlen(endfile);
		if(async_append_all_to_write_buffer(CMD_END_FILE, endfile, &l))
			return 1;
		//if(async_rw(NULL, NULL, NULL, NULL, NULL, &junk)) return -1;
		p1b->sendendofsig=0;
	}
	return 0;
}

static int start_to_receive_delta(struct sbuf *rb, const char *working, const char *deltmppath, struct config *cconf)
{
	if(cconf->compression)
	{
		if(!(rb->zp=gzopen_file(deltmppath, comp_level(cconf))))
			return -1;
	}
	else
	{
		if(!(rb->fp=open_file(deltmppath, "wb")))
			return -1;
	}
	rb->receivedelta++;

	return 0;
}

static int finish_delta(struct sbuf *rb, const char *working, const char *deltmppath)
{
	int ret=0;
	char *deltmp=NULL;
	char *delpath=NULL;
	if(!(deltmp=prepend_s("deltas.forward",
		rb->datapth, strlen(rb->datapth)))
	  || !(delpath=prepend_s(working, deltmp, strlen(deltmp)))
	  || mkpath(&delpath, working)
	  || do_rename(deltmppath, delpath))
		ret=-1;
	if(delpath) free(delpath);
	if(deltmp) free(deltmp);
	return ret;
}

// returns 1 for finished ok.
static int do_stuff_to_receive(struct sbuf *rb, FILE *p2fp, const char *datadirtmp, struct dpth *dpth, const char *working, char **last_requested, const char *deltmppath, struct cntr *cntr, struct config *cconf)
{
	int ret=0;
	char rcmd;
	size_t rlen=0;
	size_t wlen=0;
	char *rbuf=NULL;

	// This also attempts to write anything in the write buffer.
	if(async_rw(&rcmd, &rbuf, &rlen, '\0', NULL, &wlen))
	{
		logp("error in async_rw\n");
		return -1;
	}

	if(rbuf)
	{
		if(rcmd==CMD_WARNING)
		{
			logp("WARNING: %s\n", rbuf);
			do_filecounter(cntr, rcmd, 0);
		}
		else if(rb->fp || rb->zp)
		{
			// Currently writing a file (or meta data)
			if(rcmd==CMD_APPEND)
			{
				int app;
				//logp("rlen: %d\n", rlen);
				if((rb->zp
				  && (app=gzwrite(rb->zp, rbuf, rlen))<=0)
				|| (rb->fp
				  && (app=fwrite(rbuf, 1, rlen, rb->fp))<=0))
				{
					logp("error when appending: %d\n", app);
					async_write_str(CMD_ERROR, "write failed");
					ret=-1;
				}
				do_filecounter_recvbytes(cntr, rlen);
			}
			else if(rcmd==CMD_END_FILE)
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
				rb->endfile=rbuf;
				rb->elen=rlen;
				rbuf=NULL;
				if(!ret && rb->receivedelta
				  && finish_delta(rb, working, deltmppath))
					ret=-1;
				else if(!ret)
				{
					if(sbuf_to_manifest(rb, p2fp, NULL))
						ret=-1;
					else
					{
					  char cmd=rb->cmd;
					  if(rb->receivedelta)
						do_filecounter_changed(cntr,
							cmd);
					  else
						do_filecounter(cntr, cmd, 0);
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
					 do_filecounter_bytes(cntr,
					  strtoull(rb->endfile, NULL, 10));
					if(cp)
					{
						// checksum stuff goes here
					}
				}

				free_sbuf(rb);
			}
			else
			{
				logp("unexpected cmd from client while writing file: %c %s\n", rcmd, rbuf);
				ret=-1;
			}
		}
		// Otherwise, expecting to be told of a file to save.
		else if(rcmd==CMD_DATAPTH)
		{
			rb->datapth=rbuf;
			rbuf=NULL;
		}
		else if(rcmd==CMD_STAT)
		{
			rb->statbuf=rbuf;
			rb->slen=rlen;
			rbuf=NULL;
		}
		else if(filedata(rcmd))
		{
			rb->cmd=rcmd;
			rb->plen=rlen;
			rb->path=rbuf;
			rbuf=NULL;

			if(rb->datapth)
			{
				// Receiving a delta.
				if(start_to_receive_delta(rb,
				  working, deltmppath, cconf))
				{
					logp("error in start_to_receive_delta\n");
					ret=-1;
				}
			}
			else
			{
				// Receiving a whole new file.
				if(start_to_receive_new_file(rb,
					datadirtmp, dpth, cntr, cconf))
				{
					logp("error in start_to_receive_new_file\n");
					ret=-1;
				}
			}
		}
		else if(rcmd==CMD_GEN && !strcmp(rbuf, "okbackupphase2end"))
		{
			ret=1;
			//logp("got okbackupphase2end\n");
		}
		else if(rcmd==CMD_INTERRUPT)
		{
			// Interrupt - forget about the last requested file
			// if it matches. Otherwise, we can get stuck on the
			// select in the async stuff, waiting for something
			// that will never arrive.
			if(*last_requested && !strcmp(rbuf, *last_requested))
			{
				free(*last_requested);
				*last_requested=NULL;
			}
		}
		else
		{
			logp("unexpected cmd from client while expecting a file: %c %s\n", rcmd, rbuf);
			ret=-1;
		}

		if(rbuf) { free(rbuf); rbuf=NULL; }
	}

	//logp("returning: %d\n", ret);
	return ret;
}

int backup_phase2_server(gzFile *cmanfp, const char *phase1data, const char *phase2data, const char *unchangeddata, const char *datadirtmp, struct dpth *dpth, const char *currentdata, const char *working, const char *client, struct cntr *p1cntr, int resume, struct cntr *cntr, struct config *cconf)
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

	struct sbuf cb;		// file list in current manifest
	struct sbuf p1b;	// file list from client

	struct sbuf rb;		// receiving file from client

	init_sbuf(&cb);
	init_sbuf(&p1b);
	init_sbuf(&rb);

	if(!(p1zp=gzopen_file(phase1data, "rb")))
		goto error;

	// Open in read+write mode, so that they can be read through if
	// we need to resume.
	// First, open them in a+ mode, so that they will be created if they
	// do not exist.
	if(!(ucfp=open_file(unchangeddata, "a+b")))
		goto error;
	if(!(p2fp=open_file(phase2data, "a+b")))
		goto error;
	close_fp(&ucfp);
	close_fp(&p2fp);

	if(!(ucfp=open_file(unchangeddata, "r+b")))
		goto error;
	if(!(p2fp=open_file(phase2data, "r+b")))
		goto error;

	if(resume && do_resume(p1zp, p2fp, ucfp, dpth, cconf, client,
		p1cntr, cntr)) goto error;

	logp("Begin phase2 (receive file data)\n");

	if(!(deltmppath=prepend_s(working, "delta.tmp", strlen("delta.tmp"))))
		goto error;

	while(1)
	{
		int sts=0;
	//	logp("in loop, %s %s %c\n",
	//		*cmanfp?"got cmanfp":"no cmanfp",
	//		rb.path?:"no rb.path", rb.path?'X':rb.cmd);
		if(rb.path) write_status(client, STATUS_BACKUP,
			rb.path, p1cntr, cntr);
		else write_status(client, STATUS_BACKUP,
			p1b.path, p1cntr, cntr);
		if((last_requested || !p1zp || writebuflen)
		  && (ars=do_stuff_to_receive(&rb, p2fp, datadirtmp, dpth,
			working, &last_requested, deltmppath, cntr, cconf)))
		{
			if(ars<0) goto error;
			// 1 means ok.
			break;
		}

		if((sts=do_stuff_to_send(&p1b, &last_requested))<0)
			goto error;

		if(!sts && p1zp)
		{
		   free_sbuf(&p1b);

		   if((ars=sbuf_fill_phase1(NULL, p1zp, &p1b, cntr)))
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
			if(process_new(&p1b, ucfp, currentdata,
				datadirtmp, dpth, &resume_partial,
				cntr, cconf)) goto error;
		   }
		   else
		   {
			// Have an old manifest, look for it there.

			// Might already have it, or be ahead in the old
			// manifest.
			if(cb.path)
			{
				if((ars=maybe_process_file(&cb, &p1b,
					ucfp, currentdata, datadirtmp,
					deltmppath, dpth, &resume_partial,
					cntr, cconf)))
				{
					if(ars<0) goto error;
					// Do not free it - need to send stuff.
					continue;
				}
				//free_sbuf(&p1b);
			}

			while(*cmanfp)
			{
				free_sbuf(&cb);
				if((ars=sbuf_fill(NULL, *cmanfp, &cb, cntr)))
				{
					// ars==1 means it ended ok.
					if(ars<0) goto error;
					gzclose_fp(cmanfp);
		//logp("ran out of current manifest\n");
					if(process_new(&p1b, ucfp,
						currentdata, datadirtmp, dpth,
						&resume_partial, cntr, cconf))
							goto error;
					break;
				}
		//logp("against: %s\n", cb.path);
				if((ars=maybe_process_file(&cb, &p1b,
					ucfp, currentdata, datadirtmp,
					deltmppath, dpth, &resume_partial,
					cntr, cconf)))
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
			phase2data);
		ret=-1;
	}
	if(close_fp(&ucfp))
	{
		logp("error closing %s in backup_phase2_server\n",
			unchangeddata);
		ret=-1;
	}
	free(deltmppath);
	free_sbuf(&cb);
	free_sbuf(&p1b);
	free_sbuf(&rb);
	gzclose_fp(&p1zp);
	if(!ret) unlink(phase1data);

	logp("End phase2 (receive file data)\n");

	return ret;
}
