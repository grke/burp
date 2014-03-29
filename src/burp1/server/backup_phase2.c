#include "include.h"

static int treedata(struct sbuf *sb)
{
	// Windows is sending directory data as if it is file data - this
	// cannot be saved in a tree structure.
	// So, need to decode the stat to test for whether it is a directory.
	attribs_decode(sb);
	if(S_ISDIR(sb->statp.st_mode)) return 0;

	if(sb->path.cmd==CMD_FILE
	  || sb->path.cmd==CMD_ENC_FILE
	  || sb->path.cmd==CMD_EFS_FILE)
		return 1;
	return 0;
}

static char *set_new_datapth(struct sdirs *sdirs, struct conf *cconf,
	struct sbuf *sb, struct dpthl *dpthl, int *istreedata)
{
	static char *tmp=NULL;
	char *rpath=NULL;
	if(cconf->directory_tree) *istreedata=treedata(sb);

	if(*istreedata)
	{
		// We want to place this file in a directory structure like
		// the directory structure on the original client.
		if(!(tmp=prepend_s("t", sb->path.buf)))
		{
			log_and_send_oom(__FUNCTION__);
			return NULL;
		}
	}
	else
	{
		mk_dpthl(dpthl, cconf, sb->path.cmd);
		if(!(tmp=strdup(dpthl->path))) // file data path
		{
			log_and_send_oom(__FUNCTION__);
			return NULL;
		}
	}
	iobuf_from_str(&sb->burp1->datapth, CMD_DATAPTH, tmp);
	if(build_path(sdirs->datadirtmp,
		sb->burp1->datapth.buf, &rpath, sdirs->datadirtmp))
	{
		log_and_send("build path failed");
		return NULL;
	}
	return rpath;
}

static int start_to_receive_new_file(struct sdirs *sdirs, struct conf *cconf,
	struct sbuf *sb, struct dpthl *dpthl)
{
	char *rpath=NULL;
	int istreedata=0;

//logp("start to receive: %s\n", sb->path);

	if(!(rpath=set_new_datapth(sdirs, cconf, sb, dpthl, &istreedata)))
		return -1;
	
	if(!(sb->burp1->fp=open_file(rpath, "wb")))
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

static int process_changed_file(struct sdirs *sdirs, struct conf *cconf,
	struct sbuf *cb, struct sbuf *p1b,
	const char *adir)
{
	size_t blocklen=0;
	char *curpath=NULL;
	//logp("need to process changed file: %s (%s)\n", cb->path, cb->datapth);

	// Move datapth onto p1b.
	iobuf_copy(&p1b->burp1->datapth, &cb->burp1->datapth);
	cb->burp1->datapth.buf=NULL;

	if(!(curpath=prepend_s(adir, p1b->burp1->datapth.buf)))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	if(dpthl_is_compressed(cb->compression, curpath))
		p1b->burp1->sigzp=gzopen_file(curpath, "rb");
	else
		p1b->burp1->sigfp=open_file(curpath, "rb");
	if(!p1b->burp1->sigzp && !p1b->burp1->sigfp)
	{
		logp("could not open %s: %s\n", curpath, strerror(errno));
		free(curpath);
		return -1;
	}
	free(curpath);

	blocklen=get_librsync_block_len(cb->burp1->endfile.buf);
	if(!(p1b->burp1->sigjob=rs_sig_begin(blocklen, RS_DEFAULT_STRONG_LEN)))
	{
		logp("could not start signature job.\n");
		return -1;
	}
	//logp("sig begin: %s\n", p1b->burp1->datapth.buf);
	if(!(p1b->burp1->infb=rs_filebuf_new(NULL,
		p1b->burp1->sigfp, p1b->burp1->sigzp,
		-1, blocklen, -1, cconf->cntr)))
	{
		logp("could not rs_filebuf_new for infb.\n");
		return -1;
	}
	if(!(p1b->burp1->outfb=rs_filebuf_new(NULL, NULL, NULL,
		async_get_fd(), ASYNC_BUF_LEN, -1, cconf->cntr)))
	{
		logp("could not rs_filebuf_new for in_outfb.\n");
		return -1;
	}

	// Flag the things that need to be sent (to the client)
	p1b->flags |= SBUFL_SEND_DATAPTH;
	p1b->flags |= SBUFL_SEND_STAT;
	p1b->flags |= SBUFL_SEND_PATH;

	//logp("sending sig for %s\n", p1b->path);
	//logp("(%s)\n", p1b->datapth);

	return 0;
}

static int new_non_file(struct sbuf *p1b, FILE *ucfp, struct conf *cconf)
{
	// Is something that does not need more data backed up.
	// Like a directory or a link or something like that.
	// Goes into the unchanged file, so that it does not end up out of
	// order with normal files, which has to wait around for their data
	// to turn up.
	if(sbufl_to_manifest(p1b, ucfp, NULL))
		return -1;
	else
		cntr_add(cconf->cntr, p1b->path.cmd, 0);
	sbuf_free_contents(p1b);
	return 0;
}

static int changed_non_file(struct sbuf *p1b, FILE *ucfp, char cmd, struct conf *cconf)
{
	// As new_non_file.
	if(sbufl_to_manifest(p1b, ucfp, NULL))
		return -1;
	else
		cntr_add_changed(cconf->cntr, cmd);
	sbuf_free_contents(p1b);
	return 0;
}

static int process_new(struct sdirs *sdirs, struct conf *cconf,
	struct sbuf *p1b, FILE *ucfp, struct dpthl *dpthl)
{
	if(!p1b->path.buf) return 0;
	if(filedata(p1b->path.cmd))
	{
		//logp("need to process new file: %s\n", p1b->path);
		// Flag the things that need to be sent (to the client)
		p1b->flags |= SBUFL_SEND_STAT;
		p1b->flags |= SBUFL_SEND_PATH;
	}
	else
	{
		new_non_file(p1b, ucfp, cconf);
	}
	return 0;
}

static int process_unchanged_file(struct sbuf *cb, FILE *ucfp, struct conf *cconf)
{
	if(sbufl_to_manifest(cb, ucfp, NULL))
	{
		sbuf_free_contents(cb);
		return -1;
	}
	else
	{
		cntr_add_same(cconf->cntr, cb->path.cmd);
	}
	if(cb->burp1->endfile.buf) cntr_add_bytes(cconf->cntr,
		 strtoull(cb->burp1->endfile.buf, NULL, 10));
	sbuf_free_contents(cb);
	return 1;
}

static int process_new_file(struct sdirs *sdirs, struct conf *cconf,
	struct sbuf *cb, struct sbuf *p1b, FILE *ucfp,
	struct dpthl *dpthl)
{
	if(process_new(sdirs, cconf, p1b, ucfp, dpthl))
		return -1;
	sbuf_free_contents(cb);
	return 1;
}

// return 1 to say that a file was processed
static int maybe_process_file(struct sdirs *sdirs, struct conf *cconf,
	struct sbuf *cb, struct sbuf *p1b, FILE *ucfp,
	struct dpthl *dpthl)
{
	int pcmp;
	if(!(pcmp=sbuf_pathcmp(cb, p1b)))
	{
		int oldcompressed=0;

		// If the file type changed, I think it is time to back it
		// up again (for example, EFS changing to normal file, or
		// back again).
		if(cb->path.cmd!=p1b->path.cmd)
			return process_new_file(sdirs, cconf, cb, p1b, ucfp,
				dpthl);

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
			if(cb->path.cmd==CMD_ENC_METADATA
			  || p1b->path.cmd==CMD_ENC_METADATA
			// TODO: make unencrypted metadata use the librsync
			  || cb->path.cmd==CMD_METADATA
			  || p1b->path.cmd==CMD_METADATA
			  || cb->path.cmd==CMD_VSS
			  || p1b->path.cmd==CMD_VSS
			  || cb->path.cmd==CMD_ENC_VSS
			  || p1b->path.cmd==CMD_ENC_VSS
			  || cb->path.cmd==CMD_VSS_T
			  || p1b->path.cmd==CMD_VSS_T
			  || cb->path.cmd==CMD_ENC_VSS_T
			  || p1b->path.cmd==CMD_ENC_VSS_T
			  || cb->path.cmd==CMD_EFS_FILE
			  || p1b->path.cmd==CMD_EFS_FILE)
				return process_new_file(sdirs, cconf, cb,
					p1b, ucfp, dpthl);
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
		  || cb->path.cmd==CMD_ENC_FILE
		  || p1b->path.cmd==CMD_ENC_FILE
		  || cb->path.cmd==CMD_ENC_METADATA
		  || p1b->path.cmd==CMD_ENC_METADATA
		  || cb->path.cmd==CMD_EFS_FILE
		  || p1b->path.cmd==CMD_EFS_FILE
		// TODO: make unencrypted metadata use the librsync
		  || cb->path.cmd==CMD_METADATA
		  || p1b->path.cmd==CMD_METADATA
		  || cb->path.cmd==CMD_VSS
		  || p1b->path.cmd==CMD_VSS
		  || cb->path.cmd==CMD_ENC_VSS
		  || p1b->path.cmd==CMD_ENC_VSS
		  || cb->path.cmd==CMD_VSS_T
		  || p1b->path.cmd==CMD_VSS_T
		  || cb->path.cmd==CMD_ENC_VSS_T
		  || p1b->path.cmd==CMD_ENC_VSS_T)
			return process_new_file(sdirs, cconf, cb, p1b, ucfp,
				dpthl);

		// Get new files if they have switched between compression on
		// or off.
		if(cb->burp1->datapth.buf
		  && dpthl_is_compressed(cb->compression, cb->burp1->datapth.buf))
			oldcompressed=1;
		if( ( oldcompressed && !cconf->compression)
		 || (!oldcompressed &&  cconf->compression))
			return process_new_file(sdirs, cconf, cb, p1b, ucfp,
				dpthl);

		// Otherwise, do the delta stuff (if possible).
		if(filedata(p1b->path.cmd))
		{
			if(process_changed_file(sdirs, cconf, cb, p1b,
				sdirs->currentdata)) return -1;
		}
		else
		{
			if(changed_non_file(p1b, ucfp, p1b->path.cmd, cconf))
				return -1;
		}
		sbuf_free_contents(cb);
		return 1;
	}
	else if(pcmp>0)
	{
		//logp("ahead: %s\n", p1b->path);
		// ahead - need to get the whole file
		if(process_new(sdirs, cconf, p1b, ucfp, dpthl)) return -1;
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
		cntr_add_deleted(cconf->cntr, cb->path.cmd);
	}
	return 0;
}

// Return 1 if there is still stuff needing to be sent.
static int do_stuff_to_send(struct sbuf *p1b, char **last_requested)
{
	static struct iobuf wbuf;
	if(p1b->flags & SBUFL_SEND_DATAPTH)
	{
		iobuf_copy(&wbuf, &p1b->burp1->datapth);
		if(async_append_all_to_write_buffer(&wbuf)) return 1;
		p1b->flags &= ~SBUFL_SEND_DATAPTH;
	}
	if(p1b->flags & SBUFL_SEND_STAT)
	{
		iobuf_copy(&wbuf, &p1b->attr);
		if(async_append_all_to_write_buffer(&wbuf)) return 1;
		p1b->flags &= ~SBUFL_SEND_STAT;
	}
	if(p1b->flags & SBUFL_SEND_PATH)
	{
		iobuf_copy(&wbuf, &p1b->path);
		if(async_append_all_to_write_buffer(&wbuf)) return 1;
		p1b->flags &= ~SBUFL_SEND_PATH;
		if(*last_requested) free(*last_requested);
		*last_requested=strdup(p1b->path.buf);
		//if(async_rw(NULL, NULL)) return -1;
	}
	if(p1b->burp1->sigjob && !(p1b->flags & SBUFL_SEND_ENDOFSIG))
	{
		rs_result sigresult;

		sigresult=rs_async(p1b->burp1->sigjob, &(p1b->burp1->rsbuf),
			p1b->burp1->infb, p1b->burp1->outfb);
//logp("after rs_async: %d %c %s\n", sigresult, p1b->cmd, p1b->path);

		if(sigresult==RS_DONE)
		{
			p1b->flags |= SBUFL_SEND_ENDOFSIG;
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
	if(p1b->flags & SBUFL_SEND_ENDOFSIG)
	{
		iobuf_from_str(&wbuf, CMD_END_FILE, (char *)"endfile");
		if(async_append_all_to_write_buffer(&wbuf)) return 1;
		p1b->flags &= ~SBUFL_SEND_ENDOFSIG;
	}
	return 0;
}

static int start_to_receive_delta(struct sdirs *sdirs, struct conf *cconf,
	struct sbuf *rb)
{
	if(cconf->compression)
	{
		if(!(rb->burp1->zp=gzopen_file(sdirs->deltmppath,
			comp_level(cconf))))
				return -1;
	}
	else
	{
		if(!(rb->burp1->fp=open_file(sdirs->deltmppath, "wb")))
			return -1;
	}
	rb->flags |= SBUFL_RECV_DELTA;

	return 0;
}

static int finish_delta(struct sdirs *sdirs, struct sbuf *rb)
{
	int ret=0;
	char *deltmp=NULL;
	char *delpath=NULL;
	if(!(deltmp=prepend_s("deltas.forward", rb->burp1->datapth.buf))
	  || !(delpath=prepend_s(sdirs->working, deltmp))
	  || mkpath(&delpath, sdirs->working)
	  || do_rename(sdirs->deltmppath, delpath))
		ret=-1;
	if(delpath) free(delpath);
	if(deltmp) free(deltmp);
	return ret;
}

// returns 1 for finished ok.
static int do_stuff_to_receive(struct sdirs *sdirs, struct conf *cconf,
	struct sbuf *rb, FILE *p2fp, struct dpthl *dpthl, char **last_requested)
{
	static struct iobuf *rbuf=NULL;

	if(!rbuf && !(rbuf=iobuf_alloc())) goto error;

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
			cntr_add(cconf->cntr, rbuf->cmd, 0);
		}
		else if(rb->burp1->fp || rb->burp1->zp)
		{
			// Currently writing a file (or meta data)
			if(rbuf->cmd==CMD_APPEND)
			{
				int app;
				//logp("rbuf->len: %d\n", rbuf->len);
				cntr_add_recvbytes(cconf->cntr, rbuf->len);
				if((rb->burp1->zp
				  && (app=gzwrite(rb->burp1->zp, rbuf->buf, rbuf->len))<=0)
				|| (rb->burp1->fp
				  && (app=fwrite(rbuf->buf, 1, rbuf->len, rb->burp1->fp))<=0))
				{
					logp("error when appending: %d\n", app);
					async_write_str(CMD_ERROR, "write failed");
					goto error;
				}
			}
			else if(rbuf->cmd==CMD_END_FILE)
			{
				static char *cp=NULL;
				// Finished the file.
				// Write it to the phase2 file, and free the
				// buffers.

				if(close_fp(&(rb->burp1->fp)))
				{
					logp("error closing delta for %s in receive\n", rb->path);
					goto error;
				}
				if(gzclose_fp(&(rb->burp1->zp)))
				{
					logp("error gzclosing delta for %s in receive\n", rb->path);
					goto error;
				}
				iobuf_copy(&rb->burp1->endfile, rbuf);
				rbuf->buf=NULL;
				if(rb->flags & SBUFL_RECV_DELTA
				  && finish_delta(sdirs, rb))
					goto error;

				if(sbufl_to_manifest(rb, p2fp, NULL))
					goto error;

				if(rb->flags & SBUFL_RECV_DELTA)
					cntr_add_changed(
						cconf->cntr, rb->path.cmd);
				else
					cntr_add(
						cconf->cntr, rb->path.cmd, 0);
				if(*last_requested
				    && !strcmp(rb->path.buf, *last_requested))
				{
					free(*last_requested);
					*last_requested=NULL;
				}

				cp=strchr(rb->burp1->endfile.buf, ':');
				if(rb->burp1->endfile.buf)
				 cntr_add_bytes(cconf->cntr,
				  strtoull(rb->burp1->endfile.buf,
				  NULL, 10));
				if(cp)
				{
						// checksum stuff goes here
				}

				sbuf_free_contents(rb);
			}
			else
			{
				iobuf_log_unexpected(rbuf, __FUNCTION__);
				goto error;
			}
		}
		// Otherwise, expecting to be told of a file to save.
		else if(rbuf->cmd==CMD_DATAPTH)
		{
			iobuf_copy(&rb->burp1->datapth, rbuf);
			rbuf->buf=NULL;
		}
		else if(rbuf->cmd==CMD_ATTRIBS)
		{
			iobuf_copy(&rb->attr, rbuf);
			rbuf->buf=NULL;
		}
		else if(filedata(rbuf->cmd))
		{
			iobuf_copy(&rb->path, rbuf);
			rbuf->buf=NULL;

			if(rb->burp1->datapth.buf)
			{
				// Receiving a delta.
				if(start_to_receive_delta(sdirs, cconf, rb))
				{
					logp("error in start_to_receive_delta\n");
					goto error;
				}
			}
			else
			{
				// Receiving a whole new file.
				if(start_to_receive_new_file(sdirs, cconf, rb,
					dpthl))
				{
					logp("error in start_to_receive_new_file\n");
					goto error;
				}
			}
		}
		else if(rbuf->cmd==CMD_GEN
		  && !strcmp(rbuf->buf, "okbackupphase2end"))
			goto end_phase2;
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
			goto error;
		}
	}

	return 0;
end_phase2:
	return 1;
error:
	return -1;
}

int backup_phase2_server(struct sdirs *sdirs, struct conf *cconf,
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

	struct sbuf *cb=NULL; // file list in current manifest
	struct sbuf *p1b=NULL; // file list from client

	struct sbuf *rb=NULL; // receiving file from client

	if(!(cb=sbuf_alloc(cconf))
	  || !(p1b=sbuf_alloc(cconf))
	  || !(rb=sbuf_alloc(cconf)))
		goto error;

	if(!(p1zp=gzopen_file(sdirs->phase1data, "rb")))
		goto error;

	// Open in read+write mode, so that they can be read through if
	// we need to resume.
	// First, open them in a+ mode, so that they will be created if they
	// do not exist.
	if(!(ucfp=open_file(sdirs->unchangeddata, "a+b"))
	  || !(p2fp=open_file(sdirs->phase2data, "a+b")))
		goto error;
	close_fp(&ucfp);
	close_fp(&p2fp);
	if(!(ucfp=open_file(sdirs->unchangeddata, "r+b"))
	  || !(p2fp=open_file(sdirs->phase2data, "r+b")))
		goto error;

	if(resume && do_resume(p1zp, p2fp, ucfp, dpthl, cconf))
		goto error;

	logp("Begin phase2 (receive file data)\n");

	while(1)
	{
		int sts=0;
		//printf("in loop, %s %s %c\n",
		//	*cmanfp?"got cmanfp":"no cmanfp",
		//	rb->path.buf?:"no rb->path",
	 	//	rb->path.buf?'X':rb->path.cmd);
		if(write_status(STATUS_BACKUP,
			rb->path.buf?rb->path.buf:p1b->path.buf, cconf))
				goto error;
		if((last_requested || !p1zp || writebuflen)
		  && (ars=do_stuff_to_receive(sdirs, cconf, rb, p2fp, dpthl,
			&last_requested)))
		{
			if(ars<0) goto error;
			// 1 means ok.
			break;
		}

		if((sts=do_stuff_to_send(p1b, &last_requested))<0)
			goto error;

		if(!sts && p1zp)
		{
		   sbuf_free_contents(p1b);

		   if((ars=sbufl_fill_phase1(NULL, p1zp, p1b, cconf->cntr)))
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
			if(process_new(sdirs, cconf, p1b, ucfp, dpthl))
				goto error;
		   }
		   else
		   {
			// Have an old manifest, look for it there.

			// Might already have it, or be ahead in the old
			// manifest.
			if(cb->path.buf)
			{
				if((ars=maybe_process_file(sdirs, cconf,
					cb, p1b, ucfp, dpthl)))
				{
					if(ars<0) goto error;
					// Do not free it - need to send stuff.
					continue;
				}
				//free_sbufl(&p1b);
			}

			while(*cmanfp)
			{
				sbuf_free_contents(cb);
				if((ars=sbufl_fill(NULL,
					*cmanfp, cb, cconf->cntr)))
				{
					// ars==1 means it ended ok.
					if(ars<0) goto error;
					gzclose_fp(cmanfp);
		//logp("ran out of current manifest\n");
					if(process_new(sdirs, cconf,
						p1b, ucfp, dpthl))
							goto error;
					break;
				}
		//logp("against: %s\n", cb.path);
				if((ars=maybe_process_file(sdirs, cconf,
					cb, p1b, ucfp, dpthl)))
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
	sbuf_free(cb);
	sbuf_free(p1b);
	sbuf_free(rb);
	gzclose_fp(&p1zp);
	if(!ret) unlink(sdirs->phase1data);

	logp("End phase2 (receive file data)\n");

	return ret;
}
