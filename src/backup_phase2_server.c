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

static int start_to_receive_new_file(struct sbuf *sb, const char *datadirtmp, struct dpth *dpth, struct cntr *cntr, struct config *cconf)
{
	int ret=0;
	char *rpath=NULL;

//logp("start to receive: %s\n", sb->path);

	if(!(sb->datapth=strdup(dpth->path))) // file data path
	{
		log_and_send("out of memory");
		ret=-1;
	}
	else if(build_path(datadirtmp, sb->datapth, strlen(sb->datapth),
		&rpath, datadirtmp))
	{
		log_and_send("build path failed");
		ret=-1;
	}
	else if(!(sb->fp=open_file(rpath, "wb")))
	{
		log_and_send("make file failed");
		ret=-1;
	}
	if(rpath) free(rpath);
	incr_dpth(dpth, cconf);
	return ret;
}

static int filedata(char cmd)
{
	return (cmd==CMD_FILE
	  || cmd==CMD_ENC_FILE
	  || cmd==CMD_METADATA
	  || cmd==CMD_ENC_METADATA);
}

static int process_changed_file(struct sbuf *cb, struct sbuf *p1b, const char *currentdata, struct cntr *cntr)
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
		logp("out of memory\n");
		return -1;
	}
	if(dpth_is_compressed(curpath))
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
	free(curpath);

	blocklen=get_librsync_block_len(cb->endfile);
	if(!(p1b->sigjob=rs_sig_begin(blocklen, RS_DEFAULT_STRONG_LEN)))
	{
		logp("could not start signature job.\n");
		return -1;
	}
	//logp("sig begin: %s\n", p1b->datapth);
	if(!(p1b->infb=rs_filebuf_new(NULL,
		p1b->sigfp, p1b->sigzp, -1, blocklen, cntr)))
	{
		logp("could not rs_filebuf_new for infb.\n");
		return -1;
	}
	if(!(p1b->outfb=rs_filebuf_new(NULL, NULL, NULL,
		async_get_fd(), ASYNC_BUF_LEN, cntr)))
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
	{
		return -1;
	}
	else
	{
		do_filecounter(cntr, cmd, 0);
	}
	free_sbuf(p1b);
	return 0;
}

static int process_new(struct sbuf *p1b, FILE *p2fp, FILE *ucfp, struct cntr *cntr)
{
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

// return 1 to say that a file was processed
static int maybe_process_file(struct sbuf *cb, struct sbuf *p1b, FILE *p2fp, FILE *ucfp, const char *currentdata, struct cntr *cntr, struct config *cconf)
{
	int pcmp;
	if(!(pcmp=sbuf_pathcmp(cb, p1b)))
	{
		int oldcompressed=0;
		if(cb->statp.st_mtime==p1b->statp.st_mtime
		  && cb->statp.st_ctime==p1b->statp.st_ctime)
		{
			// got an unchanged file
			//logp("got unchanged file: %s\n", cb->path);
			if(sbuf_to_manifest(cb, ucfp, NULL))
			{
				free_sbuf(cb);
				return -1;
			}
			else
			{
				do_filecounter(cntr, cmd_to_same(cb->cmd), 0);
			}
			if(cb->endfile) do_filecounter_bytes(cntr,
				 strtoull(cb->endfile, NULL, 10));
			free_sbuf(cb);
			return 1;
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
		// TODO: make unencrypted metadata use the librsync
		  || cb->cmd==CMD_METADATA
		  || p1b->cmd==CMD_METADATA)
		{
			if(process_new(p1b, p2fp, ucfp, cntr)) return -1;
			free_sbuf(cb);
			return 1;
		}

		// Get new files if they have switched between compression on
		// or off.
		if(cb->datapth && dpth_is_compressed(cb->datapth))
			oldcompressed=1;
		if( ( oldcompressed && !cconf->compression)
		 || (!oldcompressed &&  cconf->compression))
		{
			if(process_new(p1b, p2fp, ucfp, cntr)) return -1;
			free_sbuf(cb);
			return 1;
		}

		// Otherwise, do the delta stuff (if possible).
		if(filedata(p1b->cmd))
		{
			if(process_changed_file(cb, p1b, currentdata, cntr))
				return -1;
		}
		else
		{
			if(new_non_file(p1b, ucfp,
				cmd_to_changed(p1b->cmd), cntr))
					return -1;
		}
		free_sbuf(cb);
		return 1;
	}
	else if(pcmp>0)
	{
		//logp("ahead: %s\n", p1b->path);
		// ahead - need to get the whole file
		if(process_new(p1b, p2fp, ucfp, cntr)) return -1;
		// do not free
		return 1;
	}
	//logp("behind: %s\n", p1b->path);
	// behind - need to read more from the old
	// manifest
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
//logp("after rs_async: %d\n", sigresult);

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
	char deltmp[64]="";
	char *delpath=NULL;
	snprintf(deltmp, sizeof(deltmp), "deltas.forward/%s", rb->datapth);
	if(!(delpath=prepend_s(working, deltmp, strlen(deltmp)))
	  || mkpath(&delpath, working)
	  || do_rename(deltmppath, delpath))
		ret=-1;
	if(delpath) free(delpath);
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

				close_fp(&(rb->fp));
				gzclose_fp(&(rb->zp));
				rb->endfile=rbuf;
				rb->elen=rlen;
				rbuf=NULL;
				if(rb->receivedelta
				  && finish_delta(rb, working, deltmppath))
					ret=-1;
				else
				{
					if(sbuf_to_manifest(rb, p2fp, NULL))
						ret=-1;
					else
					{
					  char cmd=rb->cmd;
					  if(rb->receivedelta)
						cmd=cmd_to_changed(cmd);
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
		else if(rcmd==CMD_FILE
		  || rcmd==CMD_ENC_FILE
		  || rcmd==CMD_METADATA
		  || rcmd==CMD_ENC_METADATA)
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

	if(resume && do_resume(p1zp, p2fp, ucfp, cmanfp, dpth, cconf,
		p1cntr, cntr))
			goto error;

	logp("Begin phase2 (receive file data)\n");

	if(!(deltmppath=prepend_s(working, "delta.tmp", strlen("delta.tmp"))))
		goto error;

	while(1)
	{
		int sts=0;
		//logp("in loop, %s\n", *cmanfp?"got cmanfp":"no cmanfp");
		if(rb.path) write_status(client, STATUS_BACKUP,
			rb.path, p1cntr, cntr);
		else write_status(client, STATUS_BACKUP,
			p1b.path, p1cntr, cntr);
		if((last_requested || !p1zp)
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
			if(process_new(&p1b, p2fp, ucfp, cntr)) goto error;
		   }
		   else
		   {
			// Have an old manifest, look for it there.

			// Might already have it, or be ahead in the old
			// manifest.
			if(cb.path)
			{
				if((ars=maybe_process_file(&cb, &p1b,
					p2fp, ucfp,
					currentdata, cntr, cconf)))
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
					if(process_new(&p1b, p2fp, ucfp, cntr))
						goto error;
					break;
				}
		//logp("against: %s\n", cb.path);
				if((ars=maybe_process_file(&cb, &p1b,
					p2fp, ucfp, currentdata, cntr, cconf)))
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
	free(deltmppath);
	free_sbuf(&cb);
	free_sbuf(&p1b);
	free_sbuf(&rb);
	gzclose_fp(&p1zp);
	close_fp(&p2fp);
	close_fp(&ucfp);
	if(!ret) unlink(phase1data);

	logp("End phase2 (receive file data)\n");

	return ret;
}
