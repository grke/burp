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
#include "backup_phase2_server.h"

static int start_to_receive_new_file(struct sbuf *sb, const char *datadirtmp, struct dpth *dpth, struct cntr *cntr)
{
	int ret=0;
	char *rpath=NULL;

//logp("start to receive: %s\n", sb->path);

	if(!(sb->datapth=strdup(dpth->path)))
	{
		log_and_send("out of memory");
		ret=-1;
	}
	else if(build_path(datadirtmp, sb->datapth, strlen(sb->datapth),&rpath))
	{
		log_and_send("build path failed");
		ret=-1;
	}
	else if(!(sb->fp=open_file(rpath, "wb9")))
	{
		log_and_send("make file failed");
		ret=-1;
	}
	if(rpath) free(rpath);
	incr_dpth(dpth);
	return ret;
}

static int process_changed_file(struct sbuf *cb, struct sbuf *p1b, const char *currentdata, struct cntr *cntr)
{
	char *curpath=NULL;
	//logp("need to process changed file: %s (%s)\n", cb->path, cb->datapth);

	// Move datapth onto p1b.
	p1b->datapth=cb->datapth;
	cb->datapth=NULL;

	if(!(curpath=prepend_s(currentdata, p1b->datapth, strlen(p1b->datapth))))
	{
		logp("out of memory\n");
		return -1;
	}
	if(!(p1b->sigfp=gzopen_file(curpath, "rb9")))
	{
		logp("could not open %s: %s\n", curpath, strerror(errno));
		free(curpath);
		return -1;
	}
	free(curpath);

	if(!(p1b->sigjob=rs_sig_begin(block_len, strong_len)))
	{
		logp("could not start signature job.\n");
		return -1;
	}
//logp("sig begin: %s\n", p1b->datapth);
	if(!(p1b->infb=rs_filebuf_new(NULL, NULL, p1b->sigfp, -1, rs_inbuflen, cntr)))
	{
		logp("could not rs_filebuf_new for infb.\n");
		return -1;
	}
	if(!(p1b->outfb=rs_filebuf_new(NULL, NULL, NULL, async_get_fd(), rs_outbuflen, cntr)))
	{
		logp("could not rs_filebuf_new for in_outfb.\n");
		return -1;
	}

	// Flag the things that need to be sent.
	p1b->senddatapth++;
	p1b->sendstat++;
	p1b->sendpath++;

	//logp("sending sig for %s\n", p1b->path);
	//logp("(%s)\n", p1b->datapth);

	return 0;
}

static int process_new_file(struct sbuf *p1b)
{
	//logp("need to process new file: %s\n", p1b->path);
	// Flag the things that need to be sent.
	p1b->sendstat++;
	p1b->sendpath++;
	return 0;
}

// return 1 to say that a file was processed
static int maybe_process_file(struct sbuf *cb, struct sbuf *p1b, gzFile uczp, const char *currentdata, struct cntr *cntr, struct config *cconf)
{
	int pcmp;
	if(!(pcmp=pathcmp(cb->path, p1b->path)))
	{
		if(cb->statp.st_mtime==p1b->statp.st_mtime
		  && cb->statp.st_ctime==p1b->statp.st_ctime)
		{
			// got an unchanged file
			//logp("got unchanged file: %s\n", cb->path);
			if(sbuf_to_manifest(cb, NULL, uczp))
			{
				free_sbuf(cb);
				return -1;
			}
			do_filecounter_bytes(cntr,
				 strtoull(cb->endfile, NULL, 10));
			free_sbuf(cb);
			return 1;
		}

		// Got a changed file.

		// If either old or new is encrypted, or librsync is off,
		// we need to get a new file.
		if(!cconf->librsync
		  || sbuf_is_encrypted_file(cb)
		  || sbuf_is_encrypted_file(p1b))
		{
			if(process_new_file(p1b)) return -1;
			free_sbuf(cb);
			return 1;
		}

		// Otherwise, do the delta stuff.
		if(process_changed_file(cb, p1b, currentdata, cntr)) return -1;
		free_sbuf(cb);
		return 1;
	}
	else if(pcmp>0)
	{
		// ahead - need to get the whole file
		if(process_new_file(p1b)) return -1;
		// do not free
		return 1;
	}
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
		if(async_append_all_to_write_buffer('t', p1b->datapth, &l))
			return 1;
		p1b->senddatapth=0;
		//if(async_rw(NULL, NULL, NULL, NULL, NULL, &junk)) return -1;
	}
	if(p1b->sendstat)
	{
		size_t l=p1b->slen;
		if(async_append_all_to_write_buffer('r', p1b->statbuf, &l))
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
		if(async_append_all_to_write_buffer('x', endfile, &l))
			return 1;
		//if(async_rw(NULL, NULL, NULL, NULL, NULL, &junk)) return -1;
		p1b->sendendofsig=0;
	}
	return 0;
}

static int start_to_receive_delta(struct sbuf *rb, const char *working, const char *deltmppath)
{
	if(!(rb->zp=gzopen_file(deltmppath, "wb9"))) return -1;
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
	  || mkpath(&delpath)
	  || do_rename(deltmppath, delpath))
		ret=-1;
	if(delpath) free(delpath);
	return ret;
}

// returns 1 for finished ok.
static int do_stuff_to_receive(struct sbuf *rb, FILE *p2fp, const char *datadirtmp, struct dpth *dpth, const char *working, char **last_requested, const char *deltmppath, struct cntr *cntr)
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
		if(rcmd=='w')
		{
			logp("WARNING: %s\n", rbuf);
			do_filecounter(cntr, rcmd, 0);
		}
		else if(rb->fp || rb->zp)
		{
			// Currently writing a file.
			if(rcmd=='a')
			{
				int app;
				//logp("rlen: %d\n", rlen);
				if((rb->zp
				  && (app=gzwrite(rb->zp, rbuf, rlen))<=0)
				|| (rb->fp
				  && (app=fwrite(rbuf, 1, rlen, rb->fp))<=0))
				{
					logp("error when appending: %d\n", app);
					async_write_str('e', "write failed");
					ret=-1;
				}
				do_filecounter_recvbytes(cntr, rlen);
			}
			else if(rcmd=='x')
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
					  do_filecounter(cntr, rb->receivedelta?'x':'F', 0);
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
		else if(rcmd=='t')
		{
			rb->datapth=rbuf;
			rbuf=NULL;
		}
		else if(rcmd=='r')
		{
			rb->statbuf=rbuf;
			rb->slen=rlen;
			rbuf=NULL;
		}
		else if(rcmd=='f' || rcmd=='y')
		{
			rb->cmd=rcmd;
			rb->plen=rlen;
			rb->path=rbuf;
			rbuf=NULL;

			if(rb->datapth)
			{
				// Receiving a delta.
				if(start_to_receive_delta(rb,
				  working, deltmppath))
				{
					logp("error in start_to_receive_delta\n");
					ret=-1;
				}
			}
			else
			{
				// Receiving a whole new file.
				if(start_to_receive_new_file(rb,
					datadirtmp, dpth, cntr))
				{
					logp("error in start_to_receive_new_file\n");
					ret=-1;
				}
			}
		}
		else if(rcmd=='c' && !strcmp(rbuf, "okbackupphase2end"))
		{
			ret=1;
			logp("got okbackupphase2end\n");
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

int backup_phase2_server(gzFile *cmanfp, const char *phase1data, FILE *p2fp, gzFile uczp, const char *datadirtmp, struct dpth *dpth, const char *currentdata, const char *working, const char *client, struct cntr *cntr, struct config *cconf)
{
	int ars=0;
	int ret=0;
	int quit=0;
	gzFile p1zp=NULL;
	char *deltmppath=NULL;
	char *last_requested=NULL;

	struct sbuf cb;		// file list in current manifest
	struct sbuf p1b;	// file list from client

	struct sbuf rb;		// receiving file from client

	logp("Begin phase2 (receive file data)\n");

	init_sbuf(&cb);
	init_sbuf(&p1b);
	init_sbuf(&rb);

	if(!(p1zp=gzopen_file(phase1data, "rb9")))
		return -1;

	if(!(deltmppath=prepend_s(working, "delta.tmp", strlen("delta.tmp"))))
		return -1;

	while(!quit)
	{
		int sts=0;
		//logp("in loop\n");
		if(rb.path) write_status(client, 2, rb.path, cntr);
		else write_status(client, 2, p1b.path, cntr);
		if((last_requested || !p1zp)
		  && (ars=do_stuff_to_receive(&rb, p2fp, datadirtmp, dpth,
			working, &last_requested, deltmppath, cntr)))
		{
			if(ars<0) ret=-1;
			// 1 means ok.
			break;
		}

		if((sts=do_stuff_to_send(&p1b, &last_requested))<0)
		{
			ret=-1;
			break;
		}

		if(!sts && p1zp)
		{
		   while(p1zp)
		   {
			free_sbuf(&p1b);

			if((ars=sbuf_fill_phase1(NULL, p1zp, &p1b, cntr)))
			{
				if(ars<0) { ret=-1; quit++; } // error
				// ars==1 means it ended ok.
				gzclose_fp(&p1zp);
				//free_sbuf(&p1b);
				if(async_write_str('c', "backupphase2end"))
				break;
			}

			if(sbuf_is_file(&p1b) || sbuf_is_encrypted_file(&p1b))
				break;

			// If it is not file data, we are not currently
			// interested. Write it to the unchanged file.
			if(sbuf_to_manifest(&p1b, NULL, uczp))
			{
				ret=-1; quit++;
			}
		   }
		   if(ret || !p1zp) continue;

		   //logp("check: %s\n", p1b.path);

		   // If it is file data...
		   if(!*cmanfp)
		   {
			// No old manifest, need to ask for a new file.
			//logp("no cmanfp\n");
			if(process_new_file(&p1b)) return -1;
		   }
		   else
		   {
			// Have an old manifest, look for it there.

			// Might already have it, or be ahead in the old
			// manifest.
			if(cb.path)
			{
				if((ars=maybe_process_file(&cb, &p1b, uczp,
					currentdata, cntr, cconf)))
				{
					if(ars<0)
					{
						ret=-1;
						quit++;
						break;
					}
					// Do not free it - need to send stuff.
					continue;
				}
				//free_sbuf(&p1b);
			}

			while(*cmanfp)
			{
		//logp("in loop x\n");
				free_sbuf(&cb);
				if((ars=sbuf_fill(NULL, *cmanfp, &cb, cntr)))
				{
					if(ars<0) // error
					{
						ret=-1;
						quit++;
						break;
					}
					// ars==1 means it ended ok.
					gzclose_fp(cmanfp);
		//logp("ran out of current manifest\n");
					if(process_new_file(&p1b)) return -1;
					break;
				}
		//logp("against: %s\n", cb.path);
				if(!sbuf_is_file(&cb)
				  && !sbuf_is_encrypted_file(&cb))
				{
					free_sbuf(&cb);
					continue;
				}
				if((ars=maybe_process_file(&cb, &p1b, uczp,
					currentdata, cntr, cconf)))
				{
					if(ars<0)
					{
						ret=-1;
						quit++;
						break;
					}
					// Do not free it - need to send stuff.
					break;
				}
			}
		   }
		}
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
