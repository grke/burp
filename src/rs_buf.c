/*= -*- c-basic-offset: 4; indent-tabs-mode: nil; -*-
 *
 * librsync -- the library for network deltas
 * $Id: buf.c,v 1.22 2003/12/16 00:10:55 abo Exp $
 * 
 * Copyright (C) 2000, 2001 by Martin Pool <mbp@samba.org>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

                              /*
                               | Pick a window, Jimmy, you're leaving.
                               |   -- Martin Schwenke, regularly
                               */


/*
 * buf.c -- Buffers that map between stdio file streams and librsync
 * streams.  As the stream consumes input and produces output, it is
 * refilled from appropriate input and output FILEs.  A dynamically
 * allocated buffer of configurable size is used as an intermediary.
 */

#include "burp.h"
#include "rs_buf.h"
#include "cmd.h"
#include "alloc.h"
#include "asfd.h"
#include "async.h"
#include "handy.h"
#include "iobuf.h"
#include "log.h"
#include "md5.h"

/* use fseeko instead of fseek for long file support if we have it */
#ifdef HAVE_FSEEKO
#define fseek fseeko
#endif

rs_filebuf_t *rs_filebuf_new(struct BFILE *bfd,
	struct fzp *fzp,
	struct asfd *asfd,
	size_t buf_len,
	size_t data_len)
{
	rs_filebuf_t *pf=NULL;
	if(!(pf=(struct rs_filebuf *)calloc_w(1,
		sizeof(struct rs_filebuf), __func__))
	  || !(pf->buf=(char *)calloc_w(1, buf_len, __func__))
	  || !(pf->md5=md5_alloc(__func__)))
		goto error;
	pf->buf_len=buf_len;
	pf->fzp=fzp;
	pf->bfd=bfd;
	pf->bytes=0;
	pf->data_len=data_len;
	if(data_len>0)
		pf->do_known_byte_count=1;
	else
		pf->do_known_byte_count=0;
	if(!md5_init(pf->md5))
	{
		logp("md5_init() failed\n");
		goto error;
	}
	pf->asfd=asfd;
	return pf;
error:
	rs_filebuf_free(&pf);
	return NULL;
}

void rs_filebuf_free(rs_filebuf_t **fb) 
{
	if(!fb || !*fb) return;
	md5_free(&((*fb)->md5));
	free_w(&((*fb)->buf));
	free_v((void **)fb);
}

/*
 * If the stream has no more data available, read some from F into
 * BUF, and let the stream use that.  On return, SEEN_EOF is true if
 * the end of file has passed into the stream.
 */
rs_result rs_infilebuf_fill(__attribute__ ((unused)) rs_job_t *job,
	rs_buffers_t *buf, void *opaque)
{
	int len=0;
	rs_filebuf_t *fb=(rs_filebuf_t *) opaque;

	//logp("rs_infilebuf_fill\n");

	/* This is only allowed if either the buf has no input buffer
	 * yet, or that buffer could possibly be BUF. */
	if(buf->next_in)
	{
		//logp("infilebuf avail_in %d buf_len %d\n",
		//	buf->avail_in, fb->buf_len);
		if(buf->avail_in > fb->buf_len)
		{
			logp("buf->avail_in > fb->buf_len (%lu > %lu) in %s\n",
				(unsigned long)buf->avail_in,
				(unsigned long)fb->buf_len, __func__);
			return RS_IO_ERROR;
		}
		if(buf->next_in < fb->buf)
		{
			logp("buf->next_in < fb->buf in %s\n", __func__);
			return RS_IO_ERROR;
		}
		if(buf->next_in > fb->buf + fb->buf_len)
		{
			logp("buf->next_in > fb->buf + fb->buf_len in %s\n",
				__func__);
			return RS_IO_ERROR;
		}
	}
	else
	{
		if(buf->avail_in)
		{
			logp("buf->avail_in is %lu in %s\n",
				(unsigned long)buf->avail_in, __func__);
			return RS_IO_ERROR;
		}
	}

	if(buf->eof_in)
		return RS_DONE;

	if(buf->avail_in)
		/* Still some data remaining.  Perhaps we should read
		   anyhow? */
		return RS_DONE;

	if(fb->asfd)
	{
		static struct iobuf *rbuf=NULL;
		rbuf=fb->asfd->rbuf;

		switch(rbuf->cmd)
		{
			case CMD_APPEND:
				memcpy(fb->buf, rbuf->buf, rbuf->len);
				len=rbuf->len;
				break;
			case CMD_END_FILE:
				buf->eof_in=1;
				return RS_DONE;
			default:
				iobuf_log_unexpected(rbuf, __func__);
				return RS_IO_ERROR;
		}
	}
	else if(fb->bfd)
	{
		if(fb->do_known_byte_count)
		{
			if(fb->data_len>0)
			{
				len=fb->bfd->read(fb->bfd, fb->buf,
					min(fb->buf_len, fb->data_len));
				fb->data_len-=len;
			}
			else
			{
				// We have already read as much data as the VSS
				// header told us to, so set len=0 in order to
				// finish up.
				len=0;
			}
		}
		else
			len=fb->bfd->read(fb->bfd, fb->buf, fb->buf_len);
		if(len==0)
		{
			//logp("bread: eof\n");
			buf->eof_in=1;
			return RS_DONE;
		}
		else if(len<0)
		{
			logp("rs_infilebuf_fill: error in bread: %s\n",
				strerror(errno));
			return RS_IO_ERROR;
		}
		//logp("bread: ok: %d\n", len);
		fb->bytes+=len;
		if(!md5_update(fb->md5, fb->buf, len))
		{
			logp("rs_infilebuf_fill: md5_update() failed\n");
			return RS_IO_ERROR;
		}
	}
	else if(fb->fzp)
	{
		if((len=fzp_read(fb->fzp, fb->buf, fb->buf_len))<=0)
		{
			// This will happen if file size is a multiple of
			// input block len.
			if(fzp_eof(fb->fzp))
			{
				buf->eof_in=1;
				return RS_DONE;
			}
			else
			{
				logp("rs_infilebuf_fill: got return %d when trying to read\n", len);
				return RS_IO_ERROR;
			}
		}
		fb->bytes+=len;
		if(!md5_update(fb->md5, fb->buf, len))
		{
			logp("rs_infilebuf_fill: md5_update() failed\n");
			return RS_IO_ERROR;
		}
	}

	buf->avail_in = len;
	buf->next_in = fb->buf;

	return RS_DONE;
}

/*
 * The buf is already using BUF for an output buffer, and probably
 * contains some buffered output now.  Write this out to F, and reset
 * the buffer cursor.
 */
rs_result rs_outfilebuf_drain(__attribute__ ((unused)) rs_job_t *job,
	rs_buffers_t *buf, void *opaque)
{
	rs_filebuf_t *fb=(rs_filebuf_t *)opaque;
	size_t wlen;

	//logp("in rs_outfilebuf_drain\n");

	/* This is only allowed if either the buf has no output buffer
	 * yet, or that buffer could possibly be BUF. */
	if(!buf->next_out)
	{
		if(buf->avail_out)
		{
			logp("buf->avail_out is %lu in %s\n",
				(unsigned long)buf->avail_out, __func__);
			return RS_IO_ERROR;
		}
		buf->next_out = fb->buf;
		buf->avail_out = fb->buf_len;
		return RS_DONE;
	}

	if(buf->avail_out > fb->buf_len)
	{
		logp("buf->avail_out > fb->buf_len (%lu > %lu) in %s\n",
			(unsigned long)buf->avail_out,
			(unsigned long)fb->buf_len, __func__);
		return RS_IO_ERROR;
	}
	if(buf->next_out < fb->buf)
	{
		logp("buf->next_out < fb->buf (%p < %p) in %s\n",
			buf->next_out, fb->buf, __func__);
		return RS_IO_ERROR;
	}
	if(buf->next_out > fb->buf + fb->buf_len)
	{
		logp("buf->next_out > fb->buf + fb->buf_len in %s\n",
			__func__);
		return RS_IO_ERROR;
	}

	if((wlen=buf->next_out-fb->buf)>0)
	{
		//logp("wlen: %d\n", wlen);
		if(fb->asfd)
		{
			size_t w=wlen;
			struct iobuf wbuf;
			iobuf_set(&wbuf, CMD_APPEND, fb->buf, wlen);
			switch(fb->asfd->append_all_to_write_buffer(
				fb->asfd, &wbuf))
			{
				case APPEND_OK: break;
				case APPEND_BLOCKED: return RS_BLOCKED;
				case APPEND_ERROR:
				default: return RS_IO_ERROR;
			}
			fb->bytes+=w;
		}
		else
		{
			size_t result=0;
			result=fzp_write(fb->fzp, fb->buf, wlen);
			if(wlen!=result)
			{
				logp("error draining buf to file: %s",
						strerror(errno));
				return RS_IO_ERROR;
			}
		}
	}

	buf->next_out = fb->buf;
	buf->avail_out = fb->buf_len;

	return RS_DONE;
}

static rs_result rs_async_drive(rs_job_t *job, rs_buffers_t *rsbuf,
	rs_driven_cb in_cb, void *in_opaque,
	rs_driven_cb out_cb, void *out_opaque)
{
	rs_result result;
	rs_result iores;

	if(!rsbuf->eof_in && in_cb)
	{
		iores=in_cb(job, rsbuf, in_opaque);
		if(iores!=RS_DONE) return iores;
	}

	result=rs_job_iter(job, rsbuf);
	if(result!=RS_DONE && result!=RS_BLOCKED)
		return result;

	if(out_cb)
	{
		iores=(out_cb)(job, rsbuf, out_opaque);
		if(iores!=RS_DONE) return iores;
	}

	return result;
}

rs_result rs_async(rs_job_t *job, rs_buffers_t *rsbuf,
	rs_filebuf_t *infb, rs_filebuf_t *outfb)
{
	return rs_async_drive(job, rsbuf,
		infb ? rs_infilebuf_fill : NULL, infb,
		outfb ? rs_outfilebuf_drain : NULL, outfb);
}

static rs_result rs_whole_gzrun(
	rs_job_t *job, struct fzp *in_file, struct fzp *out_file)
{
	rs_buffers_t buf;
	rs_result result;
	rs_filebuf_t *in_fb=NULL;
	rs_filebuf_t *out_fb=NULL;

	if(in_file)
		in_fb=rs_filebuf_new(NULL,
			in_file, NULL, ASYNC_BUF_LEN, -1);
	if(out_file)
		out_fb=rs_filebuf_new(NULL,
			out_file, NULL, ASYNC_BUF_LEN, -1);

	result=rs_job_drive(job, &buf,
		in_fb ? rs_infilebuf_fill : NULL, in_fb,
		out_fb ? rs_outfilebuf_drain : NULL, out_fb);

	rs_filebuf_free(&in_fb);
	rs_filebuf_free(&out_fb);
	return result;
}

rs_result rs_patch_gzfile(struct fzp *basis_file,
	struct fzp *delta_file, struct fzp *new_file)
{
	rs_job_t *job;
	rs_result r;

	// FIX THIS: Seems wrong to just pick out basis_file->fp.
	// Should probably pass a fp into rs_patch_gzfile.
	// Or, much better would be to investigate whether basis_file always
	// needs to be a FILE *. If I copy rs_file_copy_cb from librsync, and
	// rewrite it to use a struct fzp, maybe the callers to rs_patch_gzfile
	// do not need to mess around inflating files when they do not have
	// to.
	job=rs_patch_begin(rs_file_copy_cb, basis_file->fp);
	r=rs_whole_gzrun(job, delta_file, new_file);
	rs_job_free(job);

	return r;
}

rs_result rs_sig_gzfile(struct fzp *old_file, struct fzp *sig_file,
	size_t new_block_len, size_t strong_len,
	struct conf **confs)
{
	rs_job_t *job;
	rs_result r;
	job=
		rs_sig_begin(new_block_len, strong_len
#ifndef RS_DEFAULT_STRONG_LEN
                  	, rshash_to_magic_number(
				get_e_rshash(confs[OPT_RSHASH]))
#endif
		);

	r=rs_whole_gzrun(job, old_file, sig_file);
	rs_job_free(job);

	return r;
}

rs_result rs_delta_gzfile(rs_signature_t *sig, struct fzp *new_file,
	struct fzp *delta_file)
{
	rs_job_t *job;
	rs_result r;

	job=rs_delta_begin(sig);
	r=rs_whole_gzrun(job, new_file, delta_file);
	rs_job_free(job);

	return r;
}

#ifndef RS_DEFAULT_STRONG_LEN
rs_magic_number rshash_to_magic_number(enum rshash r)
{
	switch(r)
	{
		case RSHASH_BLAKE2:
			return RS_BLAKE2_SIG_MAGIC;
		default:
			return RS_MD4_SIG_MAGIC;
	}
}
#endif

rs_result rs_loadsig_fzp(struct fzp *fzp, rs_signature_t **sig)
{
	rs_result r;
	rs_job_t *job;

	job=rs_loadsig_begin(sig);
	r=rs_whole_gzrun(job, fzp, NULL);
	rs_job_free(job);

	return r;
}
