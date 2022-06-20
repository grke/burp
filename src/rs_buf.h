/*= -*- c-basic-offset: 4; indent-tabs-mode: nil; -*-
 *
 * librsync -- the library for network deltas
 * $Id: buf.h,v 1.8 2001/03/18 02:05:33 mbp Exp $
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
/* Modified by Graham Keeling, from 2011 */

#ifndef RS_BUF_H
#define RS_BUF_H

#include "burp.h"
#include "conf.h"
#include "bfile.h"

#include <librsync.h>
#include <openssl/md5.h>

extern size_t block_len;
extern size_t strong_len;

typedef struct rs_filebuf rs_filebuf_t;
struct rs_filebuf
{
	struct BFILE *bfd;
	struct fzp *fzp;
	char *buf;
	size_t buf_len;
	uint64_t bytes;
	size_t data_len;
	int do_known_byte_count;
	MD5_CTX *md5;
	struct asfd *asfd;
};

rs_filebuf_t *rs_filebuf_new(struct BFILE *bfd,
	struct fzp *fzp,
	struct asfd *asfd,
	size_t buf_len,
	size_t data_len);

void rs_filebuf_free(rs_filebuf_t **fb);

rs_result rs_infilebuf_fill(rs_job_t *job,
	rs_buffers_t *buf,
	void *opaque);
rs_result rs_outfilebuf_drain(rs_job_t *job,
	rs_buffers_t *buf,
	void *opaque);

rs_result rs_async(rs_job_t *job,
	rs_buffers_t *rsbuf, rs_filebuf_t *infb, rs_filebuf_t *outfb);

rs_result rs_patch_gzfile(struct fzp *basis_file,
	struct fzp *delta_file,
	struct fzp *new_file);
rs_result rs_sig_gzfile(struct fzp *old_file,
	struct fzp *sig_file,
	size_t new_block_len,
	size_t strong_len,
	struct conf **confs);
rs_result rs_delta_gzfile(rs_signature_t *sig,
	struct fzp *new_file,
	struct fzp *delta_file);

rs_result rs_loadsig_fzp(struct fzp *fzp,
	rs_signature_t **sig);

#ifndef RS_DEFAULT_STRONG_LEN
extern rs_magic_number rshash_to_magic_number(enum rshash r);
#endif

#define PROTO1_RS_STRONG_LEN 16

#endif
