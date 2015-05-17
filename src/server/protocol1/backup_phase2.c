#include "include.h"
#include "../../cmd.h"
#include "../../conf.h"
#include "dpth.h"

static size_t treepathlen=0;

static int path_length_warn(struct iobuf *path, struct conf **cconfs)
{
	if(get_int(cconfs[OPT_PATH_LENGTH_WARN]))
		logw(NULL, cconfs, "Path too long for tree - will save in data structure instead: %s\n", path->buf);
	return 1;
}

static int path_too_long(struct iobuf *path, struct conf **cconfs)
{
	static const char *cp;
	if(treepathlen+path->len+1>fs_full_path_max)
	{
		// FIX THIS:
		// Cannot warn down the asfd to the client, because it can
		// arrive after the client has disconnected, which causes
		// an error on the server side.
		// Would need to change the way that "backupphase2end" works
		// to be able to fix it.
		return path_length_warn(path, cconfs);
	}
	if((cp=strrchr(path->buf, '/'))) cp++;
	else cp=path->buf;
	if(strlen(cp)>fs_name_max) return path_length_warn(path, cconfs);
	return 0;
}

static int treedata(struct sbuf *sb, struct conf **cconfs)
{
	// Windows is sending directory data as if it is file data - this
	// cannot be saved in a tree structure.
	// So, need to decode the stat to test for whether it is a directory.
	attribs_decode(sb);
	if(S_ISDIR(sb->statp.st_mode)) return 0;

	if(sb->path.cmd!=CMD_FILE
	  && sb->path.cmd!=CMD_ENC_FILE
	  && sb->path.cmd!=CMD_EFS_FILE)
		return 0;

	return !path_too_long(&sb->path, cconfs);
}

static char *set_new_datapth(struct asfd *asfd,
	struct sdirs *sdirs, struct conf **cconfs,
	struct sbuf *sb, struct dpth *dpth, int *istreedata)
{
	char *tmp=NULL;
	char *rpath=NULL;
	if(get_int(cconfs[OPT_DIRECTORY_TREE]))
		*istreedata=treedata(sb, cconfs);

	if(*istreedata)
	{
		// We want to place this file in a directory structure like
		// the directory structure on the original client.
		if(!(tmp=prepend_s(TREE_DIR, sb->path.buf)))
		{
			log_and_send_oom(asfd, __func__);
			return NULL;
		}
	}
	else
	{
		if(!(tmp=strdup_w(dpth_protocol1_mk(dpth,
			get_int(cconfs[OPT_COMPRESSION]),
			sb->path.cmd), __func__))) return NULL;
	}
	iobuf_from_str(&sb->protocol1->datapth, CMD_DATAPTH, tmp);
	if(build_path(sdirs->datadirtmp,
		sb->protocol1->datapth.buf, &rpath, sdirs->datadirtmp))
	{
		log_and_send(asfd, "build path failed");
		return NULL;
	}
	return rpath;
}

static int start_to_receive_new_file(struct asfd *asfd,
	struct sdirs *sdirs, struct conf **cconfs,
	struct sbuf *sb, struct dpth *dpth)
{
	char *rpath=NULL;
	int istreedata=0;

//logp("start to receive: %s\n", sb->path.buf);

	if(!(rpath=set_new_datapth(asfd,
		sdirs, cconfs, sb, dpth, &istreedata)))
			return -1;
	
	if(!(sb->protocol1->fp=open_file(rpath, "wb")))
	{
		log_and_send(asfd, "make file failed");
		if(rpath) free(rpath);
		return -1;
	}
	if(!istreedata) dpth_incr(dpth);
	if(rpath) free(rpath);
	return 0; 
}

static int process_changed_file(struct asfd *asfd,
	struct sdirs *sdirs, struct conf **cconfs,
	struct sbuf *cb, struct sbuf *p1b,
	const char *adir)
{
	size_t blocklen=0;
	char *curpath=NULL;
	//logp("need to process changed file: %s (%s)\n",
	//	cb->path, cb->datapth);

	// Move datapth onto p1b.
	iobuf_move(&p1b->protocol1->datapth, &cb->protocol1->datapth);

	if(!(curpath=prepend_s(adir, p1b->protocol1->datapth.buf)))
	{
		log_out_of_memory(__func__);
		return -1;
	}
	if(dpth_protocol1_is_compressed(cb->compression, curpath))
		p1b->protocol1->sigzp=gzopen_file(curpath, "rb");
	else
		p1b->protocol1->sigfp=open_file(curpath, "rb");
	if(!p1b->protocol1->sigzp && !p1b->protocol1->sigfp)
	{
		logp("could not open %s: %s\n", curpath, strerror(errno));
		free(curpath);
		return -1;
	}
	free(curpath);

	blocklen=get_librsync_block_len(cb->protocol1->endfile.buf);
	if(!(p1b->protocol1->sigjob=
#ifdef RS_DEFAULT_STRONG_LEN
		rs_sig_begin(blocklen, RS_DEFAULT_STRONG_LEN)
#else
		// This is for librsync-1.0.0. RS_DEFAULT_STRONG_LEN was 8 in
		// librsync-0.9.7.
		rs_sig_begin(blocklen, 8,
		  rshash_to_magic_number(get_e_rshash(cconfs[OPT_RSHASH])))
#endif
	))
	{
		logp("could not start signature job.\n");
		return -1;
	}
	//logp("sig begin: %s\n", p1b->protocol1->datapth.buf);
	if(!(p1b->protocol1->infb=rs_filebuf_new(asfd, NULL,
		p1b->protocol1->sigfp, p1b->protocol1->sigzp,
		-1, blocklen, -1, get_cntr(cconfs[OPT_CNTR]))))
	{
		logp("could not rs_filebuf_new for infb.\n");
		return -1;
	}
	if(!(p1b->protocol1->outfb=rs_filebuf_new(asfd, NULL, NULL, NULL,
		asfd->fd, ASYNC_BUF_LEN, -1, get_cntr(cconfs[OPT_CNTR]))))
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

static int new_non_file(struct sbuf *p1b, FILE *ucfp, struct conf **cconfs)
{
	// Is something that does not need more data backed up.
	// Like a directory or a link or something like that.
	// Goes into the unchanged file, so that it does not end up out of
	// order with normal files, which has to wait around for their data
	// to turn up.
	if(sbufl_to_manifest(p1b, ucfp, NULL))
		return -1;
	else
		cntr_add(get_cntr(cconfs[OPT_CNTR]), p1b->path.cmd, 0);
	sbuf_free_content(p1b);
	return 0;
}

static int changed_non_file(struct sbuf *p1b,
	FILE *ucfp, enum cmd cmd, struct conf **cconfs)
{
	// As new_non_file.
	if(sbufl_to_manifest(p1b, ucfp, NULL))
		return -1;
	else
		cntr_add_changed(get_cntr(cconfs[OPT_CNTR]), cmd);
	sbuf_free_content(p1b);
	return 0;
}

static int process_new(struct sdirs *sdirs, struct conf **cconfs,
	struct sbuf *p1b, FILE *ucfp)
{
	if(!p1b->path.buf) return 0;
	if(cmd_is_filedata(p1b->path.cmd))
	{
		//logp("need to process new file: %s\n", p1b->path);
		// Flag the things that need to be sent (to the client)
		p1b->flags |= SBUFL_SEND_STAT;
		p1b->flags |= SBUFL_SEND_PATH;
	}
	else
	{
		new_non_file(p1b, ucfp, cconfs);
	}
	return 0;
}

static int process_unchanged_file(struct sbuf *p1b, struct sbuf *cb,
	FILE *ucfp, struct conf **cconfs)
{
	// Need to re-encode the p1b attribs to include compression and
	// other bits and pieces that are recorded on cb.
	iobuf_move(&p1b->protocol1->datapth, &cb->protocol1->datapth);
	iobuf_move(&p1b->protocol1->endfile, &cb->protocol1->endfile);
	p1b->compression=cb->compression;
	if(attribs_encode(p1b))
		return -1;
	if(sbufl_to_manifest(p1b, ucfp, NULL))
		return -1;
	cntr_add_same(get_cntr(cconfs[OPT_CNTR]), p1b->path.cmd);
	if(p1b->protocol1->endfile.buf) cntr_add_bytes(
		get_cntr(cconfs[OPT_CNTR]),
		 strtoull(p1b->protocol1->endfile.buf, NULL, 10));
	sbuf_free_content(cb);
	return 1;
}

static int process_new_file(struct sdirs *sdirs, struct conf **cconfs,
	struct sbuf *cb, struct sbuf *p1b, FILE *ucfp)
{
	if(process_new(sdirs, cconfs, p1b, ucfp))
		return -1;
	sbuf_free_content(cb);
	return 1;
}

static int maybe_do_delta_stuff(struct asfd *asfd,
	struct sdirs *sdirs, struct sbuf *cb, struct sbuf *p1b, FILE *ucfp,
	struct conf **cconfs)
{
	int oldcompressed=0;
	int compression=get_int(cconfs[OPT_COMPRESSION]);

	// If the file type changed, I think it is time to back it up again
	// (for example, EFS changing to normal file, or back again).
	if(cb->path.cmd!=p1b->path.cmd)
		return process_new_file(sdirs, cconfs, cb, p1b, ucfp);

	// mtime is the actual file data.
	// ctime is the attributes or meta data.
	if(cb->statp.st_mtime==p1b->statp.st_mtime
	  && cb->statp.st_ctime==p1b->statp.st_ctime)
	{
		// got an unchanged file
		//logp("got unchanged file: %s %c %c\n",
		//	cb->path.buf, cb->path.cmd, p1b->path.cmd);
		return process_unchanged_file(p1b, cb, ucfp, cconfs);
	}

	if(cb->statp.st_mtime==p1b->statp.st_mtime
	  && cb->statp.st_ctime!=p1b->statp.st_ctime)
	{
		// File data stayed the same, but attributes or meta data
		// changed. We already have the attributes, but may need to get
		// extra meta data.
		// FIX THIS horrible mess.
		if(cb->path.cmd==CMD_ENC_METADATA
		  || p1b->path.cmd==CMD_ENC_METADATA
		// FIX THIS: make unencrypted metadata use the librsync
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
			return process_new_file(sdirs, cconfs, cb, p1b, ucfp);
		// On Windows, we have to back up the whole file if ctime
		// changed, otherwise things like permission changes do not get
		// noticed. So, in that case, fall through to the changed stuff
		// below.
		// Non-Windows clients finish here.
		else if(!get_int(cconfs[OPT_CLIENT_IS_WINDOWS]))
			return process_unchanged_file(p1b, cb, ucfp, cconfs);
	}

	// Got a changed file.
	//logp("got changed file: %s\n", p1b->path);

	// If either old or new is encrypted, or librsync is off, we need to
	// get a new file.
	// FIX THIS horrible mess.
	if(get_int(cconfs[OPT_LIBRSYNC])
	  || cb->path.cmd==CMD_ENC_FILE
	  || p1b->path.cmd==CMD_ENC_FILE
	  || cb->path.cmd==CMD_ENC_METADATA
	  || p1b->path.cmd==CMD_ENC_METADATA
	  || cb->path.cmd==CMD_EFS_FILE
	  || p1b->path.cmd==CMD_EFS_FILE
	// FIX THIS: make unencrypted metadata use the librsync
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
		return process_new_file(sdirs, cconfs, cb, p1b, ucfp);

	// Get new files if they have switched between compression on or off.
	if(cb->protocol1->datapth.buf
	  && dpth_protocol1_is_compressed(cb->compression,
	    cb->protocol1->datapth.buf))
		oldcompressed=1;
	if( ( oldcompressed && !compression)
	 || (!oldcompressed &&  compression))
		return process_new_file(sdirs, cconfs, cb, p1b, ucfp);

	// Otherwise, do the delta stuff (if possible).
	if(cmd_is_filedata(p1b->path.cmd))
	{
		if(process_changed_file(asfd, sdirs, cconfs, cb, p1b,
			sdirs->currentdata)) return -1;
	}
	else
	{
		if(changed_non_file(p1b, ucfp, p1b->path.cmd, cconfs))
			return -1;
	}
	sbuf_free_content(cb);
	return 1;
}

// return 1 to say that a file was processed
static int maybe_process_file(struct asfd *asfd,
	struct sdirs *sdirs, struct sbuf *cb, struct sbuf *p1b, FILE *ucfp,
	struct conf **cconfs)
{
	switch(sbuf_pathcmp(cb, p1b))
	{
		case 0:
			return maybe_do_delta_stuff(asfd, sdirs, cb, p1b,
				ucfp, cconfs);
		case 1:
			//logp("ahead: %s\n", p1b->path);
			// ahead - need to get the whole file
			if(process_new(sdirs, cconfs, p1b, ucfp))
				return -1;
			// Do not free.
			return 1;
		case -1:
		default:
			//logp("behind: %s\n", p1b->path);
			// Behind - need to read more from the old manifest.
			// Count a deleted file - it was in the old manifest
			// but not the new.
			cntr_add_deleted(get_cntr(cconfs[OPT_CNTR]),
				cb->path.cmd);
			return 0;
	}
}

// Return 1 if there is still stuff needing to be sent.
// FIX THIS: lots of repeated code.
static int do_stuff_to_send(struct asfd *asfd,
	struct sbuf *p1b, char **last_requested)
{
	static struct iobuf wbuf;
	if(p1b->flags & SBUFL_SEND_DATAPTH)
	{
		iobuf_copy(&wbuf, &p1b->protocol1->datapth);
		switch(asfd->append_all_to_write_buffer(asfd, &wbuf))
		{
			case APPEND_OK: break;
			case APPEND_BLOCKED: return 1;
			default: return -1;
		}
		p1b->flags &= ~SBUFL_SEND_DATAPTH;
	}
	if(p1b->flags & SBUFL_SEND_STAT)
	{
		iobuf_copy(&wbuf, &p1b->attr);
		switch(asfd->append_all_to_write_buffer(asfd, &wbuf))
		{
			case APPEND_OK: break;
			case APPEND_BLOCKED: return 1;
			default: return -1;
		}
		p1b->flags &= ~SBUFL_SEND_STAT;
	}
	if(p1b->flags & SBUFL_SEND_PATH)
	{
		iobuf_copy(&wbuf, &p1b->path);
		switch(asfd->append_all_to_write_buffer(asfd, &wbuf))
		{
			case APPEND_OK: break;
			case APPEND_BLOCKED: return 1;
			default: return -1;
		}
		p1b->flags &= ~SBUFL_SEND_PATH;
		if(*last_requested) free(*last_requested);
		if(!(*last_requested=strdup_w(p1b->path.buf, __func__)))
			return -1;
	}
	if(p1b->protocol1->sigjob && !(p1b->flags & SBUFL_SEND_ENDOFSIG))
	{
		rs_result sigresult;

		switch((sigresult=rs_async(p1b->protocol1->sigjob,
			&(p1b->protocol1->rsbuf),
			p1b->protocol1->infb, p1b->protocol1->outfb)))
		{
			case RS_DONE:
				p1b->flags |= SBUFL_SEND_ENDOFSIG;
				break;
			case RS_BLOCKED:
			case RS_RUNNING:
				// keep going round the loop.
				return 1;
			default:
				logp("error in rs_async: %d\n", sigresult);
				return -1;
		}
	}
	if(p1b->flags & SBUFL_SEND_ENDOFSIG)
	{
		iobuf_from_str(&wbuf, CMD_END_FILE, (char *)"endfile");
		switch(asfd->append_all_to_write_buffer(asfd, &wbuf))
		{
			case APPEND_OK: break;
			case APPEND_BLOCKED: return 1;
			default: return -1;
		}
		p1b->flags &= ~SBUFL_SEND_ENDOFSIG;
	}
	return 0;
}

static int start_to_receive_delta(struct sdirs *sdirs, struct conf **cconfs,
	struct sbuf *rb)
{
	if(get_int(cconfs[OPT_COMPRESSION]))
	{
		if(!(rb->protocol1->zp=gzopen_file(sdirs->deltmppath,
			comp_level(cconfs))))
				return -1;
	}
	else
	{
		if(!(rb->protocol1->fp=open_file(sdirs->deltmppath, "wb")))
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
	if(!(deltmp=prepend_s("deltas.forward", rb->protocol1->datapth.buf))
	  || !(delpath=prepend_s(sdirs->working, deltmp))
	  || mkpath(&delpath, sdirs->working)
	// Rename race condition is of no consequence here, as delpath will
	// just get recreated.
	  || do_rename(sdirs->deltmppath, delpath))
		ret=-1;
	if(delpath) free(delpath);
	if(deltmp) free(deltmp);
	return ret;
}

static int deal_with_receive_end_file(struct asfd *asfd, struct sdirs *sdirs,
	struct sbuf *rb, FILE *chfp, struct conf **cconfs, char **last_requested)
{
	static char *cp=NULL;
	static struct iobuf *rbuf;
	rbuf=asfd->rbuf;
	// Finished the file.
	// Write it to the phase2 file, and free the buffers.

	if(close_fp(&(rb->protocol1->fp)))
	{
		logp("error closing delta for %s in receive\n", rb->path);
		goto error;
	}
	if(gzclose_fp(&(rb->protocol1->zp)))
	{
		logp("error gzclosing delta for %s in receive\n", rb->path);
		goto error;
	}
	iobuf_move(&rb->protocol1->endfile, rbuf);
	if(rb->flags & SBUFL_RECV_DELTA && finish_delta(sdirs, rb))
		goto error;

	if(sbufl_to_manifest(rb, chfp, NULL))
		goto error;

	if(rb->flags & SBUFL_RECV_DELTA)
		cntr_add_changed(get_cntr(cconfs[OPT_CNTR]), rb->path.cmd);
	else
		cntr_add(get_cntr(cconfs[OPT_CNTR]), rb->path.cmd, 0);

	if(*last_requested && !strcmp(rb->path.buf, *last_requested))
	{
		free(*last_requested);
		*last_requested=NULL;
	}

	cp=strchr(rb->protocol1->endfile.buf, ':');
	if(rb->protocol1->endfile.buf)
		cntr_add_bytes(get_cntr(cconfs[OPT_CNTR]),
			strtoull(rb->protocol1->endfile.buf, NULL, 10));
	if(cp)
	{
		// checksum stuff goes here
	}

	sbuf_free_content(rb);
	return 0;
error:
	sbuf_free_content(rb);
	return -1;
}

static int deal_with_receive_append(struct asfd *asfd, struct sbuf *rb,
	struct conf **cconfs)
{
	int app=0;
	static struct iobuf *rbuf;
	rbuf=asfd->rbuf;
	//logp("rbuf->len: %d\n", rbuf->len);

	cntr_add_recvbytes(get_cntr(cconfs[OPT_CNTR]), rbuf->len);
	if(rb->protocol1->zp)
		app=gzwrite(rb->protocol1->zp, rbuf->buf, rbuf->len);
	else if(rb->protocol1->fp)
		app=fwrite(rbuf->buf, 1, rbuf->len, rb->protocol1->fp);

	if(app>0) return 0;
	logp("error when appending: %d\n", app);
	asfd->write_str(asfd, CMD_ERROR, "write failed");
	return -1;
}

static int deal_with_filedata(struct asfd *asfd,
	struct sdirs *sdirs, struct sbuf *rb,
	struct iobuf *rbuf, struct dpth *dpth, struct conf **cconfs)
{
	iobuf_move(&rb->path, rbuf);

	if(rb->protocol1->datapth.buf)
	{
		// Receiving a delta.
		if(start_to_receive_delta(sdirs, cconfs, rb))
		{
			logp("error in start_to_receive_delta\n");
			return -1;
		}
		return 0;
	}

	// Receiving a whole new file.
	if(start_to_receive_new_file(asfd, sdirs, cconfs, rb, dpth))
	{
		logp("error in start_to_receive_new_file\n");
		return -1;
	}
	return 0;
}

// returns 1 for finished ok.
static int do_stuff_to_receive(struct asfd *asfd,
	struct sdirs *sdirs, struct conf **cconfs,
	struct sbuf *rb, FILE *chfp,
	struct dpth *dpth, char **last_requested)
{
	struct iobuf *rbuf=asfd->rbuf;

	iobuf_free_content(rbuf);
	// This also attempts to write anything in the write buffer.
	if(asfd->as->read_write(asfd->as))
	{
		logp("error in %s\n", __func__);
		return -1;
	}

	if(!rbuf->buf) return 0;

	if(rbuf->cmd==CMD_MESSAGE
	  || rbuf->cmd==CMD_WARNING)
	{
		log_recvd(rbuf, cconfs, 0);
		return 0;
	}

	if(rb->protocol1->fp || rb->protocol1->zp)
	{
		// Currently writing a file (or meta data)
		switch(rbuf->cmd)
		{
			case CMD_APPEND:
				if(deal_with_receive_append(asfd, rb, cconfs))
					goto error;
				return 0;
			case CMD_END_FILE:
				if(deal_with_receive_end_file(asfd, sdirs, rb,
					chfp, cconfs, last_requested))
						goto error;
				return 0;
			default:
				iobuf_log_unexpected(rbuf, __func__);
				goto error;
		}
	}

	// Otherwise, expecting to be told of a file to save.
	switch(rbuf->cmd)
	{
		case CMD_DATAPTH:
			iobuf_move(&rb->protocol1->datapth, rbuf);
			return 0;
		case CMD_ATTRIBS:
			iobuf_move(&rb->attr, rbuf);
			return 0;
		case CMD_GEN:
			if(!strcmp(rbuf->buf, "okbackupphase2end"))
				goto end_phase2;
			iobuf_log_unexpected(rbuf, __func__);
			goto error;
		case CMD_INTERRUPT:
			// Interrupt - forget about the last requested
			// file if it matches. Otherwise, we can get
			// stuck on the select in the async stuff,
			// waiting for something that will never arrive.
			if(*last_requested
			  && !strcmp(rbuf->buf, *last_requested))
				free_w(last_requested);
			return 0;
		default:
			break;
	}
	if(cmd_is_filedata(rbuf->cmd))
	{
		if(deal_with_filedata(asfd, sdirs, rb, rbuf, dpth, cconfs))
			goto error;
		return 0;
	}
	iobuf_log_unexpected(rbuf, __func__);

error:
	return -1;
end_phase2:
	return 1;
}

static int vss_opts_changed(struct sdirs *sdirs, struct conf **cconfs,
	const char *incexc)
{
	int ret=-1;
	struct conf **oldconfs;
	struct conf **newconfs;
	if(!(oldconfs=confs_alloc())
	  || !(newconfs=confs_alloc()))
		goto end;
	confs_init(oldconfs);
	confs_init(newconfs);

	// Figure out the old config, which is in the incexc file left
	// in the current backup directory on the server.
	if(conf_parse_incexcs_path(oldconfs, sdirs->cincexc))
	{
		// Assume that the file did not exist, and therefore
		// the old split_vss setting is 0.
		set_int(oldconfs[OPT_SPLIT_VSS], 0);
		set_int(oldconfs[OPT_STRIP_VSS], 0);
	}

	// Figure out the new config, which is either in the incexc file from
	// the client, or in the cconf on the server.
	if(incexc)
	{
		if(conf_parse_incexcs_buf(newconfs, incexc))
		{
			// Should probably not got here.
			set_int(newconfs[OPT_SPLIT_VSS], 0);
			set_int(newconfs[OPT_STRIP_VSS], 0);
		}
	}
	else
	{
		set_int(newconfs[OPT_SPLIT_VSS],
			get_int(cconfs[OPT_SPLIT_VSS]));
		set_int(newconfs[OPT_STRIP_VSS],
			get_int(cconfs[OPT_STRIP_VSS]));
	}

	if(get_int(newconfs[OPT_SPLIT_VSS])!=get_int(oldconfs[OPT_SPLIT_VSS]))
	{
		logp("split_vss=%d (changed since last backup)\n",
			get_int(newconfs[OPT_SPLIT_VSS]));
		ret=1; goto end;
	}
	if(get_int(newconfs[OPT_STRIP_VSS])!=get_int(oldconfs[OPT_STRIP_VSS]))
	{
		logp("strip_vss=%d (changed since last backup)\n",
			get_int(newconfs[OPT_STRIP_VSS]));
		ret=1; goto end;
	}
	ret=0;
end:
	if(ret==1) logp("All files will be treated as new\n");
	confs_free(&oldconfs);
	confs_free(&newconfs);
	return ret;
}

// Open the previous (current) manifest.
// If the split_vss setting changed between the previous backup and the new
// backup, do not open the previous manifest. This will have the effect of
// making the client back up everything fresh. Need to do this, otherwise
// toggling split_vss on and off will result in backups that do not work.
static int open_previous_manifest(gzFile *cmanfp,
	struct sdirs *sdirs, const char *incexc, struct conf **cconfs)
{
	struct stat statp;
	if(!lstat(sdirs->cmanifest, &statp)
	  && !vss_opts_changed(sdirs, cconfs, incexc)
	  && !(*cmanfp=gzopen_file(sdirs->cmanifest, "rb")))
	{
		logp("could not open old manifest %s\n", sdirs->cmanifest);
		return -1;
	}
	return 0;
}

int backup_phase2_server_protocol1(struct async *as, struct sdirs *sdirs,
	const char *incexc, int resume, struct conf **cconfs)
{
	int ret=0;
	gzFile p1zp=NULL;
	struct dpth *dpth=NULL;
	char *deltmppath=NULL;
	char *last_requested=NULL;
	// Where to write changed data.
	// Data is not getting written to a compressed file.
	// This is important for recovery if the power goes.
	FILE *chfp=NULL;
	FILE *ucfp=NULL; // unchanged data
	gzFile cmanfp=NULL; // previous (current) manifest.
	struct sbuf *cb=NULL; // file list in current manifest
	struct sbuf *p1b=NULL; // file list from client
	struct sbuf *rb=NULL; // receiving file from client
	struct asfd *asfd=as->asfd;
	int breaking=0;
	int breakcount=0;
	if(get_int(cconfs[OPT_BREAKPOINT])>=2000
	  && get_int(cconfs[OPT_BREAKPOINT])<3000)
	{
		breaking=get_int(cconfs[OPT_BREAKPOINT]);
		breakcount=breaking-2000;
	}

	logp("Begin phase2 (receive file data)\n");

	if(!(dpth=dpth_alloc())
	  || dpth_protocol1_init(dpth, sdirs->currentdata,
		get_int(cconfs[OPT_MAX_STORAGE_SUBDIRS])))
			goto error;

	if(open_previous_manifest(&cmanfp, sdirs, incexc, cconfs))
		goto error;

	if(get_int(cconfs[OPT_DIRECTORY_TREE]))
	{
		// Need to make sure we do not try to create a path that is
		// too long.
		if(build_path_w(sdirs->treepath)) goto error;
		treepathlen=strlen(sdirs->treepath);
		init_fs_max(sdirs->treepath);
	}

	if(!(cb=sbuf_alloc(cconfs))
	  || !(p1b=sbuf_alloc(cconfs))
	  || !(rb=sbuf_alloc(cconfs)))
		goto error;

	if(!(p1zp=gzopen_file(sdirs->phase1data, "rb")))
		goto error;

	if(resume && do_resume(p1zp, sdirs, dpth, cconfs))
		goto error;

	// Unchanged and changed should now be truncated correctly, we just
	// have to open them for appending.
	if(!(ucfp=open_file(sdirs->unchanged, "a+b"))
	  || !(chfp=open_file(sdirs->changed, "a+b")))
		goto error;

	while(1)
	{
		if(breaking)
		{
			if(breakcount--==0) return breakpoint(cconfs, __func__);
		}

		//printf("in loop, %s %s %c\n",
		//	*cmanfp?"got cmanfp":"no cmanfp",
		//	rb->path.buf?:"no rb->path",
	 	//	rb->path.buf?'X':rb->path.cmd);
		if(write_status(CNTR_STATUS_BACKUP,
			rb->path.buf?rb->path.buf:p1b->path.buf, cconfs))
				goto error;
		if(last_requested || !p1zp || asfd->writebuflen)
		{
			switch(do_stuff_to_receive(asfd, sdirs,
				cconfs, rb, chfp, dpth, &last_requested))
			{
				case 0: break;
				case 1: goto end; // Finished ok.
				case -1: goto error;
			}
		}

		switch(do_stuff_to_send(asfd, p1b, &last_requested))
		{
			case 0: break;
			case 1: continue;
			case -1: goto error;
		}

		if(!p1zp) continue;

		sbuf_free_content(p1b);

		switch(sbufl_fill_phase1(p1b, NULL, p1zp, cconfs))
		{
			case 0: break;
			case 1: gzclose_fp(&p1zp);
				if(asfd->write_str(asfd,
					CMD_GEN, "backupphase2end")) goto error;
				break;
			case -1: goto error;
		}

		if(!cmanfp)
		{
			// No old manifest, need to ask for a new file.
			if(process_new(sdirs, cconfs, p1b, ucfp))
				goto error;
			continue;
		}

		// Have an old manifest, look for it there.

		// Might already have it, or be ahead in the old
		// manifest.
		if(cb->path.buf) switch(maybe_process_file(asfd,
			sdirs, cb, p1b, ucfp, cconfs))
		{
			case 0: break;
			case 1: continue;
			case -1: goto error;
		}

		while(cmanfp)
		{
			sbuf_free_content(cb);
			switch(sbufl_fill(cb, asfd, NULL, cmanfp, cconfs))
			{
				case 0: break;
				case 1: gzclose_fp(&cmanfp);
					if(process_new(sdirs, cconfs, p1b,
						ucfp)) goto error;
					continue;
				case -1: goto error;
			}
			switch(maybe_process_file(asfd, sdirs,
				cb, p1b, ucfp, cconfs))
			{
				case 0: continue;
				case 1: break;
				case -1: goto error;
			}
			break;
		}
	}

error:
	ret=-1;
end:
	if(close_fp(&chfp))
	{
		logp("error closing %s in %s\n", sdirs->changed, __func__);
		ret=-1;
	}
	if(close_fp(&ucfp))
	{
		logp("error closing %s in %s\n", sdirs->unchanged, __func__);
		ret=-1;
	}
	free_w(&deltmppath);
	sbuf_free(&cb);
	sbuf_free(&p1b);
	sbuf_free(&rb);
	gzclose_fp(&p1zp);
	gzclose_fp(&cmanfp);
	dpth_free(&dpth);
	if(!ret) unlink(sdirs->phase1data);

	logp("End phase2 (receive file data)\n");

	return ret;
}
