#include "include.h"

static int load_signature(struct async *as,
	rs_signature_t **sumset, struct conf *conf)
{
	rs_result r;
	rs_job_t *job;

	job = rs_loadsig_begin(sumset);
	if((r=do_rs_run(as, job,
		NULL, NULL, NULL, NULL, NULL, as->asfd->fd, -1, conf->cntr)))
	{
		rs_free_sumset(*sumset);
		return r;
	}
	if((r=rs_build_hash_table(*sumset))) return r;
	rs_job_free(job);
	return r;
}

static int load_signature_and_send_delta(struct async *as,
	BFILE *bfd, FILE *in,
	unsigned long long *bytes, unsigned long long *sentbytes,
	struct conf *conf, size_t datalen)
{
	rs_job_t *job;
	rs_result r;
	rs_signature_t *sumset=NULL;
	unsigned char checksum[MD5_DIGEST_LENGTH+1];
	rs_filebuf_t *infb=NULL;
	rs_filebuf_t *outfb=NULL;
	rs_buffers_t rsbuf;
	memset(&rsbuf, 0, sizeof(rsbuf));

	if(load_signature(as, &sumset, conf)) return -1;

	if(!(job=rs_delta_begin(sumset)))
	{
		logp("could not start delta job.\n");
		rs_free_sumset(sumset);
		return RS_IO_ERROR;
	}

	if(!(infb=rs_filebuf_new(as, bfd,
		in, NULL, -1, ASYNC_BUF_LEN, datalen, conf->cntr))
	  || !(outfb=rs_filebuf_new(as, NULL, NULL,
		NULL, as->asfd->fd, ASYNC_BUF_LEN, -1, conf->cntr)))
	{
		logp("could not rs_filebuf_new for delta\n");
		if(infb) rs_filebuf_free(infb);
		return -1;
	}

	while(1)
	{
		rs_result delresult;
		delresult=rs_async(job, &rsbuf, infb, outfb);
		if(delresult==RS_DONE)
		{
			r=delresult;
			break;
		}
		else if(delresult==RS_BLOCKED || delresult==RS_RUNNING)
		{
			// Keep going
		}
		else
		{
			logp("error in rs_async for delta: %d\n", delresult);
			r=delresult;
			break;
		}
		// FIX ME: get it to read stuff (errors, for example) here too.
		if(as->rw(as, NULL, NULL)) return -1;
	}

	if(r!=RS_DONE)
		logp("delta loop returned: %d\n", r);

	if(r==RS_DONE)
	{
		*bytes=infb->bytes;
		*sentbytes=outfb->bytes;
		if(!MD5_Final(checksum, &(infb->md5)))
		{
			logp("MD5_Final() failed\n");
			r=RS_IO_ERROR;
		}
	}
	rs_filebuf_free(infb);
	rs_filebuf_free(outfb);
	rs_job_free(job);
	rs_free_sumset(sumset);

	if(r==RS_DONE && write_endfile(as, *bytes, checksum))
		return -1;

	return r;
}

static int send_whole_file_w(struct async *as,
	struct sbuf *sb, const char *datapth,
	int quick_read, unsigned long long *bytes, const char *encpassword,
	struct conf *conf, int compression, BFILE *bfd, FILE *fp,
	const char *extrameta, size_t elen, size_t datalen)
{
	if((compression || encpassword) && sb->path.cmd!=CMD_EFS_FILE)
		return send_whole_file_gzl(as,
		  sb->path.buf, datapth, quick_read, bytes, 
		  encpassword, conf, compression, bfd, fp, extrameta, elen,
		  datalen);
	else
		return send_whole_filel(as,
		  sb->path.cmd, sb->path.buf, datapth, quick_read, bytes, 
		  conf, bfd, fp, extrameta, elen,
		  datalen);
}

static int forget_file(struct async *as, struct sbuf *sb, struct conf *conf)
{
	// Tell the server to forget about this
	// file, otherwise it might get stuck
	// on a select waiting for it to arrive.
	if(as->write_str(as, CMD_INTERRUPT, sb->path.buf))
		return 0;

	if(sb->path.cmd==CMD_FILE && sb->burp1->datapth.buf)
	{
		rs_signature_t *sumset=NULL;
		// The server will be sending us a signature.
		// Munch it up then carry on.
		if(load_signature(as, &sumset, conf)) return -1;
		else rs_free_sumset(sumset);
	}
	return 0;
}

static int size_checks(struct async *as,
	struct iobuf *rbuf, struct sbuf *sb, struct conf *conf)
{
	if(rbuf->cmd!=CMD_FILE
	  && rbuf->cmd!=CMD_ENC_FILE
	  && rbuf->cmd!=CMD_EFS_FILE)
		return 0;
	if(conf->min_file_size
	  && sb->statp.st_size<(boffset_t)conf->min_file_size)
	{
		logw(as, conf, "File size decreased below min_file_size after initial scan: %c:%s", rbuf->cmd, sb->path.buf);
		return -1;
	}
	if(conf->max_file_size
	  && sb->statp.st_size>(boffset_t)conf->max_file_size)
	{
		logw(as, conf, "File size increased above max_file_size after initial scan: %c:%s", rbuf->cmd, sb->path.buf);
		return -1;
	}
	return 0;
}

static int deal_with_data(struct async *as,
	struct iobuf *rbuf, struct sbuf *sb,
	BFILE *bfd, size_t *datalen, struct conf *conf)
{
	int ret=-1;
	int forget=0;
	FILE *fp=NULL;
	size_t elen=0;
	char *extrameta=NULL;
	unsigned long long bytes=0;

	sb->compression=conf->compression;

	iobuf_copy(&sb->path, rbuf);
	rbuf->buf=NULL;

#ifdef HAVE_WIN32
	if(win32_lstat(sb->path.buf, &sb->statp, &sb->winattr))
#else
	if(lstat(sb->path.buf, &sb->statp))
#endif
	{
		logw(as, conf, "Path has vanished: %s", sb->path.buf);
		if(forget_file(as, sb, conf)) goto error;
		goto end;
	}

	if(size_checks(as, rbuf, sb, conf)) forget++;

	if(!forget)
	{
		sb->compression=in_exclude_comp(conf->excom,
			sb->path.buf, conf->compression);
		if(attribs_encode(sb)) goto error;
		else if(open_file_for_sendl(as,
#ifdef HAVE_WIN32
			bfd, NULL,
#else
			NULL, &fp,
#endif
			sb->path.buf, sb->winattr, datalen, conf->atime, conf))
				forget++;
	}

	if(forget)
	{
		if(forget_file(as, sb, conf)) goto error;
		goto end;
	}

	if(rbuf->cmd==CMD_METADATA
	  || rbuf->cmd==CMD_ENC_METADATA
	  || rbuf->cmd==CMD_VSS
	  || rbuf->cmd==CMD_ENC_VSS
#ifdef HAVE_WIN32
	  || conf->strip_vss
#endif
	  )
	{
		if(get_extrameta(as,
#ifdef HAVE_WIN32
			bfd,
#endif
			sb->path.buf, &sb->statp, &extrameta, &elen,
			sb->winattr, conf, datalen))
		{
			logw(as, conf, "Meta data error for %s", sb->path.buf);
			goto end;
		}
		if(extrameta)
		{
#ifdef HAVE_WIN32
			if(conf->strip_vss)
			{
				free(extrameta);
				extrameta=NULL;
				elen=0;
			}
#endif
		}
		else
		{
			logw(as, conf,
				"No meta data after all: %s", sb->path.buf);
			goto end;
		}
	}

	if(rbuf->cmd==CMD_FILE
	  && sb->burp1->datapth.buf)
	{
		unsigned long long sentbytes=0;
		// Need to do sig/delta stuff.
		if(as->write(as, &(sb->burp1->datapth))
		  || as->write(as, &sb->attr)
		  || as->write(as, &sb->path)
		  || load_signature_and_send_delta(as, bfd, fp,
			&bytes, &sentbytes, conf, *datalen))
		{
			logp("error in sig/delta for %s (%s)\n",
				sb->path.buf, sb->burp1->datapth.buf);
			goto end;
		}
		else
		{
			cntr_add(conf->cntr, CMD_FILE_CHANGED, 1);
			cntr_add_bytes(conf->cntr, bytes);
			cntr_add_sentbytes(conf->cntr, sentbytes);
		}
	}
	else
	{
		//logp("need to send whole file: %s\n", sb.path);
		// send the whole file.

		if((as->write(as, &sb->attr)
		  || as->write(as, &sb->path))
		  || send_whole_file_w(as, sb, NULL, 0, &bytes,
			conf->encryption_password, conf, sb->compression,
			bfd, fp, extrameta, elen, *datalen))
				goto end;
		else
		{
			cntr_add(conf->cntr, rbuf->cmd, 1);
			cntr_add_bytes(conf->cntr, bytes);
			cntr_add_sentbytes(conf->cntr, bytes);
		}
	}

end:
	ret=0;
error:
#ifdef HAVE_WIN32
	// If using Windows do not close bfd - it needs
	// to stay open to read VSS/file data/VSS.
	// It will get closed either when given a
	// different file path, or when this function
	// exits.
#else
	close_file_for_sendl(NULL, &fp, as);
#endif
	sbuf_free_content(sb);
	if(extrameta) free(extrameta);
	return ret;
}

static int parse_rbuf(struct async *as, struct iobuf *rbuf, struct sbuf *sb,
	BFILE *bfd, size_t *datalen, struct conf *conf)
{
	//logp("now: %c:%s\n", rbuf->cmd, rbuf->buf);
	if(rbuf->cmd==CMD_DATAPTH)
	{
		iobuf_copy(&(sb->burp1->datapth), rbuf);
		rbuf->buf=NULL;
	}
	else if(rbuf->cmd==CMD_ATTRIBS)
	{
		// Ignore the stat data - we will fill it
		// in again. Some time may have passed by now,
		// and it is best to make it as fresh as
		// possible.
	}
	else if(rbuf->cmd==CMD_FILE
	  || rbuf->cmd==CMD_ENC_FILE
	  || rbuf->cmd==CMD_METADATA
	  || rbuf->cmd==CMD_ENC_METADATA
	  || rbuf->cmd==CMD_VSS
	  || rbuf->cmd==CMD_ENC_VSS
	  || rbuf->cmd==CMD_VSS_T
	  || rbuf->cmd==CMD_ENC_VSS_T
	  || rbuf->cmd==CMD_EFS_FILE)
	{
		if(deal_with_data(as, rbuf, sb, bfd, datalen, conf))
			return -1;
	}
	else if(rbuf->cmd==CMD_WARNING)
	{
		cntr_add(conf->cntr, rbuf->cmd, 0);
	}
	else
	{
		iobuf_log_unexpected(rbuf, __FUNCTION__);
		return -1;
	}
	return 0;
}

static int do_backup_phase2_client(struct async *as,
	struct conf *conf, int resume)
{
	int ret=-1;
	// For efficiency, open Windows files for the VSS data, and do not
	// close them until another time around the loop, when the actual
	// data is read.
	BFILE bfd;
	// Windows VSS headers tell us how much file
	// data to expect.
	size_t datalen=0;
#ifdef HAVE_WIN32
	binit(&bfd, 0, conf);
#endif

	struct sbuf *sb=NULL;
	struct iobuf *rbuf=NULL;

	if(!(sb=sbuf_alloc(conf))) goto end;

	if(!resume)
	{
		// Only do this bit if the server did not tell us to resume.
		if(as->write_str(as, CMD_GEN, "backupphase2")
		  || as->read_expect(as, CMD_GEN, "ok"))
			goto end;
	}
	else if(conf->send_client_cntr)
	{
		// On resume, the server might update the client with cntr.
		if(cntr_recv(as, conf)) goto end;
	}

	if(!(rbuf=iobuf_alloc())) goto end;

	while(1)
	{
		iobuf_free_content(rbuf);
		if(as->read(as, rbuf)) goto end;
		else if(!rbuf->buf) continue;

		if(rbuf->cmd==CMD_GEN && !strcmp(rbuf->buf, "backupphase2end"))
		{
			if(as->write_str(as, CMD_GEN, "okbackupphase2end"))
				goto end;
			ret=0;
			break;
		}

		if(parse_rbuf(as, rbuf, sb, &bfd, &datalen, conf))
			goto end;
	}

end:
#ifdef HAVE_WIN32
	// It is possible for a bfd to still be open.
	close_file_for_sendl(&bfd, NULL, as);
#endif
	iobuf_free(rbuf);
	sbuf_free(sb);
	return ret;
}

int backup_phase2_client_burp1(struct async *as, struct conf *conf, int resume)
{
	int ret=0;

	logp("Phase 2 begin (send backup data)\n");

	ret=do_backup_phase2_client(as, conf, resume);

	cntr_print_end(conf->cntr);
	cntr_print(conf->cntr, ACTION_BACKUP);

	if(ret) logp("Error in phase 2\n");
	logp("Phase 2 end (send file data)\n");

	return ret;
}
