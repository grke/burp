#include "../burp.h"
#include "../action.h"
#include "../alloc.h"
#include "../asfd.h"
#include "../async.h"
#include "../attribs.h"
#include "../cmd.h"
#include "../cntr.h"
#include "../conf.h"
#include "../handy_extra.h"
#include "../log.h"
#include "../transfer.h"
#include "extrameta.h"
#include "find.h"
#include "backup_phase2.h"

static int rs_loadsig_network_run(struct asfd *asfd,
	rs_job_t *job, struct cntr *cntr)
{
	int ret=-1;
	rs_buffers_t buf;
	rs_result result;
	rs_filebuf_t *in_fb=NULL;
	memset(&buf, 0, sizeof(buf));

	if(!(in_fb=rs_filebuf_new(NULL,
		NULL, asfd, ASYNC_BUF_LEN, -1)))
		goto end;

	while(1)
	{
		iobuf_free_content(asfd->rbuf);
		if(asfd->read(asfd)) goto end;
		if(asfd->rbuf->cmd==CMD_MESSAGE
		  || asfd->rbuf->cmd==CMD_WARNING)
		{
			log_recvd(asfd->rbuf, cntr, 0);
			continue;
		}
		switch((result=rs_async(job, &buf, in_fb, NULL)))
		{
			case RS_BLOCKED:
			case RS_RUNNING:
				continue;
			case RS_DONE:
				ret=0;
				goto end;
			default:
				logp("error in rs_async for sig: %d\n",
					result);
				goto end;
		}
	}

end:
	iobuf_free_content(asfd->rbuf);
	rs_filebuf_free(&in_fb);
	return ret;
}

static int load_signature(struct asfd *asfd,
	rs_signature_t **sumset, struct cntr *cntr)
{
	rs_job_t *job;

	if(!(job=rs_loadsig_begin(sumset)))
	{
		logp("could not start sig job.\n");
		return -1;
	}
	if(rs_loadsig_network_run(asfd, job, cntr))
		return -1;
	if(rs_build_hash_table(*sumset))
		return -1;
	rs_job_free(job);
	return 0;
}

static int load_signature_and_send_delta(struct asfd *asfd,
	struct BFILE *bfd, uint64_t *bytes, uint64_t *sentbytes,
	struct cntr *cntr)
{
	int ret=-1;
	rs_job_t *job=NULL;
	rs_signature_t *sumset=NULL;
	uint8_t checksum[MD5_DIGEST_LENGTH];
	rs_filebuf_t *infb=NULL;
	rs_filebuf_t *outfb=NULL;
	rs_buffers_t rsbuf;
	memset(&rsbuf, 0, sizeof(rsbuf));

	if(load_signature(asfd, &sumset, cntr))
		goto end;

	if(!(job=rs_delta_begin(sumset)))
	{
		logp("could not start delta job.\n");
		goto end;
	}

	if(!(infb=rs_filebuf_new(bfd,
		NULL, NULL, ASYNC_BUF_LEN, bfd->datalen))
	  || !(outfb=rs_filebuf_new(NULL,
		NULL, asfd, ASYNC_BUF_LEN, -1)))
	{
		logp("could not rs_filebuf_new for delta\n");
		goto end;
	}

	while(1)
	{
		rs_result result;
		switch((result=rs_async(job, &rsbuf, infb, outfb)))
		{
			case RS_DONE:
				*bytes=infb->bytes;
				*sentbytes=outfb->bytes;
				if(!MD5_Final(checksum, infb->md5))
				{
					logp("MD5_Final() failed\n");
					goto end;
				}
				if(write_endfile(asfd, *bytes, checksum))
					goto end;
				ret=0;
				goto end;
			case RS_BLOCKED:
			case RS_RUNNING:
				// FIX ME: get it to read stuff here too.
				// (errors, for example)
				if(asfd->as->write(asfd->as))
					goto end;
				continue;
			default:
				logp("error in rs_async for delta: %d\n",
					result);
				goto end;
		}
	}
end:
	rs_filebuf_free(&infb);
	rs_filebuf_free(&outfb);
	if(job) rs_job_free(job);
	if(sumset) rs_free_sumset(sumset);
	return ret;
}

static enum send_e send_whole_file_w(struct asfd *asfd,
	struct sbuf *sb, const char *datapth,
	int quick_read, uint64_t *bytes, const char *encpassword,
	struct cntr *cntr, int compression, struct BFILE *bfd,
	const char *extrameta, size_t elen)
{
	if((compression || encpassword) && sb->path.cmd!=CMD_EFS_FILE)
	{
		int key_deriv=sb->encryption==ENCRYPTION_KEY_DERIVED;

		return send_whole_file_gzl(asfd, datapth, quick_read, bytes,
		  encpassword, cntr, compression, bfd, extrameta, elen,
		  key_deriv, sb->salt);
	}
	else
		return send_whole_filel(asfd,
#ifdef HAVE_WIN32
		  sb->path.cmd,
#endif
		  datapth, quick_read, bytes,
		  cntr, bfd, extrameta, elen);
}

static int forget_file(struct asfd *asfd, struct sbuf *sb, struct conf **confs)
{
	// Tell the server to forget about this
	// file, otherwise it might get stuck
	// on a select waiting for it to arrive.
	if(asfd->write_str(asfd, CMD_INTERRUPT, sb->path.buf))
		return 0;

	if(sb->path.cmd==CMD_FILE && sb->datapth.buf)
	{
		rs_signature_t *sumset=NULL;
		// The server will be sending us a signature.
		// Munch it up then carry on.
		if(load_signature(asfd, &sumset, get_cntr(confs))) return -1;
		else rs_free_sumset(sumset);
	}
	return 0;
}

static int size_checks(struct asfd *asfd, struct sbuf *sb, struct conf **confs)
{
	if(sb->path.cmd!=CMD_FILE
	  && sb->path.cmd!=CMD_ENC_FILE
	  && sb->path.cmd!=CMD_EFS_FILE)
		return 0;
	if(get_uint64_t(confs[OPT_MIN_FILE_SIZE])
	  && (uint64_t)sb->statp.st_size<get_uint64_t(confs[OPT_MIN_FILE_SIZE]))
	{
		logw(asfd, get_cntr(confs), "File size decreased below min_file_size after initial scan: %s\n", iobuf_to_printable(&sb->path));
		return -1;
	}
	if(get_uint64_t(confs[OPT_MAX_FILE_SIZE])
	  && (uint64_t)sb->statp.st_size>get_uint64_t(confs[OPT_MAX_FILE_SIZE]))
	{
		logw(asfd, get_cntr(confs), "File size increased above max_file_size after initial scan: %s\n", iobuf_to_printable(&sb->path));
		return -1;
	}
	return 0;
}

static int deal_with_data(struct asfd *asfd, struct sbuf *sb,
	struct BFILE *bfd, struct conf **confs)
{
	int ret=-1;
	int forget=0;
	size_t elen=0;
	char *extrameta=NULL;
	uint64_t bytes=0;
	int conf_compression=get_int(confs[OPT_COMPRESSION]);
	struct cntr *cntr=get_cntr(confs);
	const char *enc_password=get_string(confs[OPT_ENCRYPTION_PASSWORD]);

	sb->compression=conf_compression;
	if(enc_password)
	{
		sb->encryption=ENCRYPTION_KEY_DERIVED;
		if(!RAND_bytes((uint8_t *)&sb->salt, 8))
		{
			logp("RAND_bytes() failed\n");
			return -1;
		}
	}

	iobuf_copy(&sb->path, asfd->rbuf);
	iobuf_init(asfd->rbuf);

#ifdef HAVE_WIN32
	if(win32_lstat(sb->path.buf, &sb->statp, &sb->winattr))
#else
	if(lstat(sb->path.buf, &sb->statp))
#endif
	{
		logw(asfd, cntr, "Path has vanished: %s\n",
			iobuf_to_printable(&sb->path));
		forget++;
		goto end;
	}

	if(size_checks(asfd, sb, confs))
	{
		forget++;
		goto end;
	}

	sb->compression=in_exclude_comp(get_strlist(confs[OPT_EXCOM]),
		sb->path.buf, conf_compression);
	if(attribs_encode(sb)) goto error;

	if(sb->path.cmd!=CMD_METADATA
	  && sb->path.cmd!=CMD_ENC_METADATA)
	{
		if(bfd->open_for_send(bfd, asfd,
			sb->path.buf, sb->winattr,
			get_int(confs[OPT_ATIME]), cntr))
		{
			forget++;
			goto end;
		}
	}

	if(sb->path.cmd==CMD_METADATA
	  || sb->path.cmd==CMD_ENC_METADATA
	  || sb->path.cmd==CMD_VSS
	  || sb->path.cmd==CMD_ENC_VSS
#ifdef HAVE_WIN32
	  || get_int(confs[OPT_STRIP_VSS])
#endif
	  )
	{
		if(get_extrameta(asfd,
#ifdef HAVE_WIN32
			bfd,
#endif
			sb->path.buf,
			S_ISDIR(sb->statp.st_mode),
			&extrameta, &elen, cntr))
		{
			logw(asfd, cntr,
				"Meta data error for %s\n",
				iobuf_to_printable(&sb->path));
			forget++;
			goto end;
		}
		if(extrameta)
		{
#ifdef HAVE_WIN32
	  		if(get_int(confs[OPT_STRIP_VSS]))
			{
				free_w(&extrameta);
				elen=0;
			}
#endif
		}
		else
		{
			logw(asfd, cntr,
				"No meta data after all: %s\n",
				iobuf_to_printable(&sb->path));
			forget++;
			goto end;
		}
	}

	if(sb->path.cmd==CMD_FILE
	  && sb->datapth.buf)
	{
		uint64_t sentbytes=0;
		// Need to do sig/delta stuff.
		if(asfd->write(asfd, &(sb->datapth))
		  || asfd->write(asfd, &sb->attr)
		  || asfd->write(asfd, &sb->path)
		  || load_signature_and_send_delta(asfd, bfd,
			&bytes, &sentbytes, cntr))
		{
			logp("error in sig/delta for %s (%s)\n",
				iobuf_to_printable(&sb->path),
				iobuf_to_printable(&sb->datapth));
			forget++;
			goto end;
		}
		cntr_add(cntr, CMD_FILE_CHANGED, 1);
	}
	else
	{
		//logp("need to send whole file: %s\n", sb.path);
		// send the whole file.

		if(asfd->write(asfd, &sb->attr)
		  || asfd->write(asfd, &sb->path))
			goto end;

		switch(send_whole_file_w(asfd, sb, NULL, 0, &bytes,
			enc_password,
			cntr, sb->compression,
			bfd, extrameta, elen))
		{
			case SEND_OK:
				break;
			case SEND_ERROR:
				forget++;
				break;
			case SEND_FATAL:
			default:
				goto error;
		}
		cntr_add(cntr, sb->path.cmd, 1);
	}
	cntr_add_bytes(cntr, bytes);

end:
	ret=0;
	if(forget && forget_file(asfd, sb, confs))
		ret=-1;
error:
#ifdef HAVE_WIN32
	// If using Windows do not close bfd - it needs
	// to stay open to read VSS/file data/VSS.
	// It will get closed either when given a
	// different file path, or when this function
	// exits.
#else
	bfd->close(bfd, asfd);
#endif
	sbuf_free_content(sb);
	free_w(&extrameta);
	return ret;
}

static int parse_rbuf(struct asfd *asfd, struct sbuf *sb,
	struct BFILE *bfd, struct conf **confs)
{
	static struct iobuf *rbuf;
	rbuf=asfd->rbuf;
	if(rbuf->cmd==CMD_DATAPTH)
	{
		iobuf_move(&(sb->datapth), rbuf);
	}
	else if(rbuf->cmd==CMD_ATTRIBS)
	{
		// Ignore the stat data - we will fill it
		// in again. Some time may have passed by now,
		// and it is best to make it as fresh as
		// possible.
	}
	else if(iobuf_is_filedata(rbuf)
	  || iobuf_is_vssdata(rbuf))
	{
		if(deal_with_data(asfd, sb, bfd, confs))
			return -1;
	}
	else if(rbuf->cmd==CMD_MESSAGE
	  || rbuf->cmd==CMD_WARNING)
	{
		struct cntr *cntr=NULL;
		if(confs) cntr=get_cntr(confs);
		log_recvd(rbuf, cntr, 0);
	}
	else
	{
		iobuf_log_unexpected(rbuf, __func__);
		return -1;
	}
	return 0;
}

static int do_backup_phase2_client(struct asfd *asfd,
	struct conf **confs, int resume)
{
	int ret=-1;
	// For efficiency, open Windows files for the VSS data, and do not
	// close them until another time around the loop, when the actual
	// data is read.
	struct BFILE *bfd=NULL;
	struct sbuf *sb=NULL;
	struct iobuf *rbuf=NULL;
	struct cntr *cntr=NULL;
	if(confs) cntr=get_cntr(confs);

	if(!asfd)
	{
		logp("%s() called without asfd!\n", __func__);
		goto end;
	}
	rbuf=asfd->rbuf;

	if(!(bfd=bfile_alloc())
	  || !(sb=sbuf_alloc()))
		goto end;
	bfile_init(bfd, 0, cntr);

	if(!resume)
	{
		// Only do this bit if the server did not tell us to resume.
		if(asfd->write_str(asfd, CMD_GEN, "backupphase2")
		  || asfd_read_expect(asfd, CMD_GEN, "ok"))
			goto end;
	}
	else
	{
		// On resume, the server might update the client with cntr.
		if(cntr_recv(asfd, confs))
			goto end;
	}

	while(1)
	{
		iobuf_free_content(rbuf);
		if(asfd->read(asfd)) goto end;
		else if(!rbuf->buf) continue;

		if(rbuf->cmd==CMD_GEN && !strcmp(rbuf->buf, "backupphase2end"))
		{
			if(asfd->write_str(asfd, CMD_GEN, "okbackupphase2end"))
				goto end;
			ret=0;
			break;
		}

		if(parse_rbuf(asfd, sb, bfd, confs))
			goto end;
	}

end:
	// It is possible for a bfd to still be open.
	if(bfd) bfd->close(bfd, asfd);
	bfile_free(&bfd);
	iobuf_free_content(rbuf);
	sbuf_free(&sb);
	return ret;
}

int backup_phase2_client(struct asfd *asfd,
	struct conf **confs, int resume)
{
	int ret=0;
	struct cntr *cntr=NULL;
	if(confs) cntr=get_cntr(confs);

	logp("Phase 2 begin (send backup data)\n");
	logfmt("\n");

	ret=do_backup_phase2_client(asfd, confs, resume);

	cntr_print_end(cntr);
	cntr_set_bytes(cntr, asfd);
	cntr_print(cntr, ACTION_BACKUP);

	if(ret) logp("Error in phase 2\n");
	logp("Phase 2 end (send file data)\n");

	return ret;
}
