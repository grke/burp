#include "include.h"

int send_msg_fp(FILE *fp, char cmd, const char *buf, size_t s)
{
	if(fprintf(fp, "%c%04X", cmd, (unsigned int)s)!=5
	  || fwrite(buf, 1, s, fp)!=s
	  || fprintf(fp, "\n")!=1)
	{
		logp("Unable to write message to file: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

int send_msg_zp(gzFile zp, char cmd, const char *buf, size_t s)
{
	if(gzprintf(zp, "%c%04X", cmd, s)!=5
	  || gzwrite(zp, buf, s)!=(int)s
	  || gzprintf(zp, "\n")!=1)
	{
		logp("Unable to write message to compressed file\n");
		return -1;
	}
	return 0;
}

static int do_write(struct asfd *asfd, BFILE *bfd,
	uint8_t *out, size_t outlen, unsigned long long *sent)
{
	int ret=0;
	if((ret=bfd->write(bfd, out, outlen))<=0)
	{
		logp("%s: error when appending %d: %d\n",
			__func__, outlen, ret);
		asfd->write_str(asfd, CMD_ERROR, "write failed");
		return -1;
	}
	*sent+=outlen;
	return 0;
}

static int do_inflate(struct asfd *asfd, z_stream *zstrm, BFILE *bfd,
	uint8_t *out, unsigned long long *sent)
{
	int zret=Z_OK;
	unsigned have=0;
	struct iobuf *rbuf=asfd->rbuf;

	zstrm->avail_in=rbuf->len;
	zstrm->next_in=(uint8_t *)rbuf->buf;

	do
	{
		zstrm->avail_out=ZCHUNK;
		zstrm->next_out=out;
		zret=inflate(zstrm, Z_NO_FLUSH);
		switch(zret)
		{
			case Z_NEED_DICT:
				zret=Z_DATA_ERROR;
			case Z_DATA_ERROR:
			case Z_MEM_ERROR:
				logp("zstrm inflate error: %d\n", zret);
				return -1;
		}
		have=ZCHUNK-zstrm->avail_out;
		if(!have) continue;

		if(do_write(asfd, bfd, out, have, sent))
			return -1;
	} while(!zstrm->avail_out);
	return 0;
}

int transfer_gzfile_in(struct asfd *asfd, const char *path, BFILE *bfd,
	unsigned long long *rcvd, unsigned long long *sent, struct cntr *cntr)
{
	int quit=0;
	int ret=-1;
	uint8_t out[ZCHUNK];
	struct iobuf *rbuf=asfd->rbuf;
	z_stream zstrm;

	zstrm.zalloc=Z_NULL;
	zstrm.zfree=Z_NULL;
	zstrm.opaque=Z_NULL;
	zstrm.avail_in=0;
	zstrm.next_in=Z_NULL;

	if(inflateInit2(&zstrm, (15+16)))
	{
		logp("unable to init inflate\n");
		goto end;
	}

	while(!quit)
	{
		iobuf_free_content(rbuf);
		if(asfd->read(asfd)) goto end_inflate;
		(*rcvd)+=rbuf->len;

		//logp("transfer in: %c:%s\n", rbuf->cmd, rbuf->buf);
		switch(rbuf->cmd)
		{
			case CMD_APPEND: // append
				if(!bfd)
				{
					logp("given append, but no file to write to\n");
					asfd->write_str(asfd, CMD_ERROR,
						"append with no file");
					goto end_inflate;
				}
				else
				{
					if(do_inflate(asfd, &zstrm,
						bfd, out, sent))
							goto end_inflate;
				}
				break;
			case CMD_END_FILE: // finish up
				goto end_ok;
			case CMD_WARNING:
				logp("WARNING: %s\n", rbuf->buf);
				cntr_add(cntr, rbuf->cmd, 0);
				break;
			default:
				iobuf_log_unexpected(rbuf, __func__);
				goto end_inflate;
		}
	}

end_ok:
	ret=0;
end_inflate:
	inflateEnd(&zstrm);
end:
	if(ret) logp("transfer file returning: %d\n", ret);
	iobuf_free_content(rbuf);
	return ret;
}

FILE *open_file(const char *fname, const char *mode)
{
	FILE *fp=NULL;

	if(!(fp=fopen(fname, mode)))
	{
		logp("could not open %s: %s\n", fname, strerror(errno));
		return NULL; 
	}
	return fp;
}

gzFile gzopen_file(const char *fname, const char *mode)
{
	gzFile fp=NULL;

	if(!(fp=gzopen(fname, mode)))
	{
		logp("could not open %s: %s\n", fname, strerror(errno));
		return NULL; 
	}
	return fp;
}
