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
		logp("Unable to write message to compressed file: %s\n",
			strerror(errno));
		return -1;
	}
	return 0;
}

static int do_write(BFILE *bfd, FILE *fp, unsigned char *out, size_t outlen, unsigned long long *sent)
{
	int ret=0;
#ifdef HAVE_WIN32
	if((ret=bwrite(bfd, out, outlen))<=0)
	{
		logp("error when appending %d: %d\n", outlen, ret);
		async_write_str(CMD_ERROR, "write failed");
		return -1;
	}
#else
	if((fp && (ret=fwrite(out, 1, outlen, fp))<=0))
	{
		logp("error when appending %d: %d\n", outlen, ret);
		async_write_str(CMD_ERROR, "write failed");
		return -1;
	}
#endif
	*sent+=outlen;
	return 0;
}

static int do_inflate(z_stream *zstrm, BFILE *bfd, FILE *fp, unsigned char *out, unsigned char *buftouse, size_t lentouse, unsigned long long *sent)
{
	int zret=Z_OK;
	unsigned have=0;

	zstrm->avail_in=lentouse;
	zstrm->next_in=buftouse;

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
			  break;
		}
		have=ZCHUNK-zstrm->avail_out;
		if(!have) continue;

		if(do_write(bfd, fp, out, have, sent))
			return -1;
	} while(!zstrm->avail_out);
	return 0;
}

int transfer_gzfile_in(const char *path, BFILE *bfd, FILE *fp, unsigned long long *rcvd, unsigned long long *sent, struct cntr *cntr)
{
	int quit=0;
	int ret=-1;
	unsigned char out[ZCHUNK];
	struct iobuf rbuf;
	z_stream zstrm;

	iobuf_init(&rbuf);

	zstrm.zalloc=Z_NULL;
	zstrm.zfree=Z_NULL;
	zstrm.opaque=Z_NULL;
	zstrm.avail_in=0;
	zstrm.next_in=Z_NULL;

	if(inflateInit2(&zstrm, (15+16)))
	{
		logp("unable to init inflate\n");
		return -1;
	}

	while(!quit)
	{
		iobuf_init(&rbuf);
		if(async_read(&rbuf))
		{
			inflateEnd(&zstrm);
			return -1;
		}
		(*rcvd)+=rbuf.len;

		//logp("transfer in: %c:%s\n", rbuf.cmd, rbuf.buf);
		switch(rbuf.cmd)
		{
			case CMD_APPEND: // append
				if(!fp && !bfd)
				{
					logp("given append, but no file to write to\n");
					async_write_str(CMD_ERROR, "append with no file");
					quit++; ret=-1;
				}
				else
				{
					size_t lentouse;
					unsigned char *buftouse=NULL;
					lentouse=rbuf.len;
					buftouse=(unsigned char *)rbuf.buf;
					//logp("want to write: %d\n", zstrm.avail_in);

					if(do_inflate(&zstrm, bfd, fp, out,
						buftouse, lentouse,
						sent))
					{
						ret=-1; quit++;
						break;
					}
				}
				break;
			case CMD_END_FILE: // finish up
				quit++;
				ret=0;
				break;
			case CMD_WARNING:
				logp("WARNING: %s\n", rbuf.buf);
				do_filecounter(cntr, rbuf.cmd, 0);
				break;
			default:
				logp("unknown append cmd: %c\n", rbuf.cmd);
				quit++;
				ret=-1;
				break;
		}
		if(rbuf.buf) { free(rbuf.buf); rbuf.buf=NULL; }
	}
	inflateEnd(&zstrm);

	if(ret) logp("transfer file returning: %d\n", ret);
	if(rbuf.buf) free(rbuf.buf);
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
