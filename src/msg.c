#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "counter.h"
#include "asyncio.h"
#include "handy.h"
#include "sbuf.h"

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

static int do_write(BFILE *bfd, FILE *fp, unsigned char *out, size_t outlen, char **metadata, unsigned long long *sent)
{
	int ret=0;
	if(metadata)
	{
		// Append it to our metadata.
		out[outlen]='\0';
		//printf("\nadd outlen: %lu\n", outlen);
		if(!(*metadata=prepend_len(*metadata, *sent,
				(const char *)out, outlen,
				"", 0, (size_t *)sent)))
		{
			logp("error when appending metadata\n");
			async_write_str(CMD_ERROR, "error when appending metadata");
			return -1;
		}
	}
	else
	{
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
	}
	return 0;
}

static int do_inflate(z_stream *zstrm, BFILE *bfd, FILE *fp, unsigned char *out, unsigned char *buftouse, size_t lentouse, char **metadata, const char *encpassword, int enccompressed, unsigned long long *sent)
{
	int zret=Z_OK;
	unsigned have=0;

	// Do not want to inflate encrypted data that was not compressed.
	// Just write it straight out.
	if(encpassword && !enccompressed)
		return do_write(bfd, fp, buftouse, lentouse, metadata, sent);

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

		if(do_write(bfd, fp, out, have, metadata, sent))
			return -1;
/*
		if(md5)
		{
			if(!MD5_Update(md5, out, have))
			{
				logp("MD5 update error\n");
				return -1;
			}
		}
*/
	} while(!zstrm->avail_out);
	return 0;
}

#ifdef HAVE_WIN32

struct winbuf
{
	unsigned long long *rcvd;
	unsigned long long *sent;
	struct cntr *cntr;
};

static DWORD WINAPI read_efs(PBYTE pbData, PVOID pvCallbackContext, PULONG ulLength)
{
	char cmd='\0';
	size_t len=0;
	char *buf=NULL;
	struct winbuf *mybuf=(struct winbuf *)pvCallbackContext;

	while(1)
	{
		if(async_read(&cmd, &buf, &len))
			return ERROR_FUNCTION_FAILED;
		(*(mybuf->rcvd))+=len;

		switch(cmd)
		{
			case CMD_APPEND:
				memcpy(pbData, buf, len);
				*ulLength=(ULONG)len;
				(*(mybuf->sent))+=len;
				free(buf);
				return ERROR_SUCCESS;
			case CMD_END_FILE:
				*ulLength=0;
				free(buf);
				return ERROR_SUCCESS;
			case CMD_WARNING:
				logp("WARNING: %s\n", buf);
				do_filecounter(mybuf->cntr, cmd, 0);
				free(buf);
				continue;
			default:
				logp("unknown append cmd: %c\n", cmd);
				free(buf);
				break;
		}
	}
	return ERROR_FUNCTION_FAILED;
}

static int transfer_efs_in(BFILE *bfd, unsigned long long *rcvd, unsigned long long *sent, struct cntr *cntr)
{
	int ret=0;
	struct winbuf mybuf;
	mybuf.rcvd=rcvd;
	mybuf.sent=sent;
	mybuf.cntr=cntr;
	if((ret=WriteEncryptedFileRaw((PFE_IMPORT_FUNC)read_efs,
		&mybuf, bfd->pvContext)))
			logp("WriteEncryptedFileRaw returned %d\n", ret);
	return ret;
}

#endif

int transfer_gzfile_in(struct sbuf *sb, const char *path, BFILE *bfd, FILE *fp, unsigned long long *rcvd, unsigned long long *sent, const char *encpassword, int enccompressed, struct cntr *cntr, char **metadata)
{
	char cmd=0;
	char *buf=NULL;
	size_t len=0;
	int quit=0;
	int ret=-1;
	unsigned char out[ZCHUNK];
	size_t doutlen=0;
	//unsigned char doutbuf[1000+EVP_MAX_BLOCK_LENGTH];
	unsigned char doutbuf[ZCHUNK-EVP_MAX_BLOCK_LENGTH];

	z_stream zstrm;

	EVP_CIPHER_CTX *enc_ctx=NULL;

	// Checksum stuff
	//MD5_CTX md5;
	//unsigned char checksum[MD5_DIGEST_LENGTH+1];

#ifdef HAVE_WIN32
	if(sb && sb->cmd==CMD_EFS_FILE)
		return transfer_efs_in(bfd, rcvd, sent, cntr);
#endif

	//if(!MD5_Init(&md5))
	//{
	//	logp("MD5_Init() failed");
	//	return -1;
	//}

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

	if(encpassword && !(enc_ctx=enc_setup(0, encpassword)))
	{
		inflateEnd(&zstrm);
		return -1;
	}

	while(!quit)
	{
		if(async_read(&cmd, &buf, &len))
		{
			if(enc_ctx)
			{
				EVP_CIPHER_CTX_cleanup(enc_ctx);
				free(enc_ctx);
			}
			inflateEnd(&zstrm);
			return -1;
		}
		(*rcvd)+=len;

		//logp("transfer in: %c:%s\n", cmd, buf);
		switch(cmd)
		{
			case CMD_APPEND: // append
				if(!fp && !bfd && !metadata)
				{
					logp("given append, but no file or metadata to write to\n");
					async_write_str(CMD_ERROR, "append with no file or metadata");
					quit++; ret=-1;
				}
				else
				{
					size_t lentouse;
					unsigned char *buftouse=NULL;
/*
					if(!MD5_Update(&md5, buf, len))
					{
						logp("MD5 update enc error\n");
						quit++; ret=-1;
						break;
					}
*/
					// If doing decryption, it needs
					// to be done before uncompressing.
					if(enc_ctx)
					{
					  // updating our checksum needs to
					  // be done first
/*
					  if(!MD5_Update(&md5, buf, len))
					  {
						logp("MD5 update enc error\n");
						quit++; ret=-1;
						break;
					  }
					  else 
*/
					  if(!EVP_CipherUpdate(enc_ctx,
						doutbuf, (int *)&doutlen,
						(unsigned char *)buf,
						len))
					  {
						logp("Decryption error\n");
						quit++; ret=-1;
					  	break;
					  }
					  if(!doutlen) break;
					  lentouse=doutlen;
					  buftouse=doutbuf;
					}
					else
					{
					  lentouse=len;
					  buftouse=(unsigned char *)buf;
					}
					//logp("want to write: %d\n", zstrm.avail_in);

					if(do_inflate(&zstrm, bfd, fp, out,
						buftouse, lentouse, metadata,
						encpassword,
						enccompressed,
						sent))
					{
						ret=-1; quit++;
						break;
					}
				}
				break;
			case CMD_END_FILE: // finish up
				if(enc_ctx)
				{
					if(!EVP_CipherFinal_ex(enc_ctx,
						doutbuf, (int *)&doutlen))
					{
						logp("Decryption failure at the end.\n");
						ret=-1; quit++;
						break;
					}
					if(doutlen && do_inflate(&zstrm, bfd,
					  fp, out, doutbuf, doutlen, metadata,
					  encpassword,
					  enccompressed, sent))
					{
						ret=-1; quit++;
						break;
					}
				}
/*
				if(MD5_Final(checksum, &md5))
				{
					char *oldsum=NULL;
					const char *newsum=NULL;

					if((oldsum=strchr(buf, ':')))
					{
						oldsum++;
						newsum=get_checksum_str(checksum);
						// log if the checksum differed
						if(strcmp(newsum, oldsum))
							logw(cntr, "md5sum for '%s' did not match! (%s!=%s)\n", path, newsum, oldsum);
					}
				}
				else
				{
					logp("MD5_Final() failed\n");
				}
*/
				quit++;
				ret=0;
				break;
			case CMD_WARNING:
				logp("WARNING: %s\n", buf);
				do_filecounter(cntr, cmd, 0);
				break;
			default:
				logp("unknown append cmd: %c\n", cmd);
				quit++;
				ret=-1;
				break;
		}
		if(buf) free(buf);
		buf=NULL;
	}
	inflateEnd(&zstrm);
	if(enc_ctx)
	{
		EVP_CIPHER_CTX_cleanup(enc_ctx);
		free(enc_ctx);
	}

	if(ret) logp("transfer file returning: %d\n", ret);
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
