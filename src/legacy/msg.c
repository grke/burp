#include "include.h"

static int do_write(BFILE *bfd, FILE *fp, unsigned char *out, size_t outlen,
	char **metadata, unsigned long long *sent)
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

static int do_inflate(z_stream *zstrm, BFILE *bfd, FILE *fp,
	unsigned char *out, unsigned char *buftouse, size_t lentouse,
	char **metadata, const char *encpassword, int enccompressed,
	unsigned long long *sent)
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
	struct iobuf *rbuf=NULL;
	struct winbuf *mybuf=(struct winbuf *)pvCallbackContext;

	if(!(rbuf && !(rbuf=iobuf_alloc())))
		return ERROR_FUNCTION_FAILED;

	while(1)
	{
		if(async_read(rbuf))
			return ERROR_FUNCTION_FAILED;
		(*(mybuf->rcvd))+=rbuf->len;

		switch(rbuf->cmd)
		{
			case CMD_APPEND:
				memcpy(pbData, rbuf->buf, rbuf->len);
				*ulLength=(ULONG)rbuf->len;
				(*(mybuf->sent))+=rbuf->len;
				iobuf_free_content(rbuf);
				return ERROR_SUCCESS;
			case CMD_END_FILE:
				*ulLength=0;
				iobuf_free_content(rbuf);
				return ERROR_SUCCESS;
			case CMD_WARNING:
				logp("WARNING: %s\n", rbuf->buf);
				do_filecounter(mybuf->cntr, rbuf->cmd, 0);
				iobuf_free_content(rbuf);
				continue;
			default:
				iobuf_log_unexpected(rbuf, __FUNCTION__);
				iobuf_free_content(rbuf);
				break;
		}
	}
	return ERROR_FUNCTION_FAILED;
}

static int transfer_efs_in(BFILE *bfd, unsigned long long *rcvd,
	unsigned long long *sent, struct cntr *cntr)
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

int transfer_gzfile_in(struct sbufl *sb, const char *path, BFILE *bfd,
	FILE *fp, unsigned long long *rcvd, unsigned long long *sent,
	const char *encpassword, int enccompressed,
	struct cntr *cntr, char **metadata)
{
	int quit=0;
	int ret=-1;
	unsigned char out[ZCHUNK];
	size_t doutlen=0;
	//unsigned char doutbuf[1000+EVP_MAX_BLOCK_LENGTH];
	unsigned char doutbuf[ZCHUNK-EVP_MAX_BLOCK_LENGTH];
	static struct iobuf *rbuf=NULL;

	z_stream zstrm;

	EVP_CIPHER_CTX *enc_ctx=NULL;

	// Checksum stuff
	//MD5_CTX md5;
	//unsigned char checksum[MD5_DIGEST_LENGTH+1];

#ifdef HAVE_WIN32
	if(sb && sb->path.cmd==CMD_EFS_FILE)
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

	if(!(rbuf=iobuf_alloc())) return -1;

	while(!quit)
	{
		iobuf_free_content(rbuf);
		if(async_read(rbuf))
		{
			if(enc_ctx)
			{
				EVP_CIPHER_CTX_cleanup(enc_ctx);
				free(enc_ctx);
			}
			inflateEnd(&zstrm);
			return -1;
		}
		(*rcvd)+=rbuf->len;

		//logp("transfer in: %c:%s\n", rbuf->cmd, rbuf->buf);
		switch(rbuf->cmd)
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
					if(!MD5_Update(&md5, rbuf->buf, rbuf->len))
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
					  if(!MD5_Update(&md5, rbuf->buf, rbuf->len))
					  {
						logp("MD5 update enc error\n");
						quit++; ret=-1;
						break;
					  }
					  else 
*/
					  if(!EVP_CipherUpdate(enc_ctx,
						doutbuf, (int *)&doutlen,
						(unsigned char *)rbuf->buf,
						rbuf->len))
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
					  lentouse=rbuf->len;
					  buftouse=(unsigned char *)rbuf->buf;
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
				logp("WARNING: %s\n", rbuf->buf);
				do_filecounter(cntr, rbuf->cmd, 0);
				break;
			default:
				iobuf_log_unexpected(rbuf, __FUNCTION__);
				quit++;
				ret=-1;
				break;
		}
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
