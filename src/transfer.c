#include "burp.h"
#include "alloc.h"
#include "asfd.h"
#include "async.h"
#include "cmd.h"
#include "cntr.h"
#include "handy_extra.h"
#include "iobuf.h"
#include "log.h"
#include "prepend.h"
#include "sbuf.h"
#include "msg.h"

static int do_write(struct asfd *asfd,
	struct BFILE *bfd, uint8_t *out, size_t outlen,
	char **metadata, uint64_t *sent)
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
			asfd->write_str(asfd, CMD_ERROR,
				"error when appending metadata");
			return -1;
		}
	}
	else
	{
		if((ret=bfd->write(bfd, out, outlen))<=0)
		{
			logp("error when appending %lu: %d\n",
				(unsigned long)outlen, ret);
			asfd->write_str(asfd, CMD_ERROR, "write failed");
			return -1;
		}
		*sent+=outlen;
	}
	return 0;
}

static int do_inflate(struct asfd *asfd,
	z_stream *zstrm, struct BFILE *bfd,
	uint8_t *out, uint8_t *buftouse, size_t lentouse,
	char **metadata, const char *encpassword, int enccompressed,
	uint64_t *sent)
{
	int zret=Z_OK;
	unsigned have=0;

	// Do not want to inflate encrypted data that was not compressed.
	// Just write it straight out.
	if(encpassword && !enccompressed)
		return do_write(asfd, bfd, buftouse, lentouse, metadata, sent);

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

		if(do_write(asfd, bfd, out, have, metadata, sent))
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
	uint64_t *rcvd;
	uint64_t *sent;
	struct cntr *cntr;
	struct asfd *asfd;
};

static DWORD WINAPI read_efs(PBYTE pbData, PVOID pvCallbackContext, PULONG ulLength)
{
	struct iobuf *rbuf;
	struct winbuf *mybuf=(struct winbuf *)pvCallbackContext;
	rbuf=mybuf->asfd->rbuf;

	while(1)
	{
		if(mybuf->asfd->read(mybuf->asfd))
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
			case CMD_MESSAGE:
				logp("MESSAGE: %s\n", rbuf->buf);
				cntr_add(mybuf->cntr, rbuf->cmd, 0);
				iobuf_free_content(rbuf);
				continue;
			case CMD_WARNING:
				logp("WARNING: %s\n", rbuf->buf);
				cntr_add(mybuf->cntr, rbuf->cmd, 0);
				iobuf_free_content(rbuf);
				continue;
			default:
				iobuf_log_unexpected(rbuf, __func__);
				iobuf_free_content(rbuf);
				break;
		}
	}
	return ERROR_FUNCTION_FAILED;
}

static int transfer_efs_in(struct asfd *asfd,
	struct BFILE *bfd, uint64_t *rcvd,
	uint64_t *sent, struct cntr *cntr)
{
	int ret=0;
	struct winbuf mybuf;
	mybuf.rcvd=rcvd;
	mybuf.sent=sent;
	mybuf.cntr=cntr;
	mybuf.asfd=asfd;
	if((ret=WriteEncryptedFileRaw((PFE_IMPORT_FUNC)read_efs,
		&mybuf, bfd->pvContext)))
			logp("WriteEncryptedFileRaw returned %d\n", ret);
	return ret;
}

#endif

int transfer_gzfile_inl(struct asfd *asfd,
#ifdef HAVE_WIN32
	struct sbuf *sb,
#endif
	struct BFILE *bfd,
	uint64_t *rcvd, uint64_t *sent,
	const char *encpassword, int enccompressed,
	struct cntr *cntr, char **metadata,
	int key_deriv, uint64_t salt)
{
	int quit=0;
	int ret=-1;
	uint8_t out[ZCHUNK];
	int doutlen=0;
	//uint8_t doutbuf[1000+EVP_MAX_BLOCK_LENGTH];
	uint8_t doutbuf[ZCHUNK-EVP_MAX_BLOCK_LENGTH];
	struct iobuf *rbuf=asfd->rbuf;

	z_stream zstrm;

	EVP_CIPHER_CTX *enc_ctx=NULL;

	// Checksum stuff
	//MD5_CTX md5;
	//uint8_t checksum[MD5_DIGEST_LENGTH];

#ifdef HAVE_WIN32
	if(sb && sb->path.cmd==CMD_EFS_FILE)
		return transfer_efs_in(asfd, bfd, rcvd, sent, cntr);
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

	if(encpassword
	  && !(enc_ctx=enc_setup(0, encpassword, key_deriv, salt)))
	{
		inflateEnd(&zstrm);
		return -1;
	}

	while(!quit)
	{
		iobuf_free_content(rbuf);
		if(asfd->read(asfd))
		{
			if(enc_ctx)
			{
				EVP_CIPHER_CTX_cleanup(enc_ctx);
				EVP_CIPHER_CTX_free(enc_ctx);
				enc_ctx=NULL;
			}
			inflateEnd(&zstrm);
			return -1;
		}
		(*rcvd)+=rbuf->len;

		switch(rbuf->cmd)
		{
			case CMD_APPEND: // append
				if(!bfd && !metadata)
				{
					logp("given append, but no file or metadata to write to\n");
					asfd->write_str(asfd, CMD_ERROR,
					  "append with no file or metadata");
					quit++; ret=-1;
				}
				else
				{
					size_t lentouse;
					uint8_t *buftouse=NULL;
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
						doutbuf, &doutlen,
						(uint8_t *)rbuf->buf,
						rbuf->len))
					  {
						logp("Decryption error\n");
						quit++; ret=-1;
					  	break;
					  }
					  if(!doutlen) break;
					  lentouse=(size_t)doutlen;
					  buftouse=doutbuf;
					}
					else
					{
					  lentouse=rbuf->len;
					  buftouse=(uint8_t *)rbuf->buf;
					}
					//logp("want to write: %d\n", zstrm.avail_in);

					if(do_inflate(asfd, &zstrm, bfd, out,
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
						doutbuf, &doutlen))
					{
						logp("Decryption failure at the end.\n");
						ret=-1; quit++;
						break;
					}
					if(doutlen && do_inflate(asfd,
					  &zstrm, bfd,
					  out, doutbuf, (size_t)doutlen,
					  metadata, encpassword,
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
						newsum=bytes_to_md5str(checksum);
						// log if the checksum differed
						if(strcmp(newsum, oldsum))
							logw(asfd, cntr, "md5sum for '%s' did not match! (%s!=%s)\n", path, newsum, oldsum);
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
			case CMD_MESSAGE:
			case CMD_WARNING:
				log_recvd(rbuf, cntr, 0);
				break;
			default:
				iobuf_log_unexpected(rbuf, __func__);
				quit++;
				ret=-1;
				break;
		}
	}
	inflateEnd(&zstrm);
	if(enc_ctx)
	{
		EVP_CIPHER_CTX_cleanup(enc_ctx);
		EVP_CIPHER_CTX_free(enc_ctx);
		enc_ctx=NULL;
	}

	iobuf_free_content(rbuf);
	if(ret) logp("transfer file returning: %d\n", ret);
	return ret;
}
