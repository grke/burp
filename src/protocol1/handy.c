#include "../burp.h"
#include "../alloc.h"
#include "../asfd.h"
#include "../async.h"
#include "../bfile.h"
#include "../cmd.h"
#include "../handy.h"
#include "../hexmap.h"
#include "../iobuf.h"
#include "../log.h"
#include "handy.h"

static int do_encryption(struct asfd *asfd, EVP_CIPHER_CTX *ctx,
	uint8_t *inbuf, int inlen, uint8_t *outbuf, int *outlen,
	MD5_CTX *md5)
{
	if(!inlen) return 0;
	if(!EVP_CipherUpdate(ctx, outbuf, outlen, inbuf, inlen))
	{
		logp("Encryption failure.\n");
		return -1;
	}
	if(*outlen>0)
	{
		struct iobuf wbuf;
		iobuf_set(&wbuf, CMD_APPEND, (char *)outbuf, *outlen);
		if(asfd->write(asfd, &wbuf))
			return -1;
		if(!MD5_Update(md5, outbuf, *outlen))
		{
			logp("MD5_Update() failed\n");
			return -1;
		}
	}
	return 0;
}

EVP_CIPHER_CTX *enc_setup(int encrypt, const char *encryption_password)
{
	EVP_CIPHER_CTX *ctx=NULL;
	// Declare enc_iv with individual characters so that the weird last
	// character can be specified as a hex number in order to prevent
	// compilation warnings on Macs.
	uint8_t enc_iv[]={'[', 'l', 'k', 'd', '.', '$', 'G', 0xa3, '\0'};

	if(!encryption_password)
	{
		logp("No encryption password in %s()\n", __func__);
		goto error;
	}

	if(!(ctx=(EVP_CIPHER_CTX *)
		calloc_w(1, sizeof(EVP_CIPHER_CTX), __func__)))
			goto error;

	// Don't set key or IV because we will modify the parameters.
	EVP_CIPHER_CTX_init(ctx);
	if(!(EVP_CipherInit_ex(ctx, EVP_bf_cbc(), NULL, NULL, NULL, encrypt)))
	{
		logp("EVP_CipherInit_ex failed\n");
		goto error;
	}
	EVP_CIPHER_CTX_set_key_length(ctx, strlen(encryption_password));
	// We finished modifying parameters so now we can set key and IV

	if(!EVP_CipherInit_ex(ctx, NULL, NULL,
		(uint8_t *)encryption_password,
		enc_iv, encrypt))
	{
		logp("Second EVP_CipherInit_ex failed\n");
		goto error;
	}
	return ctx;
error:
	free_v((void **)&ctx);
	return NULL;
}

#ifdef HAVE_WIN32
struct bsid {
	int32_t dwStreamId;
	int32_t dwStreamAttributes;
	int64_t Size;
	int32_t dwStreamNameSize;
};
#endif

char *get_endfile_str(uint64_t bytes, uint8_t *checksum)
{
	static char endmsg[128]="";
	snprintf(endmsg, sizeof(endmsg), "%" PRIu64 ":%s",
			(uint64_t)bytes,
			checksum?bytes_to_md5str(checksum):"");
	return endmsg;
}

int write_endfile(struct asfd *asfd, uint64_t bytes, uint8_t *checksum)
{
	return asfd->write_str(asfd,
		CMD_END_FILE, get_endfile_str(bytes, checksum));
}

/* OK, this function is getting a bit out of control.
   One problem is that, if you give deflateInit2 compression=0, it still
   writes gzip headers and footers, so I had to add extra
   if(compression) and if(!compression) bits all over the place that would
   skip the actual compression.
   This is needed for the case where encryption is on and compression is off.
   Encryption off and compression off uses send_whole_file().
   Perhaps a separate function is needed for encryption on compression off.
*/
int send_whole_file_gzl(struct asfd *asfd,
	const char *fname, const char *datapth, int quick_read,
	uint64_t *bytes, const char *encpassword, struct cntr *cntr,
	int compression, struct BFILE *bfd, const char *extrameta,
	size_t elen)
{
	int ret=0;
	int zret=0;
	MD5_CTX md5;
	size_t metalen=0;
	const char *metadata=NULL;
	struct iobuf wbuf;

	int have;
	z_stream strm;
	int flush=Z_NO_FLUSH;
	uint8_t in[ZCHUNK];
	uint8_t out[ZCHUNK];

	int eoutlen;
	uint8_t eoutbuf[ZCHUNK+EVP_MAX_BLOCK_LENGTH];

	EVP_CIPHER_CTX *enc_ctx=NULL;
#ifdef HAVE_WIN32
	int do_known_byte_count=0;
	size_t datalen=bfd->datalen;
	if(datalen>0) do_known_byte_count=1;
#endif

	if(encpassword && !(enc_ctx=enc_setup(1, encpassword)))
		return -1;

	if(!MD5_Init(&md5))
	{
		logp("MD5_Init() failed\n");
		return -1;
	}

//logp("send_whole_file_gz: %s%s\n", fname, extrameta?" (meta)":"");

	if((metadata=extrameta))
	{
		metalen=elen;
	}

	/* allocate deflate state */
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	if((zret=deflateInit2(&strm, compression, Z_DEFLATED, (15+16),
		8, Z_DEFAULT_STRATEGY))!=Z_OK)

	{
		return -1;
	}

	do
	{
		if(metadata)
		{
			if(metalen>ZCHUNK)
				strm.avail_in=ZCHUNK;
			else
				strm.avail_in=metalen;
			memcpy(in, metadata, strm.avail_in);
			metadata+=strm.avail_in;
			metalen-=strm.avail_in;
		}
		else
		{
			// Windows VSS headers give us how much data to
			// expect to read.
#ifdef HAVE_WIN32
			if(do_known_byte_count)
			{
				if(datalen<=0) strm.avail_in=0;
				else strm.avail_in=
					(uint32_t)bfd->read(bfd, in,
						min((size_t)ZCHUNK, datalen));
				datalen-=strm.avail_in;
			}
			else
#endif
				strm.avail_in=
					(uint32_t)bfd->read(bfd, in, ZCHUNK);
		}
		if(!compression && !strm.avail_in) break;

		*bytes+=strm.avail_in;

		// The checksum needs to be later if encryption is being used.
		if(!enc_ctx)
		{
			if(!MD5_Update(&md5, in, strm.avail_in))
			{
				logp("MD5_Update() failed\n");
				ret=-1;
				break;
			}
		}

#ifdef HAVE_WIN32
		if(do_known_byte_count && datalen<=0) flush=Z_FINISH;
		else
#endif
		if(strm.avail_in) flush=Z_NO_FLUSH;
		else flush=Z_FINISH;

		strm.next_in=in;

		/* run deflate() on input until output buffer not full, finish
			compression if all of source has been read in */
		do
		{
			if(compression)
			{
				strm.avail_out = ZCHUNK;
				strm.next_out = out;
				zret = deflate(&strm, flush); /* no bad return value */
				if(zret==Z_STREAM_ERROR) /* state not clobbered */
				{
					logp("z_stream_error\n");
					ret=-1;
					break;
				}
				have = ZCHUNK-strm.avail_out;
			}
			else
			{
				have=strm.avail_in;
				memcpy(out, in, have);
			}

			if(enc_ctx)
			{
				if(do_encryption(asfd, enc_ctx, out, have,
					eoutbuf, &eoutlen, &md5))
				{
					ret=-1;
					break;
				}
			}
			else
			{
				iobuf_set(&wbuf, CMD_APPEND, (char *)out, have);
				if(asfd->write(asfd, &wbuf))
				{
					ret=-1;
					break;
				}
			}
			if(quick_read && datapth)
			{
				int qr;
				if((qr=do_quick_read(asfd, datapth, cntr))<0)
				{
					ret=-1;
					break;
				}
				if(qr) // client wants to interrupt
				{
					goto cleanup;
				}
			}
			if(!compression) break;
		} while (!strm.avail_out);

		if(ret) break;

		if(!compression) continue;

		if(strm.avail_in) /* all input will be used */
		{
			ret=-1;
			logp("strm.avail_in=%d\n", strm.avail_in);
			break;
		}
	} while(flush!=Z_FINISH);

	if(!ret)
	{
		if(compression && zret!=Z_STREAM_END)
		{
			logp("ret OK, but zstream not finished: %d\n", zret);
			ret=-1;
		}
		else if(enc_ctx)
		{
			if(!EVP_CipherFinal_ex(enc_ctx, eoutbuf, &eoutlen))
			{
				logp("Encryption failure at the end\n");
				ret=-1;
			}
			else if(eoutlen>0)
			{
			  iobuf_set(&wbuf, CMD_APPEND,
				(char *)eoutbuf, (size_t)eoutlen);
			  if(asfd->write(asfd, &wbuf))
				ret=-1;
			  else if(!MD5_Update(&md5, eoutbuf, eoutlen))
			  {
				logp("MD5_Update() failed\n");
				ret=-1;
			  }
			}
		}
	}

cleanup:
	deflateEnd(&strm);

	if(enc_ctx)
	{
		EVP_CIPHER_CTX_cleanup(enc_ctx);
		free(enc_ctx);
	}

	if(!ret)
	{
		uint8_t checksum[MD5_DIGEST_LENGTH];
		if(!MD5_Final(checksum, &md5))
		{
			logp("MD5_Final() failed\n");
			return -1;
		}

		return write_endfile(asfd, *bytes, checksum);
	}
//logp("end of send\n");
	return ret;
}

#ifdef HAVE_WIN32
struct winbuf
{
	MD5_CTX *md5;
	int quick_read;
	const char *datapth;
	struct cntr *cntr;
	uint64_t *bytes;
	struct asfd *asfd;
};

static DWORD WINAPI write_efs(PBYTE pbData,
	PVOID pvCallbackContext, ULONG ulLength)
{
	struct iobuf wbuf;
	struct winbuf *mybuf=(struct winbuf *)pvCallbackContext;
	(*(mybuf->bytes))+=ulLength;
	if(!MD5_Update(mybuf->md5, pbData, ulLength))
	{
		logp("MD5_Update() failed\n");
		return ERROR_FUNCTION_FAILED;
	}
	iobuf_set(&wbuf, CMD_APPEND, (char *)pbData, (size_t)ulLength);
	if(mybuf->asfd->write(mybuf->asfd, &wbuf))
	{
		return ERROR_FUNCTION_FAILED;
	}
	if(mybuf->quick_read)
	{
		int qr;
		if((qr=do_quick_read(mybuf->asfd,
				mybuf->datapth, mybuf->cntr))<0)
			return ERROR_FUNCTION_FAILED;
		if(qr) // client wants to interrupt
			return ERROR_FUNCTION_FAILED;
	}
	return ERROR_SUCCESS;
}
#endif

int send_whole_filel(struct asfd *asfd,
	enum cmd cmd, const char *datapth,
	int quick_read, uint64_t *bytes, struct cntr *cntr,
	struct BFILE *bfd, const char *extrameta, size_t elen)
{
	int ret=0;
	size_t s=0;
	MD5_CTX md5;
	char buf[4096]="";
	struct iobuf wbuf;

	if(!bfd)
	{
		logp("No bfd in %s()\n", __func__);
		return -1;
	}

	if(!MD5_Init(&md5))
	{
		logp("MD5_Init() failed\n");
		return -1;
	}

	if(extrameta)
	{
		size_t metalen=0;
		const char *metadata=NULL;

		metadata=extrameta;
		metalen=elen;

		// Send metadata in chunks, rather than all at once.
		while(metalen>0)
		{
			if(metalen>ZCHUNK) s=ZCHUNK;
			else s=metalen;

			if(!MD5_Update(&md5, metadata, s))
			{
				logp("MD5_Update() failed\n");
				ret=-1;
			}
			iobuf_set(&wbuf, CMD_APPEND, (char *)metadata, s);
			if(asfd->write(asfd, &wbuf))
			{
				ret=-1;
			}

			metadata+=s;
			metalen-=s;

			*bytes+=s;
		}
	}
	else
	{
#ifdef HAVE_WIN32
		if(!ret && cmd==CMD_EFS_FILE)
		{
			struct winbuf mybuf;
			mybuf.md5=&md5;
			mybuf.quick_read=quick_read;
			mybuf.datapth=datapth;
			mybuf.cntr=cntr;
			mybuf.bytes=bytes;
			mybuf.asfd=asfd;
			// The EFS read function, ReadEncryptedFileRaw(),
			// works in an annoying way. You have to give it a
			// function that it calls repeatedly every time the
			// read buffer is called.
			// So ReadEncryptedFileRaw() will not return until
			// it has read the whole file. I have no idea why
			// they do not have a plain 'read()' function for it.

			ReadEncryptedFileRaw((PFE_EXPORT_FUNC)write_efs,
				&mybuf, bfd->pvContext);
		}
		else
#endif

		if(!ret)
		{
#ifdef HAVE_WIN32
		  int do_known_byte_count=0;
		  size_t datalen=bfd->datalen;
		  if(datalen>0) do_known_byte_count=1;
#endif
		  while(1)
		  {
#ifdef HAVE_WIN32
			if(do_known_byte_count)
			{
				s=(uint32_t)bfd->read(bfd,
					buf, min((size_t)4096, datalen));
				datalen-=s;
			}
			else
			{
#endif
				s=(uint32_t)bfd->read(bfd, buf, 4096);
#ifdef HAVE_WIN32
			}
#endif
			if(s<=0) break;

			*bytes+=s;
			if(!MD5_Update(&md5, buf, s))
			{
				logp("MD5_Update() failed\n");
				ret=-1;
				break;
			}
			iobuf_set(&wbuf, CMD_APPEND, buf, s);
			if(asfd->write(asfd, &wbuf))
			{
				ret=-1;
				break;
			}
			if(quick_read)
			{
				int qr;
				if((qr=do_quick_read(asfd, datapth, cntr))<0)
				{
					ret=-1;
					break;
				}
				if(qr)
				{
					// client wants to interrupt
					break;
				}
			}
#ifdef HAVE_WIN32
			// Windows VSS headers tell us how many bytes to
			// expect.
			if(do_known_byte_count && datalen<=0) break;
#endif
		  }
		}
	}
	if(!ret)
	{
		uint8_t checksum[MD5_DIGEST_LENGTH];
		if(!MD5_Final(checksum, &md5))
		{
			logp("MD5_Final() failed\n");
			return -1;
		}
		return write_endfile(asfd, *bytes, checksum);
	}
	return ret;
}
