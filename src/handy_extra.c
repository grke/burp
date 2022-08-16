#include "burp.h"
#include "alloc.h"
#include "asfd.h"
#include "async.h"
#include "bfile.h"
#include "cmd.h"
#include "handy.h"
#include "hexmap.h"
#include "iobuf.h"
#include "log.h"
#include "md5.h"
#include "handy_extra.h"
#include "sbuf.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

static int do_encryption(struct asfd *asfd, EVP_CIPHER_CTX *ctx,
	uint8_t *inbuf, int inlen, uint8_t *outbuf, int *outlen,
	struct md5 *md5)
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
		if(!md5_update(md5, outbuf, *outlen))
		{
			logp("md5_update() failed\n");
			return -1;
		}
	}
	return 0;
}

EVP_CIPHER_CTX *enc_setup(int encrypt, const char *encryption_password,
	int key_deriv, uint64_t salt)
{
	uint8_t enc_iv[9];
	uint8_t enc_key[256];
	EVP_CIPHER_CTX *ctx=NULL;
	const EVP_CIPHER *cipher=NULL;
	int key_len;

	switch(key_deriv)
	{
		case ENCRYPTION_KEY_DERIVED_BF_CBC:
			cipher=EVP_bf_cbc();
			break;
		case ENCRYPTION_KEY_DERIVED_AES_CBC_256:
			cipher=EVP_aes_256_cbc();
			break;
		default:
			logp("Could not determine cipher from: %d\n", key_deriv);
			break;
	}

	if(!encryption_password)
	{
		logp("No encryption password in %s()\n", __func__);
		goto error;
	}

	if(key_deriv)
	{
		// New, good way.
		uint64_t be_salt=htobe64(salt);
		const EVP_MD *dgst=EVP_sha256();
		
		if(!(key_len=EVP_BytesToKey(cipher, dgst, (uint8_t *)&be_salt,
		       (const unsigned char *)encryption_password,
		       strlen(encryption_password),
		       100, enc_key, enc_iv)))
		{
			logp("EVP_BytesToKey failed\n");
			goto error;
		}
	}
	else
	{
		// Old, bad way.
		// Declare enc_iv with individual characters so that the weird
		// last character can be specified as a hex number in order to
		// prevent compilation warnings on Macs.
		uint8_t new_enc[]={
			'[', 'l', 'k', 'd', '.', '$', 'G', 0xa3, '\0'
		};
		memcpy(enc_iv, new_enc, 9);
		strcpy((char*)enc_key, encryption_password);
		key_len=strlen(encryption_password);
	}

	if(!(ctx=(EVP_CIPHER_CTX *)EVP_CIPHER_CTX_new()))
	{
		logp("EVP_CIPHER_CTX_new() failed\n");
		goto error;
	}

	// Don't set key or IV because we will modify the parameters.
	EVP_CIPHER_CTX_init(ctx);
	if(!(EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, encrypt)))
	{
		logp("EVP_CipherInit_ex failed\n");
		goto error;
	}
	if(!EVP_CIPHER_CTX_set_key_length(ctx, key_len))
	{
		logp("EVP_CIPHER_CTX_set_key_length failed\n");
		goto error;
	}
	// We finished modifying parameters so now we can set key and IV

	if(!EVP_CipherInit_ex(ctx, NULL, NULL,
		enc_key, enc_iv, encrypt))
	{
		logp("Second EVP_CipherInit_ex failed\n");
		goto error;
	}
	return ctx;
error:
	if(ctx)
	{
		EVP_CIPHER_CTX_cleanup(ctx);
		EVP_CIPHER_CTX_free(ctx);
		ctx=NULL;
	}
	return NULL;
}

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
enum send_e send_whole_file_gzl(struct asfd *asfd, const char *datapth,
	int quick_read, uint64_t *bytes, const char *encpassword,
	struct cntr *cntr, int compression, struct BFILE *bfd,
	const char *extrameta, size_t elen, int key_deriv, uint64_t salt)
{
	enum send_e ret=SEND_OK;
	int zret=0;
	struct md5 *md5=NULL;
	size_t metalen=0;
	const char *metadata=NULL;
	struct iobuf wbuf;

	int have;
	z_stream strm;
	int flush=Z_NO_FLUSH;
	uint8_t in[ZCHUNK];
	uint8_t out[ZCHUNK];
	ssize_t r;

	int eoutlen;
	uint8_t eoutbuf[ZCHUNK+EVP_MAX_BLOCK_LENGTH];

	EVP_CIPHER_CTX *enc_ctx=NULL;
#ifdef HAVE_WIN32
	int do_known_byte_count=0;
	size_t datalen=bfd->datalen;
	if(datalen>0) do_known_byte_count=1;
#endif

	if(encpassword
	  && !(enc_ctx=enc_setup(1, encpassword, key_deriv, salt)))
		return SEND_FATAL;

	if(!(md5=md5_alloc(__func__)))
		return SEND_FATAL;

	if(!md5_init(md5))
	{
		logp("md5_init() failed\n");
		md5_free(&md5);
		return SEND_FATAL;
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
		8, Z_DEFAULT_STRATEGY))!=Z_OK) {
			md5_free(&md5);
			return SEND_FATAL;
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
				if(datalen<=0)
					r=0;
				else
				{
					r=bfd->read(bfd, in,
						min((size_t)ZCHUNK, datalen));
					if(r>0)
						datalen-=r;
				}
			}
			else
#endif
				r=bfd->read(bfd, in, ZCHUNK);

			if(r<0)
			{
				logw(asfd, cntr,
					"Error when reading %s in %s: %s\n",
					bfd->path, __func__, strerror(errno));
				ret=SEND_ERROR;
				break;
			}
			strm.avail_in=(uint32_t)r;
		}
		if(!compression && !strm.avail_in)
			break;

		*bytes+=strm.avail_in;

		// The checksum needs to be later if encryption is being used.
		if(!enc_ctx)
		{
			if(!md5_update(md5, in, strm.avail_in))
			{
				logp("md5_update() failed\n");
				ret=SEND_FATAL;
				break;
			}
		}

#ifdef HAVE_WIN32
		if(do_known_byte_count && datalen<=0)
			flush=Z_FINISH;
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
					logw(asfd, cntr, "z_stream_error when reading %s in %s\n", bfd->path, __func__);
					ret=SEND_ERROR;
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
					eoutbuf, &eoutlen, md5))
				{
					ret=SEND_FATAL;
					break;
				}
			}
			else
			{
				iobuf_set(&wbuf, CMD_APPEND, (char *)out, have);
				if(asfd->write(asfd, &wbuf))
				{
					ret=SEND_FATAL;
					break;
				}
			}
			if(quick_read && datapth)
			{
				int qr;
				if((qr=do_quick_read(asfd, datapth, cntr))<0)
				{
					ret=SEND_FATAL;
					break;
				}
				if(qr) // client wants to interrupt
				{
					goto cleanup;
				}
			}
			if(!compression) break;
		} while (!strm.avail_out);

		if(ret!=SEND_OK) break;

		if(!compression) continue;

		if(strm.avail_in) /* all input will be used */
		{
			ret=SEND_FATAL;
			logp("strm.avail_in=%d\n", strm.avail_in);
			break;
		}
	} while(flush!=Z_FINISH);

	if(ret==SEND_OK)
	{
		if(compression && zret!=Z_STREAM_END)
		{
			logp("ret OK, but zstream not finished: %d\n", zret);
			ret=SEND_FATAL;
		}
		else if(enc_ctx)
		{
			if(!EVP_CipherFinal_ex(enc_ctx, eoutbuf, &eoutlen))
			{
				logp("Encryption failure at the end\n");
				ret=SEND_FATAL;
			}
			else if(eoutlen>0)
			{
				iobuf_set(&wbuf, CMD_APPEND,
					(char *)eoutbuf, (size_t)eoutlen);
				if(asfd->write(asfd, &wbuf))
					ret=SEND_FATAL;
				else if(!md5_update(md5, eoutbuf, eoutlen))
				{
					logp("md5_update() failed\n");
					ret=SEND_FATAL;
				}
			}
		}
	}

cleanup:
	deflateEnd(&strm);

	if(enc_ctx)
	{
		EVP_CIPHER_CTX_cleanup(enc_ctx);
		EVP_CIPHER_CTX_free(enc_ctx);
		enc_ctx=NULL;
	}

	if(ret==SEND_OK)
	{
		uint8_t checksum[MD5_DIGEST_LENGTH];
		if(!md5_final(md5, checksum))
		{
			logp("md5_final() failed\n");
			md5_free(&md5);
			return SEND_FATAL;
		}
		if(write_endfile(asfd, *bytes, checksum))
			return SEND_FATAL;
	}
	md5_free(&md5);
	return ret;
}

#ifdef HAVE_WIN32
struct winbuf
{
	struct md5 *md5;
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
	if(!md5_update(mybuf->md5, pbData, ulLength))
	{
		logp("md5_update() failed\n");
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

enum send_e send_whole_filel(struct asfd *asfd,
#ifdef HAVE_WIN32
	enum cmd cmd,
#endif
	const char *datapth,
	int quick_read, uint64_t *bytes, struct cntr *cntr,
	struct BFILE *bfd, const char *extrameta, size_t elen)
{
	enum send_e ret=SEND_OK;
	ssize_t s=0;
	struct md5 *md5=NULL;
	char buf[4096]="";
	struct iobuf wbuf;

	if(!bfd)
	{
		logp("No bfd in %s()\n", __func__);
		return SEND_FATAL;
	}

	if(!(md5=md5_alloc(__func__)))
		return SEND_FATAL;
	if(!md5_init(md5))
	{
		logp("md5_init() failed\n");
		md5_free(&md5);
		return SEND_FATAL;
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

			if(!md5_update(md5, metadata, s))
			{
				logp("md5_update() failed\n");
				ret=SEND_FATAL;
			}
			iobuf_set(&wbuf, CMD_APPEND, (char *)metadata, s);
			if(asfd->write(asfd, &wbuf))
				ret=SEND_FATAL;

			metadata+=s;
			metalen-=s;

			*bytes+=s;
		}
	}
	else
	{
#ifdef HAVE_WIN32
		if(ret==SEND_OK && cmd==CMD_EFS_FILE)
		{
			struct winbuf mybuf;
			mybuf.md5=md5;
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

		if(ret==SEND_OK)
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
				s=bfd->read(bfd,
					buf, min((size_t)4096, datalen));
				if(s>0)
					datalen-=s;
			}
			else
			{
#endif
				s=bfd->read(bfd, buf, 4096);
#ifdef HAVE_WIN32
			}
#endif
			if(!s)
				break;
			else if(s<0)
			{
				logw(asfd, cntr,
					"Error when reading %s in %s: %s\n",
					bfd->path, __func__, strerror(errno));
				ret=SEND_ERROR;
				break;
			}

			*bytes+=s;
			if(!md5_update(md5, buf, s))
			{
				logp("md5_update() failed\n");
				ret=SEND_FATAL;
				break;
			}
			iobuf_set(&wbuf, CMD_APPEND, buf, s);
			if(asfd->write(asfd, &wbuf))
			{
				ret=SEND_FATAL;
				break;
			}
			if(quick_read)
			{
				int qr;
				if((qr=do_quick_read(asfd, datapth, cntr))<0)
				{
					ret=SEND_FATAL;
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
	if(ret!=SEND_FATAL)
	{
		uint8_t checksum[MD5_DIGEST_LENGTH];
		if(!md5_final(md5, checksum))
		{
			logp("md5_final() failed\n");
			md5_free(&md5);
			return SEND_FATAL;
		}
		if(write_endfile(asfd, *bytes, checksum))
			return SEND_FATAL;
	}
	md5_free(&md5);
	return ret;
}
