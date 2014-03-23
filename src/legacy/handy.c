#include "include.h"

static int do_encryption(EVP_CIPHER_CTX *ctx, unsigned char *inbuf, int inlen, unsigned char *outbuf, int *outlen, MD5_CTX *md5)
{
	if(!inlen) return 0;
	if(!EVP_CipherUpdate(ctx, outbuf, outlen, inbuf, inlen))
	{
		logp("Encryption failure.\n");
		return -1;
	}
	if(*outlen>0)
	{
		int ret;
		if(!(ret=async_write_strn(CMD_APPEND,
			(char *)outbuf, (size_t)*outlen)))
		{
			if(!MD5_Update(md5, outbuf, *outlen))
			{
				logp("MD5_Update() failed\n");
				return -1;
			}
		}
		return ret;
	}
	return 0;
}

EVP_CIPHER_CTX *enc_setup(int encrypt, const char *encryption_password)
{
	EVP_CIPHER_CTX *ctx=NULL;
	const char *enc_iv="[lkd.$G£"; // never change this.

	if(!(ctx=(EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX))))
	{
		log_out_of_memory(__FUNCTION__);
		return NULL;
	}
        memset(ctx, 0, sizeof(EVP_CIPHER_CTX));
	// Don't set key or IV because we will modify the parameters.
	EVP_CIPHER_CTX_init(ctx);
	if(!(EVP_CipherInit_ex(ctx, EVP_bf_cbc(), NULL, NULL, NULL, encrypt)))
	{
		logp("EVP_CipherInit_ex failed\n");
		free(ctx);
		return NULL;
	}
	EVP_CIPHER_CTX_set_key_length(ctx, strlen(encryption_password));
	// We finished modifying parameters so now we can set key and IV

	if(!EVP_CipherInit_ex(ctx, NULL, NULL,
		(unsigned char *)encryption_password,
		(unsigned char *)enc_iv, encrypt))
	{
		logp("Second EVP_CipherInit_ex failed\n");
		free(ctx);
		return NULL;
	}
	return ctx;
}

#ifdef HAVE_WIN32
struct bsid {
	int32_t dwStreamId;
	int32_t dwStreamAttributes;
	int64_t Size;
	int32_t dwStreamNameSize;
};
#endif

int open_file_for_sendl(BFILE *bfd, FILE **fp, const char *fname,
	int64_t winattr, size_t *datalen, struct conf *conf)
{
	if(fp)
	{
		static int fd;
		if((fd=open(fname, O_RDONLY|O_NOATIME))<0
		  || !(*fp=fdopen(fd, "rb")))
		{
			logw(conf, "Could not open %s: %s\n",
				fname, strerror(errno));
			return -1;
		}
	}
#ifdef HAVE_WIN32
	else
	{
		if(bfd->mode!=BF_CLOSED)
		{
			if(bfd->path && !strcmp(bfd->path, fname))
			{
				// Already open after reading the VSS data.
				// Time now for the actual file data.
				return 0;
			}
			else
			{
				// Close the open bfd so that it can be
				// used again
				close_file_for_sendl(bfd, NULL);
			}
		}
		binit(bfd, winattr, conf);
		*datalen=0;
		if(bopen(bfd, fname, O_RDONLY | O_BINARY | O_NOATIME, 0)<=0)
		{
			berrno be;
			logw(conf->cntr, "Could not open %s: %s\n",
				fname, be.bstrerror(errno));
			return -1;
		}
	}
#endif
	return 0;
}

int close_file_for_sendl(BFILE *bfd, FILE **fp)
{
	if(fp) return close_fp(fp);
#ifdef HAVE_WIN32
	if(bfd) return bclose(bfd);
#endif
	return -1;
}

char *get_endfile_str(unsigned long long bytes, unsigned char *checksum)
{
	static char endmsg[128]="";
	snprintf(endmsg, sizeof(endmsg),
#ifdef HAVE_WIN32
		"%I64u:%s",
#else
		"%llu:%s",
#endif
		bytes, get_checksum_str(checksum));
	return endmsg;
}

int write_endfile(unsigned long long bytes, unsigned char *checksum)
{
	return async_write_str(CMD_END_FILE, get_endfile_str(bytes, checksum));
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
int send_whole_file_gzl(const char *fname, const char *datapth, int quick_read,
	unsigned long long *bytes, const char *encpassword, struct conf *conf,
	int compression, BFILE *bfd, FILE *fp, const char *extrameta,
	size_t elen, size_t datalen)
{
	int ret=0;
	int zret=0;
	MD5_CTX md5;
	size_t metalen=0;
	const char *metadata=NULL;

	int have;
	z_stream strm;
	int flush=Z_NO_FLUSH;
	unsigned char in[ZCHUNK];
	unsigned char out[ZCHUNK];

	int eoutlen;
	unsigned char eoutbuf[ZCHUNK+EVP_MAX_BLOCK_LENGTH];

	EVP_CIPHER_CTX *enc_ctx=NULL;
#ifdef HAVE_WIN32
	int do_known_byte_count=0;
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
			if(fp) strm.avail_in=fread(in, 1, ZCHUNK, fp);
#ifdef HAVE_WIN32
			else
			{
			  // Windows VSS headers give us how much data to
			  // expect to read.
			  if(do_known_byte_count)
			  {
				  if(datalen<=0) strm.avail_in=0;
				  else strm.avail_in=
					 (uint32_t)bread(bfd, in,
						min((size_t)ZCHUNK, datalen));
				  datalen-=strm.avail_in;
			  }
			  else
			  {
				  strm.avail_in=
					 (uint32_t)bread(bfd, in, ZCHUNK);
			  }
			}
#endif
		}
		if(!compression && !strm.avail_in) break;

		if(strm.avail_in<0)
		{
			logp("Error in read: %d\n", strm.avail_in);
			ret=-1;
			break;
		}
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
				if(do_encryption(enc_ctx, out, have, eoutbuf, &eoutlen, &md5))
				{
					ret=-1;
					break;
				}
			}
			else
			{
				if(async_write_strn(CMD_APPEND,
					(char *)out, (size_t)have))
				{
					ret=-1;
					break;
				}
			}
			if(quick_read && datapth)
			{
				int qr;
				if((qr=do_quick_read(datapth, conf))<0)
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
			  if(async_write_strn(CMD_APPEND,
				(char *)eoutbuf, (size_t)eoutlen))
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
		unsigned char checksum[MD5_DIGEST_LENGTH+1];
		if(!MD5_Final(checksum, &md5))
		{
			logp("MD5_Final() failed\n");
			return -1;
		}

		return write_endfile(*bytes, checksum);
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
	unsigned long long *bytes;
};

static DWORD WINAPI write_efs(PBYTE pbData,
	PVOID pvCallbackContext, ULONG ulLength)
{
	struct winbuf *mybuf=(struct winbuf *)pvCallbackContext;
	(*(mybuf->bytes))+=ulLength;
	if(!MD5_Update(mybuf->md5, pbData, ulLength))
	{
		logp("MD5_Update() failed\n");
		return ERROR_FUNCTION_FAILED;
	}
	if(async_write_strn(CMD_APPEND, (const char *)pbData, ulLength))
	{
		return ERROR_FUNCTION_FAILED;
	}
	if(mybuf->quick_read)
	{
		int qr;
		if((qr=do_quick_read(mybuf->datapth, mybuf->cntr))<0)
			return ERROR_FUNCTION_FAILED;
		if(qr) // client wants to interrupt
			return ERROR_FUNCTION_FAILED;
	}
	return ERROR_SUCCESS;
}
#endif

int send_whole_filel(char cmd, const char *fname, const char *datapth,
	int quick_read, unsigned long long *bytes, struct conf *conf,
	BFILE *bfd, FILE *fp, const char *extrameta,
	size_t elen, size_t datalen)
{
	int ret=0;
	size_t s=0;
	MD5_CTX md5;
	char buf[4096]="";

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
			if(async_write_strn(CMD_APPEND, metadata, s))
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

		if(!ret && cmd!=CMD_EFS_FILE)
		{
		  int do_known_byte_count=0;
		  if(datalen>0) do_known_byte_count=1;
		  while(1)
		  {
			if(do_known_byte_count)
			{
				s=(uint32_t)bread(bfd,
					buf, min((size_t)4096, datalen));
				datalen-=s;
			}
			else
			{
				s=(uint32_t)bread(bfd, buf, 4096);
			}
			if(s<=0) break;

			*bytes+=s;
			if(!MD5_Update(&md5, buf, s))
			{
				logp("MD5_Update() failed\n");
				ret=-1;
				break;
			}
			if(async_write_strn(CMD_APPEND, buf, s))
			{
				ret=-1;
				break;
			}
			if(quick_read)
			{
				int qr;
				if((qr=do_quick_read(datapth, cntr))<0)
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
			// Windows VSS headers tell us how many bytes to
			// expect.
			if(do_known_byte_count && datalen<=0) break;
		  }
		}
#else
	//printf("send_whole_file: %s\n", fname);
		if(!ret) while((s=fread(buf, 1, 4096, fp))>0)
		{
			*bytes+=s;
			if(!MD5_Update(&md5, buf, s))
			{
				logp("MD5_Update() failed\n");
				ret=-1;
				break;
			}
			if(async_write_strn(CMD_APPEND, buf, s))
			{
				ret=-1;
				break;
			}
			if(quick_read)
			{
				int qr;
				if((qr=do_quick_read(datapth, conf))<0)
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
		}
#endif
	}
	if(!ret)
	{
		unsigned char checksum[MD5_DIGEST_LENGTH+1];
		if(!MD5_Final(checksum, &md5))
		{
			logp("MD5_Final() failed\n");
			return -1;
		}
		return write_endfile(*bytes, checksum);
	}
	return ret;
}
