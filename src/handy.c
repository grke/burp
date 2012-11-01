#include "burp.h"
#include "handy.h"
#include "prog.h"
#include "msg.h"
#include "asyncio.h"
#include "counter.h"
#include "find.h"
#include "berrno.h"
#include "forkchild.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#ifdef HAVE_WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

void close_fd(int *fd)
{
	if(*fd<0) return;
	//logp("closing %d\n", *fd);
	close(*fd);
	*fd=-1;
}

int close_fp(FILE **fp)
{
	if(!*fp) return 0;
	if(fclose(*fp))
	{
		logp("fclose failed: %s\n", strerror(errno));
		*fp=NULL;
		return -1;
	}
	*fp=NULL;
	return 0;
}

int gzclose_fp(gzFile *fp)
{
	int e;
	if(!*fp) return 0;
	if((e=gzclose(*fp)))
	{
		const char *str=NULL;
		if(e==Z_ERRNO) str=strerror(errno);
		else str=gzerror(*fp, &e);
		logp("gzclose failed: %d (%s)\n", e, str?:"");
		*fp=NULL;
		return -1;
	}
	*fp=NULL;
	return 0;
}

int is_dir(const char *path)
{
        struct stat buf;

        if(lstat(path, &buf)) return 0;

        return S_ISDIR(buf.st_mode);
}

int mkpath(char **rpath, const char *limit)
{
	char *cp=NULL;
	struct stat buf;
	//printf("mkpath: %s\n", *rpath);
	if((cp=strrchr(*rpath, '/')))
	{
#ifdef HAVE_WIN32
		int windows_stupidity=0;
		*cp='\0';
		if(strlen(*rpath)==2 && (*rpath)[1]==':')
		{
			(*rpath)[1]='\0';
			windows_stupidity++;
		}
#else
		*cp='\0';
#endif
		if(!**rpath)
		{
			// We are down to the root, which is OK.
		}
		else if(lstat(*rpath, &buf))
		{
			// does not exist - recurse further down, then come
			// back and try to mkdir it.
			if(mkpath(rpath, limit)) return -1;

			// Require that the user has set up the required paths
			// on the server correctly. I have seen problems with
			// part of the path being a temporary symlink that
			// gets replaced by burp with a proper directory.
			// Allow it to create the actual directory specified,
			// though.

			// That is, if limit is:
			// /var/spool/burp
			// and /var/spool exists, the directory will be
			// created.
			// If only /var exists, the directory will not be
			// created.

			// Caller can give limit=NULL to create the whole
			// path with no limit, as in a restore.
			if(limit && pathcmp(*rpath, limit)<0)
			{
				logp("will not mkdir %s\n", *rpath);
#ifdef HAVE_WIN32
				if(windows_stupidity) (*rpath)[1]=':';
#endif
				*cp='/';
				return -1;
			}
			if(mkdir(*rpath, 0777))
			{
				logp("could not mkdir %s: %s\n", *rpath, strerror(errno));
#ifdef HAVE_WIN32
				if(windows_stupidity) (*rpath)[1]=':';
#endif
				*cp='/';
				return -1;
			}
		}
		else if(S_ISDIR(buf.st_mode))
		{
			// Is a directory - can put the slash back and return.
		}
		else if(S_ISLNK(buf.st_mode))
		{
			// to help with the 'current' symlink
		}
		else
		{
			// something funny going on
			logp("warning: wanted '%s' to be a directory\n",
				*rpath);
		}
#ifdef HAVE_WIN32
		if(windows_stupidity) (*rpath)[1]=':';
#endif
		*cp='/';
	}
	return 0;
}

int build_path(const char *datadir, const char *fname, size_t flen, char **rpath, const char *limit)
{
	//logp("build path: '%s/%s'\n", datadir, fname);
	if(!(*rpath=prepend_s(datadir, fname, flen))) return -1;
	if(mkpath(rpath, limit))
	{
		if(*rpath) { free(*rpath); *rpath=NULL; }
		return -1;
	}
	return 0;
}

// return -1 for error, 0 for OK, 1 if the client wants to interrupt the
// transfer.
int do_quick_read(const char *datapth, struct cntr *cntr)
{
	int r=0;
	char cmd;
	size_t len=0;
	char *buf=NULL;
	if(async_read_quick(&cmd, &buf, &len)) return -1;

	if(buf)
	{
		if(cmd==CMD_WARNING)
		{
			logp("WARNING: %s\n", buf);
			do_filecounter(cntr, cmd, 0);
		}
		else if(cmd==CMD_INTERRUPT)
		{
			// Client wants to interrupt - double check that
			// it is still talking about the file that we are
			// sending.
			if(datapth && !strcmp(buf, datapth))
				r=1;
		}
		else
		{
			logp("unexpected cmd in quick read: %c:%s\n", cmd, buf);
			r=-1;
		}
		free(buf);
	}
	return r;
}

char *get_checksum_str(unsigned char *checksum)
{
	//int i=0;
	//char tmp[3]="";
	static char str[64]="";
/*
	str[0]='\0';
	// Windows does not seem to like me writing it all at the same time.
	// Fuck knows why.
	for(i=0; i<MD5_DIGEST_LENGTH; i++)
	{
		snprintf(tmp, sizeof(tmp), "%02x", checksum[i]);
		strcat(str, tmp);
	}
*/
	snprintf(str, sizeof(str),
	  "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		checksum[0], checksum[1],
		checksum[2], checksum[3],
		checksum[4], checksum[5],
		checksum[6], checksum[7],
		checksum[8], checksum[9],
		checksum[10], checksum[11],
		checksum[12], checksum[13],
		checksum[14], checksum[15]);
	return str;
}

int write_endfile(unsigned long long bytes, unsigned char *checksum)
{
	int ret=0;
	char endmsg[128]="";

	snprintf(endmsg, sizeof(endmsg),
#ifdef HAVE_WIN32
		"%I64u:%s",
#else
		"%llu:%s",
#endif
		bytes, get_checksum_str(checksum));
	ret=async_write_str(CMD_END_FILE, endmsg);
	return ret;
}

static int do_encryption(EVP_CIPHER_CTX *ctx, unsigned char *inbuf, size_t inlen, unsigned char *outbuf, size_t *outlen, MD5_CTX *md5)
{
	if(!inlen) return 0;
	if(!EVP_CipherUpdate(ctx, outbuf, (int *)outlen, inbuf, (int)inlen))
	{
		logp("Encryption failure.\n");
		return -1;
	}
	if(*outlen>0)
	{
		int ret;
		if(!(ret=async_write(CMD_APPEND, (const char *)outbuf, *outlen)))
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

int open_file_for_send(BFILE *bfd, FILE **fp, const char *fname, int64_t winattr, size_t *datalen, struct cntr *cntr)
{
	if(fp)
	{
		if(!(*fp=fopen(fname, "rb")))
		{
			logw(cntr,
				"Could not open %s: %s\n", fname, strerror(errno));
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
				close_file_for_send(bfd, NULL);
			}
		}
		binit(bfd, winattr);
		*datalen=0;
		if(bopen(bfd, fname, O_RDONLY | O_BINARY | O_NOATIME, 0,
			(winattr & FILE_ATTRIBUTE_DIRECTORY))<=0)
		{
			berrno be;
			logw(cntr, "Could not open %s: %s\n",
				fname, be.bstrerror(errno));
			return -1;
		}
	}
#endif
	return 0;
}

int close_file_for_send(BFILE *bfd, FILE **fp)
{
	if(fp) return close_fp(fp);
#ifdef HAVE_WIN32
	if(bfd) return bclose(bfd);
#endif
	return -1;
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
int send_whole_file_gz(const char *fname, const char *datapth, int quick_read, unsigned long long *bytes, const char *encpassword, struct cntr *cntr, int compression, BFILE *bfd, FILE *fp, const char *extrameta, size_t elen, size_t datalen)
{
	int ret=0;
	int zret=0;
	MD5_CTX md5;
	size_t metalen=0;
	const char *metadata=NULL;

	unsigned have;
	z_stream strm;
	int flush=Z_NO_FLUSH;
	unsigned char in[ZCHUNK];
	unsigned char out[ZCHUNK];

	size_t eoutlen;
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
			else if(async_write(CMD_APPEND, (const char *)out, have))
			{
				ret=-1;
				break;
			}
			if(quick_read && datapth)
			{
				int qr;
				if((qr=do_quick_read(datapth, cntr))<0)
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
			if(!EVP_CipherFinal_ex(enc_ctx,
				eoutbuf, (int *)&eoutlen))
			{
				logp("Encryption failure at the end\n");
				ret=-1;
			}
			else if(eoutlen>0)
			{
			  if(async_write(CMD_APPEND, (const char *)eoutbuf, eoutlen))
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

static DWORD WINAPI write_efs(PBYTE pbData, PVOID pvCallbackContext, ULONG ulLength)
{
	struct winbuf *mybuf=(struct winbuf *)pvCallbackContext;
	(*(mybuf->bytes))+=ulLength;
	if(!MD5_Update(mybuf->md5, pbData, ulLength))
	{
		logp("MD5_Update() failed\n");
		return ERROR_FUNCTION_FAILED;
	}
	if(async_write(CMD_APPEND, (const char *)pbData, ulLength))
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

int send_whole_file(char cmd, const char *fname, const char *datapth, int quick_read, unsigned long long *bytes, struct cntr *cntr, BFILE *bfd, FILE *fp, const char *extrameta, size_t elen, size_t datalen)
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
			if(async_write(CMD_APPEND, metadata, s))
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
			if(async_write(CMD_APPEND, buf, s))
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
			if(async_write(CMD_APPEND, buf, s))
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

int set_non_blocking(int fd)
{
    int flags;
    if((flags = fcntl(fd, F_GETFL, 0))<0) flags = 0;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
     
int set_blocking(int fd)
{
    int flags;
    if((flags = fcntl(fd, F_GETFL, 0))<0) flags = 0;
    return fcntl(fd, F_SETFL, flags | ~O_NONBLOCK);
}

int do_rename(const char *oldpath, const char *newpath)
{
	if(rename(oldpath, newpath))
	{
		logp("could not rename '%s' to '%s': %s\n",
			oldpath, newpath, strerror(errno)); 
		return -1; 
	}
	return 0;
}

char *get_tmp_filename(const char *basis)
{
	char *ret=NULL;
	ret=prepend(basis, ".tmp", strlen(".tmp"), 0 /* no slash */);
	return ret;
}

void add_fd_to_sets(int fd, fd_set *read_set, fd_set *write_set, fd_set *err_set, int *max_fd)
{
	if(read_set) FD_SET((unsigned int) fd, read_set);
	if(write_set) FD_SET((unsigned int) fd, write_set);
	if(err_set) FD_SET((unsigned int) fd, err_set);

	if(fd > *max_fd) *max_fd = fd;
}

int init_client_socket(const char *host, const char *port)
{
	int rfd=-1;
	int gai_ret;
	struct addrinfo hints;
	struct addrinfo *result;
	struct addrinfo *rp;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	if((gai_ret=getaddrinfo(host, port, &hints, &result)))
	{
		logp("getaddrinfo: %s\n", gai_strerror(rfd));
		return -1;
	}

	for(rp=result; rp; rp=rp->ai_next)
	{
		rfd=socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(rfd<0) continue;
		if(connect(rfd, rp->ai_addr, rp->ai_addrlen) != -1) break;
		close_fd(&rfd);
	}
	freeaddrinfo(result);
	if(!rp)
	{
		/* host==NULL and AI_PASSIVE not set -> loopback */
		logp("could not connect to %s:%s\n",
			host?host:"loopback", port);
		close_fd(&rfd);
		return -1;
	}
	reuseaddr(rfd);

#ifdef HAVE_WIN32
	setmode(rfd, O_BINARY);
#endif
	return rfd;
}

void reuseaddr(int fd)
{
	int tmpfd;
	if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		(sockopt_val_t)&tmpfd, sizeof(tmpfd))<0)
			logp("Error: setsockopt SO_REUSEADDR: %s",
				strerror(errno));
}

#ifndef HAVE_WIN32

void write_status(const char *client, char phase, const char *path, struct cntr *p1cntr, struct cntr *cntr)
{
	static time_t lasttime=0;
	if(status_wfd>=0 && client)
	{
		char *w=NULL;
		time_t now=0;
		time_t diff=0;
		static char wbuf[1024]="";

		// Only update every 2 seconds.
		now=time(NULL);
		diff=now-lasttime;
		if(diff<2)
		{
			// Might as well do this in case they fiddled their
			// clock back in time.
			if(diff<0) lasttime=now;
			return;
		}
		lasttime=now;

		counters_to_str(wbuf, sizeof(wbuf),
			client, phase, path, p1cntr, cntr);

		w=wbuf;
		while(*w)
		{
			size_t wl=0;
			if((wl=write(status_wfd, w, strlen(w)))<0)
			{
				logp("error writing status down pipe to server: %s\n", strerror(errno));
				close_fd(&status_wfd);
				break;
			}
			w+=wl;
		}
	}
}

static void log_script_output(FILE **fp, struct cntr *cntr, int logfunc)
{
	char buf[256]="";
	if(fp && *fp)
	{
		if(fgets(buf, sizeof(buf), *fp))
		{
			// logc does not print a prefix
			if(logfunc) logp("%s", buf);
			else logc("%s", buf);
			if(cntr) logw(cntr, "%s", buf);
		}
		if(feof(*fp))
		{
			fclose(*fp);
			*fp=NULL;
		}
	}
}

static int got_sigchld=0;
static int run_script_status=-1;

static void run_script_sigchld_handler(int sig)
{
	//printf("in run_script_sigchld_handler\n");
	got_sigchld=1;
	run_script_status=-1;
	waitpid(-1, &run_script_status, 0);
}

void setup_signal(int sig, void handler(int sig))
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler=handler;
	sigaction(sig, &sa, NULL);
}

static int run_script_select(FILE **sout, FILE **serr, struct cntr *cntr, int logfunc)
{
	int mfd=-1;
	fd_set fsr;
	struct timeval tval;
	int soutfd=fileno(*sout);
	int serrfd=fileno(*serr);
	setlinebuf(*sout);
	setlinebuf(*serr);
	set_non_blocking(soutfd);
	set_non_blocking(serrfd);

	while(1)
	{
		mfd=-1;
		FD_ZERO(&fsr);
		if(*sout) add_fd_to_sets(soutfd, &fsr, NULL, NULL, &mfd);
		if(*serr) add_fd_to_sets(serrfd, &fsr, NULL, NULL, &mfd);
		tval.tv_sec=1;
		tval.tv_usec=0;
		if(select(mfd+1, &fsr, NULL, NULL, &tval)<0)
		{
			if(errno!=EAGAIN && errno!=EINTR)
			{
				logp("run_script_select error: %s\n",
					strerror(errno));
				return -1;
			}
		}
		if(FD_ISSET(soutfd, &fsr))
			log_script_output(sout, NULL, logfunc);
		if(FD_ISSET(serrfd, &fsr))
			log_script_output(serr, cntr, logfunc);

		if(!*sout && !*serr && got_sigchld)
		{
			//fclose(*sout); *sout=NULL;
			//fclose(*serr); *serr=NULL;
			got_sigchld=0;
			return 0;
		}
	}

	// Never get here.
	return -1;
}

#endif

/* TODO: make arg1..n an array */
int run_script(const char *script, struct strlist **userargs, int userargc, const char *arg1, const char *arg2, const char *arg3, const char *arg4, const char *arg5, const char *arg6, const char *arg7, const char *arg8, const char *arg9, const char *arg10, struct cntr *cntr, int do_wait, int logfunc)
{
	int a=0;
	int l=0;
	pid_t p;
	FILE *serr=NULL;
	FILE *sout=NULL;
	char *cmd[64]={ NULL };
#ifndef HAVE_WIN32
	int s=0;
#endif
	if(!script) return 0;

	cmd[l++]=(char *)script;
	if(arg1) cmd[l++]=(char *)arg1;
	if(arg2) cmd[l++]=(char *)arg2;
	if(arg3) cmd[l++]=(char *)arg3;
	if(arg4) cmd[l++]=(char *)arg4;
	if(arg5) cmd[l++]=(char *)arg5;
	if(arg6) cmd[l++]=(char *)arg6;
	if(arg7) cmd[l++]=(char *)arg7;
	if(arg8) cmd[l++]=(char *)arg8;
	if(arg9) cmd[l++]=(char *)arg9;
	if(arg10) cmd[l++]=(char *)arg10;
	for(a=0; a<userargc && l<64-1; a++)
		cmd[l++]=userargs[a]->path;
	cmd[l++]=NULL;

#ifndef HAVE_WIN32
	setup_signal(SIGCHLD, run_script_sigchld_handler);
#endif

	fflush(stdout); fflush(stderr);
	if(do_wait)
	{
		if((p=forkchild(NULL,
			&sout, &serr, cmd[0], cmd))==-1) return -1;
	}
	else
	{
		if((p=forkchild_no_wait(NULL,
			&sout, &serr, cmd[0], cmd))==-1) return -1;
		return 0;
	}
#ifdef HAVE_WIN32
	// My windows forkchild currently just executes, then returns.
	return 0;
#else
	s=run_script_select(&sout, &serr, cntr, logfunc);

	// Set SIGCHLD back to default.
	setup_signal(SIGCHLD, SIG_DFL);

	if(s) return -1;

	if(WIFEXITED(run_script_status))
	{
		int ret=WEXITSTATUS(run_script_status);
		logp("%s returned: %d\n", script, ret);
		if(cntr && ret) logw(cntr, "%s returned: %d\n",
			script, ret);
		return ret;
	}
	else if(WIFSIGNALED(run_script_status))
	{
		logp("%s terminated on signal %d\n",
			script, WTERMSIG(run_script_status));
		if(cntr) logw(cntr, "%s terminated on signal %d\n",
			script, WTERMSIG(run_script_status));
	}
	else
	{
		logp("Strange return when trying to run %s\n", script);
		if(cntr) logw(cntr, "Strange return when trying to run %s\n",
			script);
	}
	return -1;
#endif
}

char *comp_level(struct config *conf)
{
	static char comp[8]="";
	snprintf(comp, sizeof(comp), "wb%d", conf->compression);
	return comp;
}

/* Function based on src/lib/priv.c from bacula. */
int chuser_and_or_chgrp(const char *user, const char *group)
{
#if defined(HAVE_PWD_H) && defined(HAVE_GRP_H)
	struct passwd *passw = NULL;
	struct group *grp = NULL;
	gid_t gid;
	uid_t uid;
	char *username=NULL;

	if(!user && !group) return 0;

	if(user)
	{
		if(!(passw=getpwnam(user)))
		{
			logp("could not find user '%s': %s\n",
				user, strerror(errno));
			return -1;
		}
	}
	else
	{
		if(!(passw=getpwuid(getuid())))
		{
			logp("could not find password entry: %s\n",
				strerror(errno));
			return -1;
		}
		user=passw->pw_name;
	}
	// Any OS uname pointer may get overwritten, so save name, uid, and gid
	if(!(username=strdup(user)))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	uid=passw->pw_uid;
	gid=passw->pw_gid;
	if(group)
	{
		if(!(grp=getgrnam(group)))
		{
			logp("could not find group '%s': %s\n", group,
				strerror(errno));
			free(username);
			return -1;
		}
		gid=grp->gr_gid;
	}
	if(gid!=getgid() // do not do it if we already have the same gid.
	  && initgroups(username, gid))
	{
		if(grp)
			logp("could not initgroups for group '%s', user '%s': %s\n", group, user, strerror(errno));
		else
			logp("could not initgroups for user '%s': %s\n", user, strerror(errno));
		free(username);
		return -1;
	}
	free(username);
	if(grp)
	{
		if(gid!=getgid() // do not do it if we already have the same gid
		 && setgid(gid))
		{
			logp("could not set group '%s': %s\n", group,
				strerror(errno));
			return -1;
		}
	}
	if(uid!=getuid() // do not do it if we already have the same uid
	  && setuid(uid))
	{
		logp("could not set specified user '%s': %s\n", username,
			strerror(errno));
		return -1;
	}
#endif
	return 0;
}

const char *getdatestr(time_t t)
{
	static char buf[32]="";
	const struct tm *ctm=NULL;

	if(!t) return "never";

	ctm=localtime(&t);

	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", ctm);
	return buf;
}

const char *time_taken(time_t d)
{
	static char str[32]="";
	int seconds=0;
	int minutes=0;
	int hours=0;
	int days=0;
	char ss[4]="";
	char ms[4]="";
	char hs[4]="";
	char ds[4]="";
	seconds=d % 60;
	minutes=(d/60) % 60;
	hours=(d/60/60) % 24;
	days=(d/60/60/24);
	if(days)
	{
		snprintf(ds, sizeof(ds), "%02d:", days);
		snprintf(hs, sizeof(hs), "%02d:", hours);
	}
	else if(hours)
	{
		snprintf(hs, sizeof(hs), "%02d:", hours);
	}
	snprintf(ms, sizeof(ms), "%02d:", minutes);
	snprintf(ss, sizeof(ss), "%02d", seconds);
	snprintf(str, sizeof(str), "%s%s%s%s", ds, hs, ms, ss);
	return str;
}

// Not in dpth.c so that Windows client can see it.
int dpth_is_compressed(int compressed, const char *datapath)
{
	const char *dp=NULL;

	if(compressed>0) return compressed;
	if(compressed==0) return 0;

	/* Legacy - if the compressed value is -1 - that is, it is not set in
	   the manifest, deduce the value from the datapath. */
	if((dp=strrchr(datapath, '.')) && !strcmp(dp, ".gz")) return 1;
	return 0;
}

void cmd_to_text(char cmd, char *buf, size_t len)
{
	switch(cmd)
	{
		case CMD_DATAPTH:
			snprintf(buf, len, "Path to data on the server"); break;
		case CMD_STAT:
			snprintf(buf, len, "File stat information"); break;
		case CMD_FILE:
			snprintf(buf, len, "Plain file"); break;
		case CMD_ENC_FILE:
			snprintf(buf, len, "Encrypted file"); break;
		case CMD_DIRECTORY:
			snprintf(buf, len, "Directory"); break;
		case CMD_SOFT_LINK:
			snprintf(buf, len, "Soft link"); break;
		case CMD_HARD_LINK:
			snprintf(buf, len, "Hard link"); break;
		case CMD_SPECIAL:
			snprintf(buf, len, "Special file - fifo, socket, device node"); break;
		case CMD_METADATA:
			snprintf(buf, len, "Extra meta data"); break;
		case CMD_GEN:
			snprintf(buf, len, "Generic command"); break;
		case CMD_ERROR:
			snprintf(buf, len, "Error message"); break;
		case CMD_APPEND:
			snprintf(buf, len, "Append to a file"); break;
		case CMD_INTERRUPT:
			snprintf(buf, len, "Interrupt"); break;
		case CMD_WARNING:
			snprintf(buf, len, "Warning"); break;
		case CMD_END_FILE:
			snprintf(buf, len, "End of file transmission"); break;
		case CMD_ENC_METADATA:
			snprintf(buf, len, "Encrypted meta data"); break;
		case CMD_EFS_FILE:
			snprintf(buf, len, "Windows EFS file"); break;
		case CMD_FILE_CHANGED:
			snprintf(buf, len, "Plain file changed"); break;
		case CMD_TIMESTAMP:
			snprintf(buf, len, "Backup timestamp"); break;
		case CMD_VSS:
			snprintf(buf, len, "Windows VSS header"); break;
		case CMD_ENC_VSS:
			snprintf(buf, len, "Encrypted windows VSS header"); break;
		case CMD_VSS_T:
			snprintf(buf, len, "Windows VSS footer"); break;
		case CMD_ENC_VSS_T:
			snprintf(buf, len, "Encrypted windows VSS footer"); break;
		default:
			snprintf(buf, len, "----------------"); break;
	}
}

void print_all_cmds(void)
{
	int i=0;
	char buf[256]="";
	char cmds[256]="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	size_t len=sizeof(buf);
	printf("\nIndex of symbols\n\n");
	for(i=0; cmds[i]; i++)
	{
		cmd_to_text(cmds[i], buf, len);
		printf("  %c: %s\n", cmds[i], buf);
	}
	printf("\n");
}

void log_restore_settings(struct config *cconf, int srestore)
{
	int i=0;
	logp("Restore settings:\n");
	if(cconf->orig_client)
		logp("orig_client = %s\n", cconf->orig_client);
	logp("backup = %s\n", cconf->backup);
	if(srestore)
	{
		// This are unknown unless doing a server initiated restore.
		logp("overwrite = %d\n", cconf->overwrite);
		logp("strip = %d\n", cconf->strip);
	}
	if(cconf->restoreprefix)
		logp("restoreprefix = %s\n", cconf->restoreprefix);
	if(cconf->regex) logp("regex = %s\n", cconf->regex);
	for(i=0; i<cconf->iecount; i++)
	{
		if(cconf->incexcdir[i]->flag)
			logp("include = %s\n", cconf->incexcdir[i]->path);
	}
}

long version_to_long(const char *version)
{
	long ret=0;
	char *copy=NULL;
	char *tok1=NULL;
	char *tok2=NULL;
	char *tok3=NULL;
	if(!version || !*version) return 0;
	if(!(copy=strdup(version)))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	if(!(tok1=strtok(copy, "."))
	  || !(tok2=strtok(NULL, "."))
	  || !(tok3=strtok(NULL, ".")))
	{
		free(copy);
		return -1;
	}
	ret+=atol(tok3);
	ret+=atol(tok2)*100;
	ret+=atol(tok1)*100*100;
	free(copy);
	return ret;
}

/* These receive_a_file() and send_file() functions are for use by extra_comms
   and the CA stuff, rather than backups/restores. */
int receive_a_file(const char *path, struct cntr *p1cntr)
{
	int c=0;
	int ret=0;
#ifdef HAVE_WIN32
	BFILE bfd;
#else
	FILE *fp=NULL;
#endif
	unsigned long long rcvdbytes=0;
	unsigned long long sentbytes=0;

#ifdef HAVE_WIN32
	binit(&bfd, 0);
	bfd.use_backup_api=0;
	//set_win32_backup(&bfd);
	if(bopen(&bfd, path,
		O_WRONLY | O_CREAT | O_TRUNC | O_BINARY,
		S_IRUSR | S_IWUSR, 0)<=0)
	{
		berrno be;
		logp("Could not open for writing %s: %s\n",
			path, be.bstrerror(errno));
		ret=-1;
		goto end;
	}
#else
	if(!(fp=open_file(path, "wb")))
	{
		ret=-1;
		goto end;
	}
#endif

#ifdef HAVE_WIN32
	ret=transfer_gzfile_in(NULL, path, &bfd, NULL,
		&rcvdbytes, &sentbytes, NULL, 0, p1cntr, NULL);
	c=bclose(&bfd);
#else
	ret=transfer_gzfile_in(NULL, path, NULL, fp,
		&rcvdbytes, &sentbytes, NULL, 0, p1cntr, NULL);
	c=close_fp(&fp);
#endif
end:
	if(c)
	{
		logp("error closing %s in receive_a_file\n", path);
		ret=-1;
	}
	if(!ret) logp("Received: %s\n", path);
	return ret;
}

/* Windows will use this function, when sending a certificate signing request.
   It is not using the Windows API stuff because it needs to arrive on the
   server side without any junk in it. */
int send_a_file(const char *path, struct cntr *p1cntr)
{
	int ret=0;
	FILE *fp=NULL;
	size_t datalen=0;
	unsigned long long bytes=0;
	if(open_file_for_send(NULL, &fp, path, 0, &datalen, p1cntr)
	  || send_whole_file_gz(path, "datapth", 0, &bytes, NULL,
		p1cntr, 9, // compression
		NULL, fp, NULL, 0, -1))
	{
		ret=-1;
		goto end;
	}
	logp("Sent %s\n", path);
end:
	close_file_for_send(NULL, &fp);
	return ret;
}
