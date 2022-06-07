#include "burp.h"
#include "alloc.h"
#include "cmd.h"
#include "fsops.h"
#include "fzp.h"
#include "log.h"
#include "prepend.h"
#ifndef HAVE_WIN32
#include "server/compress.h"
#include "server/zlibio.h"
#endif

static struct fzp *fzp_alloc(void)
{
	return (struct fzp *)calloc_w(1, sizeof(struct fzp), __func__);
}

static void fzp_free(struct fzp **fzp)
{
	if(!fzp || !*fzp) return;
	free_w(&(*fzp)->buf);
	free_v((void **)fzp);
}

static FILE *open_fp(const char *fname, const char *mode)
{
	FILE *fp=NULL;
	if(!(fp=fopen(fname, mode)))
		logp("could not open %s: %s\n", fname, strerror(errno));
	return fp;
}

static gzFile open_zp(const char *fname, const char *mode)
{
	gzFile zp=NULL;

	if(!(zp=gzopen(fname, mode)))
		logp("could not open %s: %s\n", fname, strerror(errno));
	return zp;
}

static int close_fp(FILE **fp)
{
	int ret=0;
	if(!*fp) return ret;
	if(fclose(*fp))
	{
		logp("fclose failed: %s\n", strerror(errno));
		ret=-1;
	}
	*fp=NULL;
	return ret;
}

static int close_zp(gzFile *zp)
{
	int e;
	int ret=0;
	if(!*zp) return ret;
	if((e=gzclose(*zp))
	// Can return Z_BUF_ERROR if the last read ended in the middle
	// of a gzip stream. I saw this happening in utests on OpenBSD.
	  && e!=Z_BUF_ERROR)
	{
		const char *str=NULL;
		if(e==Z_ERRNO)
			str=strerror(errno);
		logp("gzclose failed: %d (%s)\n", e, str?:"");
		ret=-1;
	}
	return ret;
}

static void unknown_type(enum fzp_type type, const char *func)
{
	logp("unknown type in %s: %d\n", func, type);
}

static void not_open(const char *func)
{
	logp("File pointer not open in %s\n", func);
}

static struct fzp *fzp_do_open(const char *path, const char *mode,
	enum fzp_type type)
{
	struct fzp *fzp=NULL;

	if(!(fzp=fzp_alloc())) goto error;
	fzp->type=type;
	switch(type)
	{
		case FZP_FILE:
			if(!(fzp->fp=open_fp(path, mode)))
				goto error;
			return fzp;
		case FZP_COMPRESSED:
			if(!(fzp->zp=open_zp(path, mode)))
				goto error;
			return fzp;
		default:
			unknown_type(fzp->type, __func__);
			goto error;
	}
error:
	fzp_close(&fzp);
	return NULL;
}

struct fzp *fzp_open(const char *path, const char *mode)
{
	return fzp_do_open(path, mode, FZP_FILE);
}

struct fzp *fzp_gzopen(const char *path, const char *mode)
{
	return fzp_do_open(path, mode, FZP_COMPRESSED);
}

int fzp_close(struct fzp **fzp)
{
	int ret=-1;
	if(!fzp || !*fzp) return 0;
	switch((*fzp)->type)
	{
		case FZP_FILE:
			ret=close_fp(&((*fzp)->fp));
			break;
		case FZP_COMPRESSED:
			ret=close_zp(&((*fzp)->zp));
			break;
		default:
			unknown_type((*fzp)->type, __func__);
			break;
	}
	fzp_free(fzp);
	return ret;
}

int fzp_read(struct fzp *fzp, void *ptr, size_t nmemb)
{
	if(fzp) switch(fzp->type)
	{
		case FZP_FILE:
			return (int)fread(ptr, 1, nmemb, fzp->fp);
		case FZP_COMPRESSED:
			return gzread(fzp->zp, ptr, (unsigned)nmemb);
		default:
			unknown_type(fzp->type, __func__);
			goto error;
	}
	not_open(__func__);
error:
	return 0;
}

size_t fzp_write(struct fzp *fzp, const void *ptr, size_t nmemb)
{
	if(fzp) switch(fzp->type)
	{
		case FZP_FILE:
			return fwrite(ptr, 1, nmemb, fzp->fp);
		case FZP_COMPRESSED:
			return gzwrite(fzp->zp, ptr, (unsigned)nmemb);
		default:
			unknown_type(fzp->type, __func__);
			goto error;
	}
	not_open(__func__);
error:
	return 0;
}

int fzp_eof(struct fzp *fzp)
{
	if(fzp) switch(fzp->type)
	{
		case FZP_FILE:
			return feof(fzp->fp);
		case FZP_COMPRESSED:
			return gzeof(fzp->zp);
		default:
			unknown_type(fzp->type, __func__);
			goto error;
	}
	not_open(__func__);
error:
	// Non-zero means end of file. Should be OK to use -1 here.
	return -1;
}

int fzp_flush(struct fzp *fzp)
{
	if(fzp) switch(fzp->type)
	{
		case FZP_FILE:
			return fflush(fzp->fp);
		case FZP_COMPRESSED:
			return gzflush(fzp->zp, Z_FINISH);
		default:
			unknown_type(fzp->type, __func__);
			goto error;
	}
	not_open(__func__);
error:
	return EOF;
}

int fzp_seek(struct fzp *fzp, off_t offset, int whence)
{
	if(fzp) switch(fzp->type)
	{
		case FZP_FILE:
			return fseeko(fzp->fp, offset, whence);
		case FZP_COMPRESSED:
			// Notice that gzseek returns the new offset.
			if(gzseek(fzp->zp, offset, whence)==offset)
				return 0;
			goto error;
		default:
			unknown_type(fzp->type, __func__);
			goto error;
	}
	not_open(__func__);
error:
	return -1;
}

off_t fzp_tell(struct fzp *fzp)
{
	if(fzp) switch(fzp->type)
	{
		case FZP_FILE:
			return ftello(fzp->fp);
		case FZP_COMPRESSED:
			return gztell(fzp->zp);
		default:
			unknown_type(fzp->type, __func__);
			goto error;
	}
	not_open(__func__);
error:
	return -1;
}

#ifndef HAVE_WIN32
// There is no zlib gztruncate. Inflate it, truncate it, recompress it.
static int gztruncate(const char *path, off_t length, int compression)
{
	int ret=1;
	char tmp[16];
	char *dest=NULL;
	char *dest2=NULL;
	snprintf(tmp, sizeof(tmp), ".%d", getpid());
	if(!(dest=prepend(path, tmp))
	  || !(dest2=prepend(dest, "-2"))
	  || zlib_inflate(NULL, path, dest, NULL))
		goto end;
	if(truncate(dest, length))
	{
		logp("truncate of %s failed in %s\n", dest, __func__);
		goto end;
	}
	if(compress_file(dest, dest2, compression))
		goto end;
	unlink(dest);
	ret=do_rename(dest2, path);
end:
	if(dest) unlink(dest);
	if(dest2) unlink(dest2);
	free_w(&dest);
	free_w(&dest2);
	return ret;
}

int fzp_truncate(const char *path, enum fzp_type type, off_t length,
	int compression)
{
	if(!path)
	{
		// Avoids a valgrind complaint in one of the tests.
		errno=ENOENT;
		goto error;
	}
	switch(type)
	{
		case FZP_FILE:
			return truncate(path, length);
		case FZP_COMPRESSED:
			return gztruncate(path, length, compression);
		default:
			unknown_type(type, __func__);
			goto error;
	}
error:
	return -1;
}
#endif

int fzp_printf(struct fzp *fzp, const char *format, ...)
{
	int ret=-1;
	int n;

	if(!fzp)
	{
		not_open(__func__);
		return ret;
	}

	if(!fzp->buf)
	{
		fzp->s=128;
		if(!(fzp->buf=(char *)malloc_w(fzp->s, __func__)))
			return ret;
	}

	// Avoid fixed size buffer.
	while(1)
	{
		va_list ap;
		va_start(ap, format);
		n=vsnprintf(fzp->buf, fzp->s, format, ap);
		va_end(ap);
		if(n<0)
		{
			logp("Failed to vsnprintf in %s: %s\n",
				__func__, strerror(errno));
			return ret;
		}
		if(fzp->s<(size_t)n+1)
		{
			fzp->s*=2;
			if(!(fzp->buf=(char *)
				realloc_w(fzp->buf, fzp->s, __func__)))
					return ret;
			continue;
		}

		break;
	}

	switch(fzp->type)
	{
		case FZP_FILE:
			ret=fprintf(fzp->fp, "%s", fzp->buf);
			break;
		case FZP_COMPRESSED:
			ret=gzprintf(fzp->zp, "%s", fzp->buf);
			break;
		default:
			unknown_type(fzp->type, __func__);
			break;
	}

	return ret;
}

void fzp_setlinebuf(struct fzp *fzp)
{
#ifndef HAVE_WIN32
	if(fzp) switch(fzp->type)
	{
		case FZP_FILE:
			setlinebuf(fzp->fp);
			return;
		case FZP_COMPRESSED:
			logp("gzsetlinebuf() does not exist in %s\n", __func__);
			return;
		default:
			unknown_type(fzp->type, __func__);
			return;
	}
	not_open(__func__);
#endif
}

char *fzp_gets(struct fzp *fzp, char *s, int size)
{
	if(fzp) switch(fzp->type)
	{
		case FZP_FILE:
			return fgets(s, size, fzp->fp);
		case FZP_COMPRESSED:
			return gzgets(fzp->zp, s, size);
		default:
			unknown_type(fzp->type, __func__);
			goto error;
	}
	not_open(__func__);
error:
	return NULL;
}

extern int fzp_fileno(struct fzp *fzp)
{
	if(fzp) switch(fzp->type)
	{
		case FZP_FILE:
			return fileno(fzp->fp);
		case FZP_COMPRESSED:
			logp("gzfileno() does not exist in %s\n", __func__);
			goto error;
		default:
			unknown_type(fzp->type, __func__);
			goto error;
	}
	not_open(__func__);
error:
	return -1;
}

static struct fzp *fzp_do_dopen(int fd, const char *mode,
	enum fzp_type type)
{
	struct fzp *fzp=NULL;

	if(!(fzp=fzp_alloc())) goto error;
	fzp->type=type;
	switch(type)
	{
		case FZP_FILE:
			if(!(fzp->fp=fdopen(fd, mode)))
				goto error;
			return fzp;
		case FZP_COMPRESSED:
			if(!(fzp->zp=gzdopen(fd, mode)))
				goto error;
			return fzp;
		default:
			unknown_type(fzp->type, __func__);
			goto error;
	}
error:
	fzp_close(&fzp);
	return NULL;
}

struct fzp *fzp_dopen(int fd, const char *mode)
{
	return fzp_do_dopen(fd, mode, FZP_FILE);
}

struct fzp *fzp_gzdopen(int fd, const char *mode)
{
	return fzp_do_dopen(fd, mode, FZP_COMPRESSED);
}

void fzp_ERR_print_errors_fp(struct fzp *fzp)
{
	if(fzp) switch(fzp->type)
	{
		case FZP_FILE:
			ERR_print_errors_fp(fzp->fp);
			break;
		case FZP_COMPRESSED:
			logp("ERR_print_errors_zp() does not exist in %s\n",
				__func__);
			break;
		default:
			unknown_type(fzp->type, __func__);
			break;
	}
}

X509 *fzp_PEM_read_X509(struct fzp *fzp)
{
	if(fzp) switch(fzp->type)
	{
		case FZP_FILE:
			return PEM_read_X509(fzp->fp, NULL, NULL, NULL);
		case FZP_COMPRESSED:
			logp("PEM_read_X509() does not exist in %s\n",
				__func__);
			goto error;
		default:
			unknown_type(fzp->type, __func__);
			goto error;
	}
	not_open(__func__);
error:
	return NULL;
}

static void pass_msg(size_t nmemb, size_t got, int pass)
{
	logp("Tried to read %lu bytes, got %lu by pass %d\n",
		(unsigned long)nmemb, (unsigned long)got, pass);
}

int fzp_read_ensure(struct fzp *fzp, void *ptr, size_t nmemb, const char *func)
{
	static int f;
	static int r;
	static size_t got;
	static int pass;
	for(r=0, got=0, pass=0; got!=nmemb; pass++)
	{
		r=fzp_read(fzp, ((char *)ptr)+got, nmemb-got);
		if(r>0)
		{
			got+=r;
			continue;
		}
		if(r<0)
		{
			pass_msg(nmemb, got, pass);
			logp("Error in %s, called from %s: %s\n",
				__func__, func, strerror(errno));
			return -1;
		}
		f=fzp_eof(fzp);
		if(!f) continue; // Not yet end of file, keep trying.
		if(f>0)
		{
			// End of file.
			if(!got) return 1;
			pass_msg(nmemb, got, pass);
			logp("Error in %s, called from %s: %lu bytes, eof\n",
				__func__, func, (unsigned long)got);
			return -1;
		}
		else
		{
			pass_msg(nmemb, got, pass);
			logp("Error in %s by fzp_feof, called from %s: %s\n",
				__func__, func, strerror(errno));
			return -1;
		}
	}
	return 0;
}
