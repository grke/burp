#include "burp.h"
#include "alloc.h"
#include "fsops.h"
#include "fzp.h"
#include "log.h"

static struct fzp *fzp_alloc(void)
{
	return (struct fzp *)calloc_w(1, sizeof(struct fzp), __func__);
}

static void fzp_free(struct fzp **fzp)
{
	if(!fzp || !*fzp) return;
	free_v((void **)fzp);
}

static void unknown_type(struct fzp *fzp, const char *func)
{
	logp("unknown type in %s: %d\n", func, fzp->type);
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
			if(!(fzp->fp=open_file(path, mode)))
				goto error;
			return fzp;
		case FZP_COMPRESSED:
			if(!(fzp->zp=gzopen_file(path, mode)))
				goto error;
			return fzp;
		default:
			unknown_type(fzp, __func__);
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
			ret=gzclose_fp(&((*fzp)->zp));
			break;
		default:
			unknown_type(*fzp, __func__);
			break;
	}
	fzp_free(fzp);
	return ret;
}

size_t fzp_read(struct fzp *fzp, void *ptr, size_t nmemb)
{
	switch(fzp->type)
	{
		case FZP_FILE:
			return fread(ptr, 1, nmemb, fzp->fp);
		case FZP_COMPRESSED:
			return gzread(fzp->zp, ptr, (unsigned)nmemb);
		default:
			unknown_type(fzp, __func__);
			return 0;
	}
}

size_t fzp_write(struct fzp *fzp, void *ptr, size_t nmemb)
{
	switch(fzp->type)
	{
		case FZP_FILE:
			return fwrite(ptr, 1, nmemb, fzp->fp);
		case FZP_COMPRESSED:
			return gzwrite(fzp->zp, ptr, (unsigned)nmemb);
		default:
			unknown_type(fzp, __func__);
			return 0;
	}
}

int fzp_eof(struct fzp *fzp)
{
	switch(fzp->type)
	{
		case FZP_FILE:
			return feof(fzp->fp);
		case FZP_COMPRESSED:
			return gzeof(fzp->zp);
		default:
			unknown_type(fzp, __func__);
			return -1;
	}
}
