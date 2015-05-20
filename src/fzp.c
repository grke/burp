#include "burp.h"
#include "alloc.h"
#include "fsops.h"
#include "fzp.h"
#include "log.h"

struct fzp *fzp_alloc(void)
{
	return (struct fzp *)calloc_w(1, sizeof(struct fzp), __func__);
}

int fzp_free(struct fzp **fzp)
{
	int ret=0;
	if(!fzp || !*fzp) return 0;
	if(fzp_close(*fzp)) ret=-1;
	free_v((void **)fzp);
	return ret;
}

static int unknown_type(struct fzp *fzp, const char *func)
{
	logp("unknown type in %s: %d\n", func, fzp->type);
	return -1;
}

static int fzp_do_open(struct fzp *fzp, enum fzp_type type,
	const char *path, const char *mode)
{
	if(fzp->zp || fzp->fp)
	{
		logp("Pointer already open in %s\n", __func__);
		return -1;
	}
	fzp->type=type;
	switch(type)
	{
		case FZP_FILE:
			if(!(fzp->fp=open_file(path, mode)))
				return -1;
			return 0;
		case FZP_COMPRESSED:
			if(!(fzp->zp=gzopen_file(path, mode)))
				return -1;
			return 0;
		default:
			return unknown_type(fzp, __func__);
	}
}

int fzp_open(struct fzp *fzp, const char *path, const char *mode)
{
	return fzp_do_open(fzp, FZP_FILE, path, mode);
}

int fzp_gzopen(struct fzp *fzp, const char *path, const char *mode)
{
	return fzp_do_open(fzp, FZP_COMPRESSED, path, mode);
}

int fzp_close(struct fzp *fzp)
{
	switch(fzp->type)
	{
		case FZP_FILE:
			return close_fp(&fzp->fp);
		case FZP_COMPRESSED:
			return gzclose_fp(&fzp->zp);
		default:
			return unknown_type(fzp, __func__);
	}
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
			return unknown_type(fzp, __func__);
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
			return unknown_type(fzp, __func__);
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
			return unknown_type(fzp, __func__);
	}
}
