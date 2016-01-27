#include "../../burp.h"
#include "../../alloc.h"
#include "../../cntr.h"
#include "../../conf.h"
#include "../../fsops.h"
#include "../../fzp.h"
#include "../../log.h"
#include "../../prepend.h"
#include "../child.h"
#include "link.h"

int recursive_hardlink(const char *src, const char *dst, struct conf **confs)
{
	int n=-1;
	int ret=0;
	struct dirent **dir;
	char *tmp=NULL;
	char *fullpatha=NULL;
	char *fullpathb=NULL;
	//logp("in rec hl: %s %s\n", src, dst);
	if(!(tmp=prepend_s(dst, "dummy"))) return -1;
	if(mkpath(&tmp, dst))
	{
		logp("could not mkpath for %s\n", tmp);
		free_w(&tmp);
		return -1;
	}
	free_w(&tmp);

	if((n=scandir(src, &dir, 0, 0))<0)
	{
		logp("recursive_hardlink scandir %s: %s\n",
			src, strerror(errno));
		return -1;
	}
	while(n--)
	{
		struct stat statp;
		if(dir[n]->d_ino==0
		  || !strcmp(dir[n]->d_name, ".")
		  || !strcmp(dir[n]->d_name, ".."))
			{ free(dir[n]); continue; }
		free_w(&fullpatha);
		free_w(&fullpathb);
		if(!(fullpatha=prepend_s(src, dir[n]->d_name))
		  || !(fullpathb=prepend_s(dst, dir[n]->d_name)))
			break;

#ifdef _DIRENT_HAVE_D_TYPE
// Faster evaluation on most systems.
		if(dir[n]->d_type==DT_DIR)
		{
			if(recursive_hardlink(fullpatha, fullpathb, confs))
				break;
		}
		else
#endif
		// Otherwise, we have to do an lstat() anyway, because we
		// will need to check the number of hardlinks in do_link().
		if(lstat(fullpatha, &statp))
		{
			logp("could not lstat %s\n", fullpatha);
		}
		else if(S_ISDIR(statp.st_mode))
		{
			if(recursive_hardlink(fullpatha, fullpathb, confs))
				break;
		}
		else
		{
			//logp("hardlinking %s to %s\n", fullpathb, fullpatha);
			if(write_status(CNTR_STATUS_SHUFFLING, fullpathb,
				get_cntr(confs))
			  || do_link(fullpatha, fullpathb, &statp, confs,
				0 /* do not overwrite target */))
				break;
		}
		free(dir[n]);
	}
	if(n>0)
	{
		ret=-1;
		for(; n>0; n--) free(dir[n]);
	}
	free(dir);

	free_w(&fullpatha);
	free_w(&fullpathb);

	return ret;
}

#define DUP_CHUNK	4096
static int duplicate_file(const char *oldpath, const char *newpath)
{
	int ret=-1;
	size_t s=0;
	size_t t=0;
	struct fzp *op=NULL;
	struct fzp *np=NULL;
	char buf[DUP_CHUNK]="";
	if(!(op=fzp_open(oldpath, "rb"))
	  || !(np=fzp_open(newpath, "wb")))
		goto end;

	while((s=fzp_read(op, buf, DUP_CHUNK))>0)
	{
		t=fzp_write(np, buf, s);
		if(t!=s)
		{
			logp("could not write all bytes: %zu!=%zu\n", s, t);
			goto end;
		}
	}

	ret=0;
end:
	fzp_close(&np);
	fzp_close(&op);
	if(ret) logp("could not duplicate %s to %s\n", oldpath, newpath);
	return ret;
}

int do_link(const char *oldpath, const char *newpath, struct stat *statp,
	struct conf **confs, uint8_t overwrite)
{
	/* Avoid creating too many hardlinks */
	if(confs
	  && statp->st_nlink >= (unsigned int)get_int(confs[OPT_MAX_HARDLINKS]))
	{
		return duplicate_file(oldpath, newpath);
	}
	else if(link(oldpath, newpath))
	{
		if(overwrite && errno==EEXIST)
		{
			unlink(newpath);
			if(!link(oldpath, newpath))
			{
				//logp("Successful hard link of '%s' to '%s' after unlinking the former\n", newpath, oldpath);
				return 0;
			}
		}
		logp("could not hard link '%s' to '%s': %s\n",
			newpath, oldpath, strerror(errno));
		return -1;
	}
	return 0;
}
