#include "../burp.h"
#include "../alloc.h"
#include "../cntr.h"
#include "../conf.h"
#include "../cstat.h"
#include "../fsops.h"
#include "../fzp.h"
#include "../log.h"
#include "../prepend.h"
#include "child.h"
#include "link.h"

int recursive_hardlink(const char *src, const char *dst, struct conf **confs)
{
	int ret=-1;
	DIR *dirp=NULL;
	char *tmp=NULL;
	char *fullpatha=NULL;
	char *fullpathb=NULL;
	struct dirent *entry=NULL;

	if(!(tmp=prepend_s(dst, "dummy")))
		goto end;
	if(mkpath(&tmp, dst))
	{
		logp("could not mkpath for %s\n", tmp);
		goto end;
	}

	if(!(dirp=opendir(src)))
	{
		logp("opendir %s in %s: %s\n",
			src, __func__, strerror(errno));
		goto end;
	}

	while(1)
	{
		struct stat statp;

		errno=0;
		if(!(entry=readdir(dirp)))
		{
			if(errno)
			{
				logp("error in readdir in %s: %s\n",
					__func__, strerror(errno));
				goto end;
			}
			break;
		}

		if(!filter_dot(entry))
			continue;

		free_w(&fullpatha);
		free_w(&fullpathb);
		if(!(fullpatha=prepend_s(src, entry->d_name))
		  || !(fullpathb=prepend_s(dst, entry->d_name)))
			goto end;

#ifdef _DIRENT_HAVE_D_TYPE
// Faster evaluation on most systems.
		if(entry->d_type==DT_DIR)
		{
			if(recursive_hardlink(fullpatha, fullpathb, confs))
				goto end;
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
				goto end;
		}
		else
		{
			//logp("hardlinking %s to %s\n", fullpathb, fullpatha);
			if(timed_operation_status_only(CNTR_STATUS_SHUFFLING,
				fullpathb, confs)
			  || do_link(fullpatha, fullpathb, &statp, confs,
				0 /* do not overwrite target */))
					goto end;
		}
	}

	ret=0;
end:
	if(dirp) closedir(dirp);
	free_w(&fullpatha);
	free_w(&fullpathb);
	free_w(&tmp);

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
			logp("could not write all bytes: %lu!=%lu\n",
				(unsigned long)s, (unsigned long)t);
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
