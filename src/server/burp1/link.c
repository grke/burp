#include "include.h"
#include "../monitor/status_client.h"

#include <dirent.h>

int recursive_hardlink(const char *src, const char *dst, struct conf *conf)
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
			if(recursive_hardlink(fullpatha, fullpathb, conf))
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
			if(recursive_hardlink(fullpatha, fullpathb, conf))
				break;
		}
		else
		{
			//logp("hardlinking %s to %s\n", fullpathb, fullpatha);
			if(write_status(STATUS_SHUFFLING, fullpathb, conf)
			  || do_link(fullpatha, fullpathb, &statp, conf,
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
	FILE *op=NULL;
	FILE *np=NULL;
	char buf[DUP_CHUNK]="";
	if(!(op=open_file(oldpath, "rb"))
	  || !(np=open_file(newpath, "wb")))
		goto end;

	while((s=fread(buf, 1, DUP_CHUNK, op))>0)
	{
		t=fwrite(buf, 1, s, np);
		if(t!=s)
		{
			logp("could not write all bytes: %d!=%d\n", s, t);
			goto end;
		}
	}

	ret=0;
end:
	close_fp(&np);
	close_fp(&op);
	if(ret) logp("could not duplicate %s to %s\n", oldpath, newpath);
	return ret;
}

int do_link(const char *oldpath, const char *newpath, struct stat *statp, struct conf *conf, uint8_t overwrite)
{
	/* Avoid creating too many hardlinks */
	if(statp->st_nlink >= (unsigned int)conf->max_hardlinks)
	{
		return duplicate_file(oldpath, newpath);
	}
	else if(link(oldpath, newpath))
	{
		if(overwrite && errno==EEXIST)
		{
			unlink(newpath);
			if(link(oldpath, newpath))
			{
				logp("could not hard link '%s' to '%s': %s\n",
					newpath, oldpath, strerror(errno));
				return -1;
			}
			else
			{
				logp("Successful hard link of '%s' to '%s' after unlinking the former\n", newpath, oldpath);
				return 0;
			}
		}
		return -1;
	}
	return 0;
}
