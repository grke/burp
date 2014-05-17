#include "include.h"

#include <dirent.h>

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

int is_dir_lstat(const char *path)
{
        struct stat buf;

        if(lstat(path, &buf)) return 0;

        return S_ISDIR(buf.st_mode);
}

int is_dir(const char *path, struct dirent *d)
{
#ifdef _DIRENT_HAVE_D_TYPE
	// Faster evaluation on most systems.
	switch(d->d_type)
	{
		case DT_DIR:
			return 1;
		case DT_UNKNOWN:
			break;
		default:
			return 0;
	}
#endif
	return is_dir_lstat(path);
}

int mkpath(char **rpath, const char *limit)
{
	int ret=-1;
	char *cp=NULL;
	struct stat buf;
#ifdef HAVE_WIN32
	int windows_stupidity=0;
#endif
	if((cp=strrchr(*rpath, '/')))
	{
		*cp='\0';
#ifdef HAVE_WIN32
		if(strlen(*rpath)==2 && (*rpath)[1]==':')
		{
			(*rpath)[1]='\0';
			windows_stupidity++;
		}
#endif
		if(!**rpath)
		{
			// We are down to the root, which is OK.
		}
		else if(lstat(*rpath, &buf))
		{
			// does not exist - recurse further down, then come
			// back and try to mkdir it.
			if(mkpath(rpath, limit)) goto end;

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
				goto end;
			}
			if(mkdir(*rpath, 0777))
			{
				logp("could not mkdir %s: %s\n", *rpath, strerror(errno));
				goto end;
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
	}

	ret=0;
end:
#ifdef HAVE_WIN32
	if(windows_stupidity) (*rpath)[1]=':';
#endif
	if(cp) *cp='/';
	return ret;
}

int build_path(const char *datadir, const char *fname, char **rpath, const char *limit)
{
	//logp("build path: '%s/%s'\n", datadir, fname);
	if(!(*rpath=prepend_s(datadir, fname))) return -1;
	if(mkpath(rpath, limit))
	{
		if(*rpath) { free(*rpath); *rpath=NULL; }
		return -1;
	}
	return 0;
}

int do_rename(const char *oldpath, const char *newpath)
{
	// Be careful, this is not actually atomic. Everything that uses this
	// needs to deal with the consequences.
	if(rename(oldpath, newpath))
	{
		logp("could not rename '%s' to '%s': %s\n",
			oldpath, newpath, strerror(errno)); 
		return -1; 
	}
	return 0;
}

int build_path_w(const char *path)
{
	char *rpath=NULL;
	if(build_path(path, "", &rpath, NULL))
		return -1;
	free(rpath);
	return 0;
}

#define RECDEL_ERROR			-1
#define RECDEL_OK			0
#define RECDEL_ENTRIES_REMAINING	1

static void get_max(int32_t *max, int32_t default_max)
{
	*max = pathconf(".", default_max);
	if(*max < 1024) *max = 1024;
	// Add for EOS.
	(*max)++;
}

static int do_recursive_delete(const char *d, const char *file, uint8_t delfiles, int32_t name_max)
{
	int ret=RECDEL_OK;
	DIR *dirp;
	struct dirent *entry;
	struct dirent *result;
	struct stat statp;
	char *directory=NULL;

	if(!file)
	{
		if(!(directory=prepend_s(d, ""))) return RECDEL_ERROR;
	}
	else if(!(directory=prepend_s(d, file)))
	{
		log_out_of_memory(__func__);
		return RECDEL_ERROR;
	}

	if(lstat(directory, &statp))
	{
		// path does not exist.
		free(directory);
		return RECDEL_OK;
	}

	if(!(dirp=opendir(directory)))
	{
		logp("opendir %s: %s\n", directory, strerror(errno));
		free(directory);
		return RECDEL_ERROR;
	}

	if(!(entry=(struct dirent *)
		malloc(sizeof(struct dirent)+name_max+100)))
	{
		log_out_of_memory(__func__);
		free(directory);
		return RECDEL_ERROR;
	}


	while(1)
	{
		char *fullpath=NULL;

		if(readdir_r(dirp, entry, &result) || !result)
		{
			// Got to the end of the directory.
			break;
		}

		if(entry->d_ino==0
		  || !strcmp(entry->d_name, ".")
		  || !strcmp(entry->d_name, ".."))
			continue;
		if(!(fullpath=prepend_s(directory, entry->d_name)))
		{
			ret=RECDEL_ERROR;
			break;
		}

		if(is_dir(fullpath, entry))
		{
			int r;
			if((r=do_recursive_delete(directory, entry->d_name,
				delfiles, name_max))==RECDEL_ERROR)
			{
				free(fullpath);
				break;
			}
			// do not overwrite ret with OK if it previously
			// had ENTRIES_REMAINING
			if(r==RECDEL_ENTRIES_REMAINING) ret=r;
		}
		else if(delfiles)
		{
			if(unlink(fullpath))
			{
				logp("unlink %s: %s\n",
					fullpath, strerror(errno));
				ret=RECDEL_ENTRIES_REMAINING;
			}
		}
		else
		{
			ret=RECDEL_ENTRIES_REMAINING;
		}
		free(fullpath);
	}

	if(ret==RECDEL_OK && rmdir(directory))
	{
		logp("rmdir %s: %s\n", directory, strerror(errno));
		ret=RECDEL_ERROR;
	}
	closedir(dirp);
	free(directory);
	free(entry);
	return ret;
}

int recursive_delete(const char *d, const char *file, uint8_t delfiles)
{
	int32_t name_max;
	get_max(&name_max, _PC_NAME_MAX);
	return do_recursive_delete(d, file, delfiles, name_max);
}
