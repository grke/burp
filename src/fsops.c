#include "burp.h"
#include "alloc.h"
#include "fsops.h"
#include "log.h"
#include "pathcmp.h"
#include "prepend.h"

uint32_t fs_name_max=0;
uint32_t fs_full_path_max=0;
static uint32_t fs_path_max=0;

void close_fd(int *fd)
{
	if(!fd || *fd<0) return;
	//logp("closing %d\n", *fd);
	close(*fd);
	*fd=-1;
}

int is_dir_lstat(const char *path)
{
        struct stat buf;

        if(lstat(path, &buf)) return -1;

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
		free_w(rpath);
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
	int ret;
	char *rpath=NULL;
	ret=build_path(path, "", &rpath, NULL);
	free_w(&rpath);
	return ret;
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

static int do_recursive_delete(const char *d, const char *file,
	uint8_t delfiles, int32_t name_max)
{
	int ret=RECDEL_ERROR;
	DIR *dirp=NULL;
	struct dirent *entry=NULL;
	struct dirent *result;
	struct stat statp;
	char *directory=NULL;
	char *fullpath=NULL;

	if(!file)
	{
		if(!(directory=prepend_s(d, ""))) goto end;
	}
	else if(!(directory=prepend_s(d, file)))
	{
		log_out_of_memory(__func__);
		goto end;
	}

	if(lstat(directory, &statp))
	{
		// path does not exist.
		ret=RECDEL_OK;
		goto end;
	}

	if(!(dirp=opendir(directory)))
	{
		logp("opendir %s: %s\n", directory, strerror(errno));
		goto end;
	}

	if(!(entry=(struct dirent *)
		malloc_w(sizeof(struct dirent)+name_max+100, __func__)))
			goto end;

	while(1)
	{
		if(readdir_r(dirp, entry, &result) || !result)
		{
			// Got to the end of the directory.
			ret=RECDEL_OK;
			break;
		}

		if(!entry->d_ino
		  || !strcmp(entry->d_name, ".")
		  || !strcmp(entry->d_name, ".."))
			continue;
		free_w(&fullpath);
		if(!(fullpath=prepend_s(directory, entry->d_name)))
			goto end;

		if(is_dir(fullpath, entry)>0)
		{
			int r;
			if((r=do_recursive_delete(directory, entry->d_name,
				delfiles, name_max))==RECDEL_ERROR)
					goto end;
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
	}

	if(ret==RECDEL_OK && rmdir(directory))
	{
		logp("rmdir %s: %s\n", directory, strerror(errno));
		ret=RECDEL_ERROR;
	}
end:
	if(dirp) closedir(dirp);
	free_w(&fullpath);
	free_w(&directory);
	free_v((void **)&entry);
	return ret;
}

static int do_recursive_delete_w(const char *path, uint8_t delfiles)
{
	int32_t name_max;
	get_max(&name_max, _PC_NAME_MAX);
	return do_recursive_delete(path, NULL, delfiles, name_max);
}

int recursive_delete(const char *path)
{
	struct stat statp;
	// We might have been given a file entry, instead of a directory.
	if(!lstat(path, &statp) && !S_ISDIR(statp.st_mode))
	{
		if(unlink(path))
		{
			logp("unlink %s: %s\n", path, strerror(errno));
			return RECDEL_ENTRIES_REMAINING;
		}
	}
	return do_recursive_delete_w(path, 1);
}

int recursive_delete_dirs_only(const char *path)
{
	return do_recursive_delete_w(path, 0);
}

int unlink_w(const char *path, const char *func)
{
	if(unlink(path))
	{
		logp("unlink(%s) called from %s(): %s\n",
			path, func, strerror(errno));
		return -1;
	}
	return 0;
}

static void init_max(const char *path,
	uint32_t *max, int what, uint32_t default_max)
{
	*max=pathconf(path?path:".", what);
	if(*max<default_max) *max=default_max;
}

int init_fs_max(const char *path)
{
	struct stat statp;
	if(stat(path, &statp))
	{
		logp("Path %s does not exist in %s\n", path, __func__);
		return -1;
	}
	// Get system path and filename maximum lengths.
	init_max(path, &fs_path_max, _PC_PATH_MAX, 1024);
	init_max(path, &fs_name_max, _PC_NAME_MAX, 255);
	fs_full_path_max=fs_path_max+fs_name_max;
	return 0;
}

int looks_like_tmp_or_hidden_file(const char *filename)
{
	if(!filename) return 0;
	if(filename[0]=='.' // Also avoids '.' and '..'.
	  // I am told that emacs tmp files end with '~'.
	  || filename[strlen(filename)-1]=='~')
		return 1;
	return 0;
}

int do_get_entries_in_directory(DIR *directory, struct dirent ***nl,
	int *count, int (*compar)(const void *, const void *))
{
	int status;
	int allocated=0;
	struct dirent **ntmp=NULL;
	struct dirent *entry=NULL;
	struct dirent *result=NULL;

	*count=0;

	// This here is doing a funky kind of scandir/alphasort
	// that can also run on Windows.
	while(1)
	{
		char *p;
		if(!(entry=(struct dirent *)malloc_w(
		  sizeof(struct dirent)+fs_name_max+100, __func__)))
			goto error;
		status=readdir_r(directory, entry, &result);
		if(status || !result)
		{
			free_v((void **)&entry);
			break;
		}

		p=entry->d_name;
		ASSERT(fs_name_max+1 > (int)sizeof(struct dirent)+strlen(p));

		if(!p
		  || !strcmp(p, ".")
		  || !strcmp(p, ".."))
		{
			free_v((void **)&entry);
			continue;
		}

		if(*count==allocated)
		{
			if(!allocated) allocated=10;
			else allocated*=2;

			if(!(ntmp=(struct dirent **)
			  realloc_w(*nl, allocated*sizeof(**nl), __func__)))
				goto error;
			*nl=ntmp;
		}
		(*nl)[(*count)++]=entry;
	}
	if(*nl && compar) qsort(*nl, *count, sizeof(**nl), compar);
	return 0;
error:
	free_v((void **)&entry);
	if(*nl)
	{
		int i;
		for(i=0; i<*count; i++)
			free_v((void **)&((*nl)[i]));
		free_v((void **)nl);
	}
	return -1;
}

static int entries_in_directory(const char *path, struct dirent ***nl,
	int *count, int atime,
	int (*compar)(const struct dirent **, const struct dirent **))
{
	int ret=0;
	DIR *directory=NULL;

	if(!fs_name_max)
	{
        	// Get system path and filename maximum lengths.
        	// FIX THIS: maybe this should be done every time a file system
        	// is crossed?
		if(init_fs_max(path)) return -1;
	}
#if defined(O_DIRECTORY) && defined(O_NOATIME)
	int dfd=-1;
	if((dfd=open(path, O_RDONLY|O_DIRECTORY|atime?0:O_NOATIME))<0
	  || !(directory=fdopendir(dfd)))
#else
// Mac OS X appears to have no O_NOATIME and no fdopendir(), so it should
// end up using opendir() here.
	if(!(directory=opendir(path)))
#endif
	{
#if defined(O_DIRECTORY) && defined(O_NOATIME)
		close_fd(&dfd);
#endif
		ret=1;
        }
	else
	{
		if(do_get_entries_in_directory(directory, nl, count,
			(int (*)(const void *, const void *))compar))
				ret=-1;
	}
	if(directory) closedir(directory);
	return ret;
}

static int my_alphasort(const struct dirent **a, const struct dirent **b)
{
	return strcmp((*a)->d_name, (*b)->d_name);
}

static int rev_alphasort(const struct dirent **a, const struct dirent **b)
{
	return strcmp((*a)->d_name, (*b)->d_name)*-1;
}

int entries_in_directory_alphasort(const char *path, struct dirent ***nl,
	int *count, int atime)
{
	return entries_in_directory(path, nl, count, atime, my_alphasort);
}

int entries_in_directory_alphasort_rev(const char *path, struct dirent ***nl,
	int *count, int atime)
{
	return entries_in_directory(path, nl, count, atime, rev_alphasort);
}

int entries_in_directory_no_sort(const char *path, struct dirent ***nl,
	int *count, int atime)
{
	return entries_in_directory(path, nl, count, atime, NULL);
}
