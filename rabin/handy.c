#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "handy.h"
#include "prepend.h"

FILE *file_open(const char *path, const char *mode)
{
	FILE *fp=NULL;
	if(!(fp=fopen(path, mode)))
		fprintf(stderr, "Could not open %s in mode %s: %s\n",
			path, mode, strerror(errno));
	return fp;
}

int file_close(FILE **fp)
{
	if(*fp)
	{
		if(fclose(*fp))
		{
			fprintf(stderr, "Could not close file in %s: %s\n",
				__FUNCTION__, strerror(errno));
			*fp=NULL;
			return -1;
		}
		*fp=NULL;
	}
	return 0;
}

int pathcmp(const char *a, const char *b)
{
	const char *x=NULL;
	const char *y=NULL;
	if(!a && !b) return 0; // equal
	if( a && !b) return 1; // a is longer
	if(!a &&  b) return -1; // b is longer
	for(x=a, y=b; *x && *y ; x++, y++)
	{
		if(*x==*y) continue;
		if(*x=='/' && *y!='/') return -1;
		if(*x!='/' && *y=='/') return 1;
		if(*x<*y) return -1;
		if(*x>*y) return 1;
	}
	if(!*x && !*y) return 0; // equal
	if( *x && !*y) return 1; // x is longer
	return -1; // y is longer
}

int mkpath(char **rpath, const char *limit)
{
	char *cp=NULL;
	struct stat buf;
	//printf("mkpath: %s\n", *rpath);
	if((cp=strrchr(*rpath, '/')))
	{
		*cp='\0';

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
				fprintf(stderr, "will not mkdir %s\n", *rpath);
				*cp='/';
				return -1;
			}
			if(mkdir(*rpath, 0777))
			{
				fprintf(stderr, "could not mkdir %s: %s\n", *rpath, strerror(errno));
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
			fprintf(stderr, "warning: wanted '%s' to be a directory\n",
				*rpath);
		}
		*cp='/';
	}
	return 0;
}

static int build_path(const char *datadir, const char *fname, size_t flen, char **rpath, const char *limit)
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

int build_path_w(const char *path)
{
	char *rpath=NULL;
	if(build_path(path, "", strlen(path), &rpath, NULL))
		return -1;
	free(rpath);
	return 0;
}
