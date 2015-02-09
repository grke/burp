/*
   Bacula® - The Network Backup Solution

   Copyright (C) 2000-2010 Free Software Foundation Europe e.V.

   The main author of Bacula is Kern Sibbald, with contributions from
   many others, a complete list can be found in the file AUTHORS.
   This program is Free Software; you can redistribute it and/or
   modify it under the terms of version three of the GNU Affero General Public
   License as published by the Free Software Foundation and included
   in the file LICENSE.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
   General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301, USA.

   Bacula® is a registered trademark of Kern Sibbald.
   The licensor of Bacula is the Free Software Foundation Europe
   (FSFE), Fiduciary Program, Sumatrastrasse 25, 8006 Zürich,
   Switzerland, email:ftf@fsfeurope.org.
*/
/*
   This file was derived from GNU TAR source code. Except for a few key
   ideas, it has been entirely rewritten for Bacula.

      Kern Sibbald, MM

   Thanks to the TAR programmers.
*/
/*
   This file was derived from the findlib code from bacula-5.0.3, and
   heavily modified. Therefore, I have retained the bacula copyright notice.
   The specific bacula files were:
   src/findlib/find.c
   src/findlib/find_one.c.
   The comment by Kern above, about TAR, was from find_one.c.
   
      Graham Keeling, 2014.
*/

#include "include.h"
#include "linkhash.h"
#include "pathcmp.h"

#ifdef HAVE_LINUX_OS
#include <sys/statfs.h>
#endif

// Initialize the find files "global" variables
FF_PKT *find_files_init(void)
{
	FF_PKT *ff;

	if(!(ff=(FF_PKT *)calloc_w(1, sizeof(FF_PKT), __func__))
	  || linkhash_init())
		return NULL;

	// Get system path and filename maximum lengths.
	// FIX THIS: maybe this should be done every time a file system is
	// crossed?
	init_fs_max(NULL);

	return ff;
}

void find_files_free(FF_PKT *ff)
{
	linkhash_free();
	free_v((void **)&ff);
}

static int myalphasort(const struct dirent **a, const struct dirent **b)
{
	return pathcmp((*a)->d_name, (*b)->d_name);
}

// Return 1 to include the file, 0 to exclude it.
static int in_include_ext(struct strlist *incext, const char *fname)
{
	int i=0;
	struct strlist *l;
	const char *cp=NULL;
	// If not doing include_ext, let the file get backed up. 
	if(!incext) return 1;

	// The flag of the first item contains the maximum number of characters
	// that need to be checked.
	// FIX THIS: The next two functions do things very similar to this.
	for(cp=fname+strlen(fname)-1; i<incext->flag && cp>=fname; cp--, i++)
	{
		if(*cp!='.') continue;
		for(l=incext; l; l=l->next)
			if(!strcasecmp(l->path, cp+1))
				return 1;
		// If file has no extension, it cannot be included.
		return 0;
	}
	return 0;
}

static int in_exclude_ext(struct strlist *excext, const char *fname)
{
	int i=0;
	struct strlist *l;
	const char *cp=NULL;
	// If not doing exclude_ext, let the file get backed up.
	if(!excext) return 0;

	// The flag of the first item contains the maximum number of characters
	// that need to be checked.
	for(cp=fname+strlen(fname)-1; i<excext->flag && cp>=fname; cp--, i++)
	{
		if(*cp!='.') continue;
		for(l=excext; l; l=l->next)
			if(!strcasecmp(l->path, cp+1))
				return 1;
		// If file has no extension, it is included.
		return 0;
	}
	return 0;
}

// Returns the level of compression.
int in_exclude_comp(struct strlist *excom, const char *fname, int compression)
{
	int i=0;
	struct strlist *l;
	const char *cp=NULL;
	// If not doing compression, or there are no excludes, return
	// straight away.
	if(!compression || !excom) return compression;

	// The flag of the first item contains the maximum number of characters
	// that need to be checked.
	for(cp=fname+strlen(fname)-1; i<excom->flag && cp>=fname; cp--, i++)
	{
		if(*cp!='.') continue;
		for(l=excom; l; l=l->next)
			if(!strcasecmp(l->path, cp+1))
				return 0;
		return compression;
	}
	return compression;
}

/* Return 1 to include the file, 0 to exclude it. */
/* Currently not used - it needs more thinking about. */
int in_include_regex(struct strlist *increg, const char *fname)
{
	// If not doing include_regex, let the file get backed up.
	if(!increg) return 1;
	for(; increg; increg=increg->next)
		if(check_regex(increg->re, fname))
			return 1;
	return 0;
}

int in_exclude_regex(struct strlist *excreg, const char *fname)
{
	// If not doing exclude_regex, let the file get backed up.
	for(; excreg; excreg=excreg->next)
		if(check_regex(excreg->re, fname))
			return 1;
	return 0;
}

// When recursing into directories, do not want to check the include_ext list.
static int file_is_included_no_incext(struct conf *conf, const char *fname)
{
	int ret=0;
	int longest=0;
	int matching=0;
	struct strlist *l=NULL;
	struct strlist *best=NULL;

	if(in_exclude_ext(conf->excext, fname)
	  || in_exclude_regex(conf->excreg, fname))
		return 0;

	// Check include/exclude directories.
	for(l=conf->incexcdir; l; l=l->next)
	{
		//logp("try: %d %s\n", i, l->path);
		matching=is_subdir(l->path, fname);
		if(matching>longest)
		{
			longest=matching;
			best=l;
		}
	}
	//logp("best: %d\n", best);
	if(!best) ret=0;
	else ret=best->flag;

	//logp("return: %d\n", ret);
	return ret;
}

static int file_is_included(struct conf *conf,
	const char *fname, bool top_level)
{
	// Always save the top level directory.
	// This will help in the simulation of browsing backups because it
	// will mean that there is always a directory before any files:
	// d /home/graham
	// f /home/graham/somefile.txt
	// This means that we can use the stats of the directory (/home/graham
	// in this example) as the stats of the parent directories (/home,
	// for example). Trust me on this.
	if(!top_level
	  && !in_include_ext(conf->incext, fname)) return 0;

	return file_is_included_no_incext(conf, fname);
}

static int fs_change_is_allowed(struct conf *conf, const char *fname)
{
	struct strlist *l;
	if(conf->cross_all_filesystems) return 1;
	for(l=conf->fschgdir; l; l=l->next)
		if(!strcmp(l->path, fname)) return 1;
	return 0;
}

static int need_to_read_fifo(struct conf *conf, const char *fname)
{
	struct strlist *l;
	if(conf->read_all_fifos) return 1;
	for(l=conf->fifos; l; l=l->next)
		if(!strcmp(l->path, fname)) return 1;
	return 0;
}

static int need_to_read_blockdev(struct conf *conf, const char *fname)
{
	struct strlist *l;
	if(conf->read_all_blockdevs) return 1;
	for(l=conf->blockdevs; l; l=l->next)
		if(!strcmp(l->path, fname)) return 1;
	return 0;
}

static int nobackup_directory(struct strlist *nobackup, const char *path)
{
	struct stat statp;
	for(; nobackup; nobackup=nobackup->next)
	{
		char *fullpath=NULL;
		if(!(fullpath=prepend_s(path, nobackup->path)))
			return -1;
		if(!lstat(fullpath, &statp))
		{
			free_w(&fullpath);
			return 1;
		}
		free_w(&fullpath);
	}
	return 0;
}

static int file_size_match(FF_PKT *ff_pkt, struct conf *conf)
{
	boffset_t sizeleft;
	sizeleft=ff_pkt->statp.st_size;

	if(conf->min_file_size && sizeleft<(boffset_t)conf->min_file_size)
		return 0;
	if(conf->max_file_size && sizeleft>(boffset_t)conf->max_file_size)
		return 0;
	return 1;
}

// Last checks before actually processing the file system entry.
int send_file_w(struct asfd *asfd, FF_PKT *ff, bool top_level, struct conf *conf)
{
	if(!file_is_included(conf, ff->fname, top_level)) return 0;

	// Doing the file size match here also catches hard links.
	if(S_ISREG(ff->statp.st_mode))
	{
		if(!file_is_included(conf, ff->fname, top_level)) return 0;
		if(!file_size_match(ff, conf)) return 0;
	}

	/*
	 * Handle hard linked files
	 * Maintain a list of hard linked files already backed up. This
	 *  allows us to ensure that the data of each file gets backed
	 *  up only once.
	 */
	if(ff->statp.st_nlink > 1
	  && (S_ISREG(ff->statp.st_mode)
		|| S_ISCHR(ff->statp.st_mode)
		|| S_ISBLK(ff->statp.st_mode)
		|| S_ISFIFO(ff->statp.st_mode)
		|| S_ISSOCK(ff->statp.st_mode)))
	{
		struct f_link *lp;
		struct f_link **bucket=NULL;

		if((lp=linkhash_search(ff, &bucket)))
		{
			if(!strcmp(lp->name, ff->fname)) return 0;
			ff->link=lp->name;
			/* Handle link, file already saved */
			ff->type=FT_LNK_H;
		}
		else
		{
			if(linkhash_add(ff, bucket)) return -1;
		}
	}

	return send_file(asfd, ff, top_level, conf);
}

static int found_regular_file(struct asfd *asfd,
	FF_PKT *ff_pkt, struct conf *conf,
	char *fname, bool top_level)
{
	ff_pkt->type=FT_REG;
	return send_file_w(asfd, ff_pkt, top_level, conf);
}

static int found_soft_link(struct asfd *asfd, FF_PKT *ff_pkt, struct conf *conf,
	char *fname, bool top_level)
{
	ssize_t size;
	char *buffer=(char *)alloca(fs_full_path_max+102);

	if((size=readlink(fname, buffer, fs_full_path_max+101))<0)
	{
		/* Could not follow link */
		ff_pkt->type=FT_NOFOLLOW;
		return send_file_w(asfd, ff_pkt, top_level, conf);
	}
	buffer[size]=0;
	ff_pkt->link=buffer;	/* point to link */
	ff_pkt->type=FT_LNK_S;	/* got a soft link */
	return send_file_w(asfd, ff_pkt, top_level, conf);
}

static int fstype_excluded(struct asfd *asfd,
	struct conf *conf, const char *fname)
{
#if defined(HAVE_LINUX_OS)
	struct statfs buf;
	struct strlist *l;
	if(statfs(fname, &buf))
	{
		logw(asfd, conf, "Could not statfs %s: %s\n",
			fname, strerror(errno));
		return -1;
	}
	for(l=conf->excfs; l; l=l->next)
	{
		if(l->flag==buf.f_type)
		{
			//printf("excluding: %s (%s)\n", fname, l->path);
			return -1;
		}
	}
#endif
	return 0;
}

#if defined(HAVE_WIN32)
static void windows_reparse_point_fiddling(FF_PKT *ff_pkt)
{
	/*
	* We have set st_rdev to 1 if it is a reparse point, otherwise 0,
	*  if st_rdev is 2, it is a mount point 
	*/
	/*
	 * A reparse point (WIN32_REPARSE_POINT)
	 *  is something special like one of the following:
	 *  IO_REPARSE_TAG_DFS              0x8000000A
	 *  IO_REPARSE_TAG_DFSR             0x80000012
	 *  IO_REPARSE_TAG_HSM              0xC0000004
	 *  IO_REPARSE_TAG_HSM2             0x80000006
	 *  IO_REPARSE_TAG_SIS              0x80000007
	 *  IO_REPARSE_TAG_SYMLINK          0xA000000C
	 *
	 * A junction point is a:
	 *  IO_REPARSE_TAG_MOUNT_POINT      0xA0000003
	 * which can be either a link to a Volume (WIN32_MOUNT_POINT)
	 * or a link to a directory (WIN32_JUNCTION_POINT)
	 *
	 * Ignore WIN32_REPARSE_POINT and WIN32_JUNCTION_POINT
	 */
	if (ff_pkt->statp.st_rdev == WIN32_REPARSE_POINT) {
		ff_pkt->type = FT_REPARSE;
	} else if (ff_pkt->statp.st_rdev == WIN32_JUNCTION_POINT) {
		ff_pkt->type = FT_JUNCTION;
	}
}
#endif

static int get_files_in_directory(DIR *directory, struct dirent ***nl, int *count)
{
	int status;
	int allocated=0;
	struct dirent **ntmp=NULL;
	struct dirent *entry=NULL;
	struct dirent *result=NULL;

	/* Graham says: this here is doing a funky kind of scandir/alphasort
	   that can also run on Windows.
	*/
	while(1)
	{
		char *p;
		if(!(entry=(struct dirent *)malloc_w(
			sizeof(struct dirent)+fs_name_max+100, __func__)))
				return -1;
		status=readdir_r(directory, entry, &result);
		if(status || !result)
		{
			free_v((void **)&entry);
			break;
		}

		p=entry->d_name;
		ASSERT(fs_name_max+1 > (int)sizeof(struct dirent)+strlen(p));

		/* Skip `.', `..', and excluded file names.  */
		if(!p || !strcmp(p, ".") || !strcmp(p, ".."))
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
			{
				free_v((void **)&entry);
				return -1;
			}
			*nl=ntmp;
		}
		(*nl)[(*count)++]=entry;
	}
	if(*nl) qsort(*nl, *count, sizeof(**nl),
		(int (*)(const void *, const void *))myalphasort);
	return 0;
}

// Prototype because process_files_in_directory() recurses using find_files().
static int find_files(struct asfd *asfd, FF_PKT *ff_pkt, struct conf *conf,
	char *fname, dev_t parent_device, bool top_level);

static int process_files_in_directory(struct asfd *asfd, struct dirent **nl,
	int count, int *rtn_stat, char **link, size_t len, size_t *link_len,
	struct conf *conf, FF_PKT *ff_pkt, dev_t our_device)
{
	int m=0;
	for(m=0; m<count; m++)
	{
		size_t i;
		char *p=NULL;
		char *q=NULL;

		p=nl[m]->d_name;

		if(strlen(p)+len>=*link_len)
		{
			*link_len=len+strlen(p)+1;
			if(!(*link=(char *)
			  realloc_w(*link, (*link_len)+1, __func__)))
				return -1;
		}
		q=(*link)+len;
		for(i=0; i<strlen(nl[m]->d_name); i++)
			*q++=*p++;
		*q=0;
		ff_pkt->flen=i;

		if(file_is_included_no_incext(conf, *link))
		{
			*rtn_stat=find_files(asfd, ff_pkt,
				conf, *link, our_device, false);
		}
		else
		{
			struct strlist *x;
			// Excluded, but there might be a subdirectory that is
			// included.
			for(x=conf->incexcdir; x; x=x->next)
			{
				if(x->flag
				  && is_subdir(*link, x->path))
				{
					struct strlist *y;
					if((*rtn_stat=find_files(asfd, ff_pkt,
						conf, x->path,
						our_device, false)))
							break;
					// Now need to skip subdirectories of
					// the thing that we just stuck in
					// find_one_file(), or we might get
					// some things backed up twice.
					for(y=x->next; y; y=y->next)
						if(is_subdir(x->path, y->path))
							y=y->next;
				}
			}
		}
		free_v((void **)&(nl[m]));
		if(*rtn_stat) break;
	}
	return 0;
}

static int found_directory(struct asfd *asfd, FF_PKT *ff_pkt, struct conf *conf,
	char *fname, dev_t parent_device, bool top_level)
{
	int rtn_stat;
	DIR *directory;
	char *link=NULL;
	size_t link_len;
	size_t len;
	int nbret=0;
	int count=0;
	bool recurse;
	dev_t our_device;
	struct dirent **nl=NULL;

	recurse=true;
	our_device=ff_pkt->statp.st_dev;

	/*
	* Ignore this directory and everything below if one of the files defined
	* by the 'nobackup' option exists.
	*/
	if((nbret=nobackup_directory(conf->nobackup, ff_pkt->fname)))
	{
		if(nbret<0) return -1; // error
		return 0; // do not back it up.
	}

	/* Build a canonical directory name with a trailing slash in link var */
	len=strlen(fname);
	link_len=len+200;
	if(!(link=(char *)malloc_w(link_len+2, __func__)))
		return -1;
	snprintf(link, link_len, "%s", fname);

	/* Strip all trailing slashes */
	while(len >= 1 && IsPathSeparator(link[len - 1])) len--;
	/* add back one */
	link[len++]='/';
	link[len]=0;

	ff_pkt->link=link;
	ff_pkt->type=FT_DIR;

#if defined(HAVE_WIN32)
	windows_reparse_point_fiddling(ff_pkt);
#endif

	rtn_stat=send_file_w(asfd, ff_pkt, top_level, conf);
	if(rtn_stat || ff_pkt->type==FT_REPARSE || ff_pkt->type==FT_JUNCTION)
	{
		/* ignore or error status */
		free_w(&link);
		return rtn_stat;
	}

	/*
	* Do not descend into subdirectories (recurse) if the
	* user has turned it off for this directory.
	*
	* If we are crossing file systems, we are either not allowed
	* to cross, or we may be restricted by a list of permitted
	* file systems.
	*/
	if(!top_level
	  && (parent_device!=ff_pkt->statp.st_dev
#if defined(HAVE_WIN32)
		|| ff_pkt->statp.st_rdev==WIN32_MOUNT_POINT
#endif
		))
	{
		if(fstype_excluded(asfd, conf, ff_pkt->fname))
		{
			free_w(&link);
			return send_file_w(asfd, ff_pkt, top_level, conf);
		}
		if(!fs_change_is_allowed(conf, ff_pkt->fname))
		{
			ff_pkt->type=FT_NOFSCHG;
			recurse=false;
		}
	}
	/* If not recursing, just backup dir and return */
	if(!recurse)
	{
		free_w(&link);
		return send_file_w(asfd, ff_pkt, top_level, conf);
	}

	/* reset "link" */
	ff_pkt->link=ff_pkt->fname;

	/*
	* Descend into or "recurse" into the directory to read
	*   all the files in it.
	*/
	errno = 0;
#if defined(O_DIRECTORY) && defined(O_NOATIME)
	int dfd=-1;
	if((dfd=open(fname, O_RDONLY|O_DIRECTORY|conf->atime?0:O_NOATIME))<0
	  || !(directory=fdopendir(dfd)))
#else
// Mac OS X appears to have no O_NOATIME and no fdopendir(), so it should
// end up using opendir() here.
	if(!(directory=opendir(fname)))
#endif
	{
#if defined(O_DIRECTORY) && defined(O_NOATIME)
		if(dfd>=0) close(dfd);
#endif
		ff_pkt->type=FT_NOOPEN;
		rtn_stat=send_file_w(asfd, ff_pkt, top_level, conf);
		free_w(&link);
		return rtn_stat;
	}

	/*
	* Process all files in this directory entry (recursing).
	*    This would possibly run faster if we chdir to the directory
	*    before traversing it.
	*/
	if(get_files_in_directory(directory, &nl, &count))
	{
		closedir(directory);
		free_w(&link);
		return -1;
	}
	closedir(directory);

	rtn_stat=0;
	if(nl)
	{
		if(process_files_in_directory(asfd, nl, count,
			&rtn_stat, &link, len, &link_len, conf,
			ff_pkt, our_device))
		{
			free_w(&link);
			free(nl);
			return -1;
		}
	}
	free_w(&link);
	if(nl) free(nl);

	return rtn_stat;
}

static int found_other(struct asfd *asfd, FF_PKT *ff_pkt, struct conf *conf,
	char *fname, bool top_level)
{
#ifdef HAVE_FREEBSD_OS
	/*
	 * On FreeBSD, all block devices are character devices, so
	 *   to be able to read a raw disk, we need the check for
	 *   a character device.
	 * crw-r----- 1 root  operator - 116, 0x00040002 Jun 9 19:32 /dev/ad0s3
	 * crw-r----- 1 root  operator - 116, 0x00040002 Jun 9 19:32 /dev/rad0s3
	 */
	if((S_ISBLK(ff_pkt->statp.st_mode) || S_ISCHR(ff_pkt->statp.st_mode))
		&& need_to_read_blockdev(conf, ff_pkt->fname))
	{
#else
	if(S_ISBLK(ff_pkt->statp.st_mode)
		&& need_to_read_blockdev(conf, ff_pkt->fname))
	{
#endif
		ff_pkt->type = FT_RAW;          /* raw partition */
	}
	else if(S_ISFIFO(ff_pkt->statp.st_mode)
		&& need_to_read_fifo(conf, ff_pkt->fname))
	{
		ff_pkt->type=FT_FIFO;
	}
	else
	{
		/* The only remaining are special (character, ...) files */
		ff_pkt->type=FT_SPEC;
	}
	return send_file_w(asfd, ff_pkt, top_level, conf);
}

/*
 * Find a single file.
 * p is the filename
 * parent_device is the device we are currently on
 * top_level is 1 when not recursing or 0 when
 *  descending into a directory.
 */
static int find_files(struct asfd *asfd, FF_PKT *ff_pkt, struct conf *conf,
	char *fname, dev_t parent_device, bool top_level)
{
	ff_pkt->fname=fname;
	ff_pkt->link=fname;

#ifdef HAVE_WIN32
	if(win32_lstat(fname, &ff_pkt->statp, &ff_pkt->winattr))
#else
	if(lstat(fname, &ff_pkt->statp))
#endif
	{
		ff_pkt->type=FT_NOSTAT;
		return send_file_w(asfd, ff_pkt, top_level, conf);
	}

	if(S_ISREG(ff_pkt->statp.st_mode))
		return found_regular_file(asfd, ff_pkt, conf, fname, top_level);
	else if(S_ISLNK(ff_pkt->statp.st_mode))
	{
#ifdef S_IFLNK
		/* A symlink.
		   If they have specified the symlink in a read_blockdev
		   argument, treat it as a block device.
		*/
		struct strlist *l;
		for(l=conf->blockdevs; l; l=l->next)
		{
			if(!strcmp(l->path, fname))
			{
				ff_pkt->statp.st_mode ^= S_IFLNK;
				ff_pkt->statp.st_mode |= S_IFBLK;
				return found_other(asfd, ff_pkt, conf, fname,
					top_level);
			}
		}
#endif
		return found_soft_link(asfd, ff_pkt, conf, fname, top_level);
	}
	else if(S_ISDIR(ff_pkt->statp.st_mode))
		return found_directory(asfd, ff_pkt, conf, fname,
			parent_device, top_level);
	else
		return found_other(asfd, ff_pkt, conf, fname, top_level);
}

int find_files_begin(struct asfd *asfd,
	FF_PKT *ff_pkt, struct conf *conf, char *fname)
{
	return find_files(asfd, ff_pkt,
		conf, fname, (dev_t)-1, 1 /* top_level */);
}
