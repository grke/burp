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

#include "../burp.h"
#include "../alloc.h"
#include "../conf.h"
#include "../fsops.h"
#include "../linkhash.h"
#include "../log.h"
#include "../pathcmp.h"
#include "../prepend.h"
#include "../regexp.h"
#include "../strlist.h"
#include "cvss.h"
#include "find.h"
#include "find_logic.h"

#ifdef HAVE_LINUX_OS
#include <sys/statfs.h>
#endif
#ifdef HAVE_SUN_OS
#include <sys/statvfs.h>
#endif

static int (*my_send_file)(struct asfd *, struct FF_PKT *, struct conf **);

// Initialize the find files "global" variables
struct FF_PKT *find_files_init(
	int callback(struct asfd *asfd, struct FF_PKT *ff, struct conf **confs))
{
	struct FF_PKT *ff;

	if(!(ff=(struct FF_PKT *)calloc_w(1, sizeof(struct FF_PKT), __func__))
	  || linkhash_init())
		return NULL;
	my_send_file=callback;

	return ff;
}

void find_files_free(struct FF_PKT **ff)
{
	linkhash_free();
	free_v((void **)ff);
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
int in_include_regex(struct strlist *increg, const char *fname)
{
	// If not doing include_regex, let the file get backed up.
	if(!increg) return 1;
	for(; increg; increg=increg->next)
		if(regex_check(increg->re, fname))
			return 1;
	return 0;
}

static int in_exclude_regex(struct strlist *excreg, const char *fname)
{
	// If not doing exclude_regex, let the file get backed up.
	for(; excreg; excreg=excreg->next)
		if(regex_check(excreg->re, fname))
			return 1;
	return 0;
}

// When recursing into directories, do not want to check the include_ext list.
#ifndef UTEST
static
#endif
int file_is_included_no_incext(struct conf **confs, const char *fname)
{
	int ret=0;
	int longest=0;
	int matching=0;
	struct strlist *l=NULL;
	struct strlist *best=NULL;

	if(in_exclude_ext(get_strlist(confs[OPT_EXCEXT]), fname)
	  || in_exclude_regex(get_strlist(confs[OPT_EXCREG]), fname)
		|| !in_include_regex(get_strlist(confs[OPT_INCREG]), fname))
		return 0;

	// Check include/exclude directories.
	for(l=get_strlist(confs[OPT_INCEXCDIR]); l; l=l->next)
	{
		matching=is_subdir(l->path, fname);
		if(matching>=longest)
		{
			longest=matching;
			best=l;
		}
	}
	if(!best) ret=0;
	else ret=best->flag;

	return ret;
}

static int file_is_included(struct conf **confs,
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
	  && !in_include_ext(get_strlist(confs[OPT_INCEXT]), fname)) return 0;

	return file_is_included_no_incext(confs, fname);
}

static int fs_change_is_allowed(struct conf **confs, const char *fname)
{
	struct strlist *l;
	if(get_int(confs[OPT_CROSS_ALL_FILESYSTEMS])) return 1;
	for(l=get_strlist(confs[OPT_FSCHGDIR]); l; l=l->next)
		if(!strcmp(l->path, fname)) return 1;
	return 0;
}

static int need_to_read_fifo(struct conf **confs, const char *fname)
{
	struct strlist *l;
	if(get_int(confs[OPT_READ_ALL_FIFOS])) return 1;
	for(l=get_strlist(confs[OPT_FIFOS]); l; l=l->next)
		if(!strcmp(l->path, fname)) return 1;
	return 0;
}

static int need_to_read_blockdev(struct conf **confs, const char *fname)
{
	struct strlist *l;
	if(get_int(confs[OPT_READ_ALL_BLOCKDEVS])) return 1;
	for(l=get_strlist(confs[OPT_BLOCKDEVS]); l; l=l->next)
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

static int file_size_match(struct FF_PKT *ff_pkt, struct conf **confs)
{
	uint64_t sizeleft;
	uint64_t min_file_size=get_uint64_t(confs[OPT_MIN_FILE_SIZE]);
	uint64_t max_file_size=get_uint64_t(confs[OPT_MAX_FILE_SIZE]);
	sizeleft=(uint64_t)ff_pkt->statp.st_size;

	if(min_file_size && sizeleft<min_file_size)
		return 0;
	if(max_file_size && sizeleft>max_file_size)
		return 0;
	return 1;
}

// Last checks before actually processing the file system entry.
static int my_send_file_w(struct asfd *asfd, struct FF_PKT *ff, bool top_level, struct conf **confs)
{
	if(!file_is_included(confs, ff->fname, top_level)
		|| is_logic_excluded(confs, ff)) return 0;

	// Doing the file size match here also catches hard links.
	if(S_ISREG(ff->statp.st_mode)
	  && !file_size_match(ff, confs))
		return 0;

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

		if((lp=linkhash_search(&ff->statp, &bucket)))
		{
			if(!strcmp(lp->name, ff->fname)) return 0;
			ff->link=lp->name;
			/* Handle link, file already saved */
			ff->type=FT_LNK_H;
		}
		else
		{
			if(linkhash_add(ff->fname,
				&ff->statp, bucket)) return -1;
		}
	}

	return my_send_file(asfd, ff, confs);
}

static int found_regular_file(struct asfd *asfd,
	struct FF_PKT *ff_pkt, struct conf **confs,
	bool top_level)
{
	ff_pkt->type=FT_REG;
	return my_send_file_w(asfd, ff_pkt, top_level, confs);
}

static int found_soft_link(struct asfd *asfd, struct FF_PKT *ff_pkt, struct conf **confs,
	char *fname, bool top_level)
{
	ssize_t size;
	char *buffer=(char *)alloca(fs_full_path_max+102);

	if((size=readlink(fname, buffer, fs_full_path_max+101))<0)
	{
		/* Could not follow link */
		ff_pkt->type=FT_NOFOLLOW;
	}
	else
	{
		buffer[size]=0;
		ff_pkt->link=buffer;	/* point to link */
		ff_pkt->type=FT_LNK_S;	/* got a soft link */
	}
	return my_send_file_w(asfd, ff_pkt, top_level, confs);
}

static int fstype_matches(struct asfd *asfd,
	struct conf **confs, const char *fname, int inex)
{
#if defined(HAVE_LINUX_OS) \
 || defined(HAVE_SUN_OS)
	struct strlist *l;
#if defined(HAVE_LINUX_OS)
	struct statfs buf;
	if(statfs(fname, &buf))
#elif defined(HAVE_SUN_OS)
	struct statvfs buf;
	if(statvfs(fname, &buf))
#endif
	{
		logw(asfd, get_cntr(confs), "Could not statfs %s: %s\n",
			fname, strerror(errno));
		return -1;
	}
	for(l=get_strlist(confs[inex]); l; l=l->next)
#if defined(HAVE_LINUX_OS)
		if(l->flag==buf.f_type)
#elif defined(HAVE_SUN_OS)
		if(strcmp(l->path,buf.f_basetype)==0)
#endif
			return -1;
#elif defined(HAVE_WIN32)
	char filesystem_name[MAX_PATH_UTF8 + 1];
	if (win32_getfsname(fname, filesystem_name, sizeof(filesystem_name)))
		return -1;
	for(strlist *l=get_strlist(confs[inex]); l; l=l->next)
		if(strcmp(l->path,filesystem_name)==0)
			return -1;
#endif
	return 0;
}

#if defined(HAVE_WIN32)
static void windows_reparse_point_fiddling(struct FF_PKT *ff_pkt)
{
	/*
	* We have set st_rdev to 1 if it is a reparse point, otherwise 0,
	*  if st_rdev is 2, it is a mount point.
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
	 */
	if (ff_pkt->statp.st_rdev == WIN32_REPARSE_POINT) {
		ff_pkt->type = FT_REPARSE;
	} else if (ff_pkt->statp.st_rdev == WIN32_JUNCTION_POINT) {
		ff_pkt->type = FT_JUNCTION;
	}
}
#endif

// Prototype because process_entries_in_directory() recurses using find_files().
static int find_files(struct asfd *asfd,
	struct FF_PKT *ff_pkt, struct conf **confs,
	char *fname, dev_t parent_device, bool top_level);

static int process_entries_in_directory(struct asfd *asfd, char **nl,
	int count, char **link, size_t len, size_t *link_len,
	struct conf **confs, struct FF_PKT *ff_pkt, dev_t our_device)
{
	int m=0;
	int ret=0;
	for(m=0; m<count; m++)
	{
		size_t i;
		char *p=NULL;
		char *q=NULL;
		size_t plen;

		p=nl[m];

		if(strlen(p)+len>=*link_len)
		{
			*link_len=len+strlen(p)+1;
			if(!(*link=(char *)
			  realloc_w(*link, (*link_len)+1, __func__)))
				return -1;
		}
		q=(*link)+len;
		plen=strlen(p);
		for(i=0; i<plen; i++)
			*q++=*p++;
		*q=0;
		ff_pkt->flen=i;

		if(file_is_included_no_incext(confs, *link))
		{
			ret=find_files(asfd, ff_pkt,
				confs, *link, our_device, false /*top_level*/);
		}
		else
		{
			struct strlist *x;
			// Excluded, but there might be a subdirectory that is
			// included.
			for(x=get_strlist(confs[OPT_INCEXCDIR]); x; x=x->next)
			{
				if(x->flag
				  && is_subdir(*link, x->path))
				{
					struct strlist *y;
					if((ret=find_files(asfd, ff_pkt,
						confs, x->path,
						our_device, false)))
							break;
					// Now need to skip subdirectories of
					// the thing that we just stuck in
					// find_one_file(), or we might get
					// some things backed up twice.
					for(y=x->next; y; y=y->next)
						if(y->next
						 && is_subdir(x->path, y->path))
							y=y->next;
				}
			}
		}
		free_w(&(nl[m]));
		if(ret) break;
	}
	return ret;
}

static int found_directory(struct asfd *asfd,
	struct FF_PKT *ff_pkt, struct conf **confs,
	char *fname, dev_t parent_device, bool top_level)
{
	int ret=-1;
	char *link=NULL;
	size_t link_len;
	size_t len;
	int nbret=0;
	int count=0;
	dev_t our_device;
	char **nl=NULL;

	our_device=ff_pkt->statp.st_dev;

	/* Build a canonical directory name with a trailing slash in link var */
	len=strlen(fname);
	link_len=len+200;
	if(!(link=(char *)malloc_w(link_len+2, __func__)))
		goto end;
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

	if(my_send_file_w(asfd, ff_pkt, top_level, confs))
		goto end;

	// After my_send_file_w, so that we backup the directory itself.
	if((nbret=nobackup_directory(get_strlist(confs[OPT_NOBACKUP]),
		ff_pkt->fname)))
	{
		if(nbret<0) goto end; // Error.
		ret=0; // Do not back it up.
		goto end;
	}

	if(ff_pkt->type==FT_REPARSE || ff_pkt->type==FT_JUNCTION)
	{
		// Ignore.
		ret=0;
		goto end;
	}

	if(top_level
	  || (parent_device!=ff_pkt->statp.st_dev
#if defined(HAVE_WIN32)
		|| ff_pkt->statp.st_rdev==WIN32_MOUNT_POINT
#endif
		))
	{
		if(fstype_matches(asfd, confs, ff_pkt->fname, OPT_EXCFS)
		  || (get_strlist(confs[OPT_INCFS])
		     && !fstype_matches(asfd, confs, ff_pkt->fname, OPT_INCFS)))
		{
			if(top_level)
				logw(asfd, get_cntr(confs),
					"Skipping '%s' because of file system include or exclude.\n", fname);
			ret=my_send_file_w(asfd, ff_pkt, top_level, confs);
			goto end;
		}
		if(!top_level && !fs_change_is_allowed(confs, ff_pkt->fname))
		{
			ff_pkt->type=FT_NOFSCHG;
			// Just backup the directory and return.
			ret=my_send_file_w(asfd, ff_pkt, top_level, confs);
			goto end;
		}
	}

	ff_pkt->link=ff_pkt->fname;

	errno=0;
	switch(entries_in_directory_alphasort(fname,
		&nl, &count, get_int(confs[OPT_ATIME]),
		/* follow_symlinks */ 0))
	{
		case 0: break;
		case 1:
			ff_pkt->type=FT_NOOPEN;
			ret=my_send_file_w(asfd, ff_pkt, top_level, confs);
		default:
			goto end;
	}

	if(nl)
	{
		if(process_entries_in_directory(asfd, nl, count,
			&link, len, &link_len, confs, ff_pkt, our_device))
				goto end;
	}
	ret=0;
end:
	free_w(&link);
	free_v((void **)&nl);
	return ret;
}

static int found_other(struct asfd *asfd, struct FF_PKT *ff_pkt,
	struct conf **confs, bool top_level)
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
		&& need_to_read_blockdev(confs, ff_pkt->fname))
	{
#else
	if(S_ISBLK(ff_pkt->statp.st_mode)
		&& need_to_read_blockdev(confs, ff_pkt->fname))
	{
#endif
		/* raw partition */
		ff_pkt->type=FT_RAW;
	}
	else if(S_ISFIFO(ff_pkt->statp.st_mode)
		&& need_to_read_fifo(confs, ff_pkt->fname))
	{
		ff_pkt->type=FT_FIFO;
	}
	else
	{
		/* The only remaining are special (character, ...) files */
		ff_pkt->type=FT_SPEC;
	}
	return my_send_file_w(asfd, ff_pkt, top_level, confs);
}

static int find_files(
	struct asfd *asfd,
	struct FF_PKT *ff_pkt,
	struct conf **confs,
	char *fname,
	dev_t parent_device,
	bool top_level
) {
	ff_pkt->fname=fname;
	ff_pkt->link=fname;

#ifdef HAVE_WIN32
	ff_pkt->use_winapi=get_use_winapi(
		get_string(confs[OPT_REMOTE_DRIVES]),
		ff_pkt->fname[0]
	);
	if(win32_lstat(fname, &ff_pkt->statp, &ff_pkt->winattr))
#else
	if(lstat(fname, &ff_pkt->statp))
#endif
	{
		ff_pkt->type=FT_NOSTAT;
		return my_send_file_w(asfd, ff_pkt, top_level, confs);
	}

	if(S_ISREG(ff_pkt->statp.st_mode))
		return found_regular_file(asfd, ff_pkt, confs, top_level);
	else if(S_ISLNK(ff_pkt->statp.st_mode))
	{
#ifdef S_IFLNK
		/* A symlink.
		   If they have specified the symlink in a read_blockdev
		   argument, treat it as a block device.
		*/
		struct strlist *l;
		for(l=get_strlist(confs[OPT_BLOCKDEVS]); l; l=l->next)
		{
			if(!strcmp(l->path, fname))
			{
				ff_pkt->statp.st_mode ^= S_IFLNK;
				ff_pkt->statp.st_mode |= S_IFBLK;
				return found_other(asfd, ff_pkt, confs,
					top_level);
			}
		}
#endif
		return found_soft_link(asfd, ff_pkt, confs, fname, top_level);
	}
	else if(S_ISDIR(ff_pkt->statp.st_mode))
		return found_directory(asfd, ff_pkt, confs, fname,
			parent_device, top_level);
	else
		return found_other(asfd, ff_pkt, confs, top_level);
}

int find_files_begin(struct asfd *asfd,
	struct FF_PKT *ff_pkt, struct conf **confs, char *fname)
{
	return find_files(asfd, ff_pkt,
		confs, fname, (dev_t)-1, 1 /* top_level */);
}
