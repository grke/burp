#include "burp.h"
#include "prog.h"
#include "find.h"
#include "log.h"
#include "asyncio.h"
#include "handy.h"
#include "regexp.h"
#include "backup_client.h"
#ifdef HAVE_DARWIN_OS
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/attr.h>
#endif
#ifdef HAVE_LINUX_OS
#include <sys/statfs.h>
#endif

static int32_t name_max; // Filename max length.
static int32_t path_max; // path name max length.

static int sd=0; // starting directory index.

enum ff_e
{
	FF_NOT_FOUND=0,
	FF_FOUND,
	FF_DIRECTORY,
	FF_ERROR,
};

static void init_max(int32_t *max, int32_t default_max)
{
	*max = pathconf(".", default_max);
	if(*max < 1024) *max = 1024;
	// Add for EOS.
	(*max)++;
}

// Initialize the find files "global" variables.
FF_PKT *find_files_init(void)
{
	FF_PKT *ff;
	ff = (FF_PKT *)calloc(1, sizeof(FF_PKT));

	// Get system path and filename maximum lengths.
	init_max(&path_max, _PC_PATH_MAX);
	init_max(&name_max, _PC_NAME_MAX);

	sd=0;

	return ff;
}

/*
 * Structure for keeping track of hard linked files, we
 *   keep an entry for each hardlinked file that we save,
 *   which is the first one found. For all the other files that
 *   are linked to this one, we save only the directory
 *   entry so we can link it.
 */
struct f_link
{
	struct f_link *next;
	dev_t dev;                        /* device */
	ino_t ino;                        /* inode with device is unique */
	char name[1];                     /* The name */
};

typedef struct f_link link_t;
#define LINK_HASHTABLE_BITS 16
#define LINK_HASHTABLE_SIZE (1<<LINK_HASHTABLE_BITS)
#define LINK_HASHTABLE_MASK (LINK_HASHTABLE_SIZE-1)

// Maybe convert this stuff to uthash?
static inline int LINKHASH(const struct stat &info)
{
	int hash = info.st_dev;
	unsigned long long i = info.st_ino;
	hash ^= i;
	i >>= 16;
	hash ^= i;
	i >>= 16;
	hash ^= i;
	i >>= 16;
	hash ^= i;
	return hash & LINK_HASHTABLE_MASK;
}

static int term_find_one(FF_PKT *ff)
{
	int i;
	int count=0;
	struct f_link *lp;
	struct f_link *lc;

	if(!ff->linkhash) return 0;

	for(i=0; i<LINK_HASHTABLE_SIZE; i++)
	{
		// Free up list of hard linked files.
		lp=ff->linkhash[i];
		while(lp)
		{
			lc=lp;
			lp=lp->next;
			if(lc)
			{
				free(lc);
				count++;
			}
		}
		ff->linkhash[i]=NULL;
	}
	free(ff->linkhash);
	ff->linkhash=NULL;
	return count;
}

static void free_ff_dir(ff_dir *ff_dir)
{
	if(ff_dir)
	{
		if(ff_dir->nl) free(ff_dir->nl);
		if(ff_dir->dirname) free(ff_dir->dirname);
		free(ff_dir);
	}
}

// Terminate find_files() and release all allocated memory.
int find_files_free(FF_PKT *ff)
{
	int hard_links=term_find_one(ff);
	if(ff)
	{
		if(ff->fname) free(ff->fname);
		// Should probably attempt to free the whole ff_dir list here.
		free_ff_dir(ff->ff_dir);
		free(ff);
	}
	return hard_links;
}

static int myalphasort(const struct dirent **a, const struct dirent **b)
{
	return pathcmp((*a)->d_name, (*b)->d_name);
}

// Return 1 to include the file, 0 to exclude it.
static int in_include_ext(struct strlist **incext, int incount, const char *fname)
{
	int i=0;
	const char *cp=NULL;
	// If not doing include_ext, let the file get backed up. 
	if(!incount) return 1;

	// The flag of the first item contains the maximum number of characters
	// that need to be checked.
	for(cp=fname+strlen(fname)-1; i<incext[0]->flag && cp>=fname; cp--, i++)
	{
		if(*cp=='.')
		{
			for(i=0; i<incount; i++)
				if(!strcasecmp(incext[i]->path, cp+1))
					return 1;
			// If file has no extension, it cannot be included.
			return 0;
		}
	}
	return 0;
}

static int in_exclude_ext(struct strlist **excext, int excount, const char *fname)
{
	int i=0;
	const char *cp=NULL;
	// If not doing exclude_ext, let the file get backed up.
	if(!excount) return 0;

	// The flag of the first item contains the maximum number of characters
	// that need to be checked.
	for(cp=fname+strlen(fname)-1; i<excext[0]->flag && cp>=fname; cp--, i++)
	{
		if(*cp=='.')
		{
			for(i=0; i<excount; i++)
				if(!strcasecmp(excext[i]->path, cp+1))
					return 1;
			// If file has no extension, it is included.
			return 0;
		}
	}

	return 0;
}

// Returns the level of compression.
int in_exclude_comp(struct strlist **excom, int excmcount, const char *fname, int compression)
{
	int i=0;
	const char *cp=NULL;
	// If not doing compression, or there are no excludes, return
	// straight away.
	if(!compression || !excmcount) return compression;

	// The flag of the first item contains the maximum number of characters
	// that need to be checked.
	for(cp=fname+strlen(fname)-1; i<excom[0]->flag && cp>=fname; cp--, i++)
	{
		if(*cp=='.')
		{
			for(i=0; i<excmcount; i++)
				if(!strcasecmp(excom[i]->path, cp+1))
					return 0;
			return compression;
		}
	}
	return compression;
}

// Return 1 to include the file, 0 to exclude it.
/* Currently not used - it needs more thinking about.
int in_include_regex(struct strlist **increg, int ircount, const char *fname)
{
	int i;
	// If not doing include_regex, let the file get backed up.
	if(!ircount) return 1;
	for(i=0; i<ircount; i++)
	{
		if(check_regex(increg[i]->re, fname))
			return 1;
	}
	return 0;
}
*/

int in_exclude_regex(struct strlist **excreg, int ercount, const char *fname)
{
	int i;
	// If not doing exclude_regex, let the file get backed up.
	//if(!ercount) return 0; (will return 0 anyway)
	for(i=0; i<ercount; i++)
        {
		if(check_regex(excreg[i]->re, fname))
			return 1;
	}
	return 0;
}

// When recursing into directories, do not want to check the include_ext list.
static int file_is_included_no_incext(struct strlist **ielist, int iecount, struct strlist **excext, int excount, struct strlist **excreg, int ercount, const char *fname)
{
	int i=0;
	int ret=0;
	int longest=0;
	int matching=0;
	int best=-1;

	if(in_exclude_ext(excext, excount, fname)
	  || in_exclude_regex(excreg, ercount, fname))
		return 0;

	// Check include/exclude directories.
	for(i=0; i<iecount; i++)
	{
		//logp("try: %d %s\n", i, ielist[i]->path);
		matching=is_subdir(ielist[i]->path, fname);
		if(matching>longest)
		{
			longest=matching;
			best=i;
		}
	}
	//logp("best: %d\n", best);
	if(best<0) ret=0;
	else ret=ielist[best]->flag;

	//logp("return: %d\n", ret);
	return ret;
}

int file_is_included(struct strlist **ielist, int iecount,
	struct strlist **incexc, int incount,
	struct strlist **excext, int excount,
	struct strlist **increg, int ircount,
	struct strlist **excreg, int ercount,
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
	  && !in_include_ext(incexc, incount, fname)) return 0;

	return file_is_included_no_incext(ielist, iecount,
		excext, excount, excreg, ercount, fname);
}

static int fs_change_is_allowed(struct config *conf, const char *fname)
{
	int i=0;
	if(conf->cross_all_filesystems) return 1;
	for(i=0; i<conf->fscount; i++)
		if(!strcmp(conf->fschgdir[i]->path, fname)) return 1;
	return 0;
}

static int need_to_read_fifo(struct config *conf, const char *fname)
{
	int i=0;
	if(conf->read_all_fifos) return 1;
	for(i=0; i<conf->ffcount; i++)
		if(!strcmp(conf->fifos[i]->path, fname)) return 1;
	return 0;
}

static int need_to_read_blockdev(struct config *conf, const char *fname)
{
	int i=0;
	if(conf->read_all_blockdevs) return 1;
	for(i=0; i<conf->bdcount; i++)
		if(!strcmp(conf->blockdevs[i]->path, fname)) return 1;
	return 0;
}

static int nobackup_directory(struct config *conf, const char *path)
{
	int i=0;
	struct stat statp;
	for(i=0; i<conf->nbcount; i++)
	{
		char *fullpath=NULL;
		if(!(fullpath=prepend_s(path,
		  conf->nobackup[i]->path, strlen(conf->nobackup[i]->path))))
				return -1;
		if(!lstat(fullpath, &statp))
		{
			free(fullpath);
			return 1;
		}
		free(fullpath);
	}
	return 0;
}

#define MODE_RALL (S_IRUSR|S_IRGRP|S_IROTH)
static ff_e found_regular_file(FF_PKT *ff_pkt, struct config *conf,
	struct cntr *cntr, char *fname, bool top_level)
{
	boffset_t sizeleft;

	sizeleft=ff_pkt->statp.st_size;

	// If the user specified a minimum or maximum file size, obey it.
	if(conf->min_file_size && sizeleft<(boffset_t)conf->min_file_size)
		return FF_NOT_FOUND;
	if(conf->max_file_size && sizeleft>(boffset_t)conf->max_file_size)
		return FF_NOT_FOUND;

	/* Don't bother opening empty, world readable files.  Also do not open
	files when archive is meant for /dev/null.  */
	if(!sizeleft && MODE_RALL==(MODE_RALL & ff_pkt->statp.st_mode))
		ff_pkt->type=FT_REGE;
	else
		ff_pkt->type=FT_REG;
	return FF_FOUND;
}

static ff_e found_soft_link(FF_PKT *ff_pkt, struct config *conf,
	struct cntr *cntr, char *fname, bool top_level)
{
	int size;
	char *buffer=(char *)alloca(path_max+name_max+102);

	if((size=readlink(fname, buffer, path_max+name_max+101))<0)
	{
		/* Could not follow link */
		ff_pkt->type=FT_NOFOLLOW;
		return FF_FOUND;
	}
	buffer[size]=0;
	ff_pkt->link=buffer;	/* point to link */
	ff_pkt->type=FT_LNK_S;	/* got a real link */
	return FF_FOUND;
}

static int fstype_excluded(struct config *conf, const char *fname, struct cntr *cntr)
{
#if defined(HAVE_LINUX_OS)
	int i=0;
	struct statfs buf;
	if(statfs(fname, &buf))
	{
		logw(cntr, "Could not statfs %s: %s\n", fname, strerror(errno));
		return -1;
	}
	for(i=0; i<conf->exfscount; i++)
	{
		if(conf->excfs[i]->flag==buf.f_type)
		{
			//printf("excluding: %s (%s)\n",
			//	fname, conf->excfs[i]->path);
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
	if(ff_pkt->statp.st_rdev==WIN32_REPARSE_POINT)
		ff_pkt->type = FT_REPARSE;
	else if(ff_pkt->statp.st_rdev==WIN32_JUNCTION_POINT)
		ff_pkt->type = FT_JUNCTION;
}
#endif

static int get_files_in_directory(DIR *directory, struct dirent ***nl, int *count)
{
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
		if(!(entry=(struct dirent *)malloc(
			sizeof(struct dirent)+name_max+100)))
		{
			log_out_of_memory(__FUNCTION__);
			return -1;
		}
		if(readdir_r(directory, entry, &result) || !result)
		{
			// Got to the end of the directory.
			free(entry);
			break;
		}

		p=entry->d_name;
		ASSERT(name_max+1 > (int)sizeof(struct dirent)+strlen(p));

		if(!p || !strcmp(p, ".") || !strcmp(p, ".."))
		{
			free(entry);
			continue;
		}

		if(*count==allocated)
		{
			if(!allocated) allocated=10;
			else allocated*=2;

			if(!(ntmp=(struct dirent **)
				realloc(*nl, allocated*sizeof(**nl))))
			{
				free(entry);
				log_out_of_memory(__FUNCTION__);
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

static ff_e found_directory(FF_PKT *ff_pkt, struct config *conf,
	struct cntr *cntr, char *fname, dev_t parent_device, bool top_level)
{
	int nbret=0;
	int count=0;
	struct dirent **nl=NULL;

	/*
	 * Ignore this directory and everything below if one of the files
	 * defined by the 'nobackup' option exists.
	 */
	if((nbret=nobackup_directory(conf, ff_pkt->fname)))
	{
		if(nbret<0) return FF_ERROR;
		return FF_NOT_FOUND;
	}

#if defined(HAVE_WIN32)
	windows_reparse_point_fiddling(ff_pkt);
	// Do not treat them like real directories that get descended into.
	if(ff_pkt->type==FT_REPARSE || ff_pkt->type==FT_JUNCTION)
		return FF_FOUND;
#endif

	/*
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
		if(fstype_excluded(conf, ff_pkt->fname, cntr))
		{
			// Just back up the directory entry, not the contents.
			ff_pkt->type=FT_DIR;
			return FF_FOUND;
		}
		if(!fs_change_is_allowed(conf, ff_pkt->fname))
		{
			ff_pkt->type=FT_NOFSCHG;
			return FF_FOUND;
		}
	}

	ff_pkt->type=FT_DIR;
	return FF_DIRECTORY;
}

static ff_e found_other(FF_PKT *ff_pkt, struct config *conf,
	struct cntr *cntr, char *fname, bool top_level)
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
	return FF_FOUND;
}

/*
 * Find a single file.
 * p is the filename
 * parent_device is the device we are currently on
 * top_level is 1 when not recursing or 0 when
 *  descending into a directory.
 */
static ff_e find_files(FF_PKT *ff, struct config *conf, struct cntr *cntr,
	char *fname, dev_t parent_device, bool top_level)
{
	int len;

	if(ff->fname) free(ff->fname);
	ff->fname=strdup(fname);
	ff->link=ff->fname;

#ifdef HAVE_WIN32
	if(win32_lstat(fname, &ff->statp, &ff->winattr))
#else
	if(lstat(fname, &ff->statp))
#endif
	{
		ff->type=FT_NOSTAT;
		return FF_FOUND;
	}

	/*
	 * Handle hard linked files.
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
		if(!(ff->linkhash))
		{
			if(!(ff->linkhash=(link_t **)malloc(
				LINK_HASHTABLE_SIZE*sizeof(link_t *))))
			{
				log_out_of_memory(__FUNCTION__);
				return FF_ERROR;
			}
			memset(ff->linkhash, 0,
				LINK_HASHTABLE_SIZE*sizeof(link_t *));
		}
		const int linkhash=LINKHASH(ff->statp);

		// Search link list of hard linked files
		for(lp=ff->linkhash[linkhash]; lp; lp=lp->next)
		{
		  if(lp->ino==(ino_t)ff->statp.st_ino
			&& lp->dev==(dev_t)ff->statp.st_dev)
		  {
			ff->link=lp->name;
			// Handle link, file already saved.
			ff->type=FT_LNK_H;
			ff->linked=0;
			return FF_FOUND;
		  }
		}

		// File not previously dumped. Chain it into our list.
		len=strlen(fname)+1;
		if(!(lp=(struct f_link *)malloc(sizeof(struct f_link)+len)))
		{
			log_out_of_memory(__FUNCTION__);
			return FF_ERROR;
		}
		lp->ino=ff->statp.st_ino;
		lp->dev=ff->statp.st_dev;

		snprintf(lp->name, len, "%s", fname);
		lp->next=ff->linkhash[linkhash];
		ff->linkhash[linkhash]=lp;
		// Mark saved link.
		ff->linked=lp;
	}
	else
	{
		ff->linked=NULL;
	}

	// This is not a link to a previously dumped file, so dump it.
	if(S_ISREG(ff->statp.st_mode))
		return found_regular_file(ff, conf, cntr, fname, top_level);
	else if(S_ISDIR(ff->statp.st_mode))
		return found_directory(ff, conf, cntr, fname,
			parent_device, top_level);
	else if(S_ISLNK(ff->statp.st_mode))
	{
#ifdef S_IFLNK
		/* A symlink.
		   If they have specified the symlink in a read_blockdev
		   argument, treat it as a block device.
		*/
		int i=0;
		for(i=0; i<conf->bdcount; i++)
		{
			if(!strcmp(conf->blockdevs[i]->path, fname))
			{
				ff->statp.st_mode ^= S_IFLNK;
				ff->statp.st_mode |= S_IFBLK;
				return found_other(ff, conf, cntr, fname,
					top_level);
			}
		}
#endif
		return found_soft_link(ff, conf, cntr, fname, top_level);
	}
	else
		return found_other(ff, conf, cntr, fname, top_level);
}

static int set_up_new_ff_dir(FF_PKT *ff)
{
	static DIR *directory;
	static struct ff_dir *ff_dir;
	static size_t len;

	len=strlen(ff->fname)+2;
	if(!(ff_dir=(struct ff_dir *)calloc(1, sizeof(struct ff_dir)))
	  || !(ff_dir->dirname=(char *)malloc(len)))
	{
		free(ff_dir);
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	snprintf(ff_dir->dirname, len, "%s", ff->fname);

	errno = 0;
	if(!(directory=opendir(ff->fname)))
	{
		ff->type=FT_NOOPEN;
		free(ff_dir->dirname);
		free(ff_dir);
		return 0;
	}
	if(get_files_in_directory(directory, &(ff_dir->nl), &(ff_dir->count)))
	{
		closedir(directory);
		free_ff_dir(ff_dir);
		return -1;
	}
	closedir(directory);

	if(!ff_dir->count)
	{
		// Nothing in the directory. Just back up the directory entry.
		free_ff_dir(ff_dir);
		return 0;
	}

	ff_dir->dev=ff->statp.st_dev;

	// Strip all trailing slashes.
	len=strlen(ff_dir->dirname);
	while(len >= 1 && IsPathSeparator(ff_dir->dirname[len - 1])) len--;
	// Add one back.
	ff_dir->dirname[len++]='/';
	ff_dir->dirname[len]=0;

	// Add it to the beginning of our list.
	ff_dir->next=ff->ff_dir;
	ff->ff_dir=ff_dir;
	return 0;
}

static int deal_with_ff_ret(FF_PKT *ff, ff_e ff_ret)
{
	switch(ff_ret)
	{
		case FF_DIRECTORY:
			if(set_up_new_ff_dir(ff)) return -1;
			// Fall through to record the directory itself.
		case FF_FOUND:
			// Now ff should be set up with the next entry.
			return 0;
		case FF_NOT_FOUND:
			// Should never get here.
		case FF_ERROR:
		default:
			break;
	}
	return -1;
}

// Returns -1 on error. 1 on finished, 0 on more stuff to do.
// Fills ff with information about the next file to back up.
int find_file_next(FF_PKT *ff, struct config *conf, struct cntr *p1cntr, bool *top_level)
{
	static ff_e ff_ret;

	if(ff->ff_dir)
	{
		// Have already recursed into a directory.
		// Get the next entry.
		static struct dirent *nl;
		static struct ff_dir *ff_dir;
		char *path=NULL;

		ff_dir=ff->ff_dir;
		nl=ff_dir->nl[ff_dir->c++];

		if(!(path=prepend(ff_dir->dirname,
			nl->d_name, strlen(nl->d_name), NULL))) goto error;
		free(nl);

		if(file_is_included_no_incext(conf->incexcdir, conf->iecount,
			conf->excext, conf->excount,
			conf->excreg, conf->ercount,
			path))
		{
			while((ff_ret=find_files(ff, conf, p1cntr,
				path, ff_dir->dev, false))==FF_NOT_FOUND) { }
		}
		else
		{
			ff_ret=FF_NOT_FOUND;
/* BIG TODO: Make this bit work. Probably have to remember that we are inside
   a directory that was excluded.
			// Excluded, but there might be a subdirectory that is
			// included.
			int ex=0;
			for(ex=0; ex<conf->iecount; ex++)
			{
				if(conf->incexcdir[ex]->flag
				  && is_subdir(path, conf->incexcdir[ex]->path))
				{
					while((ff_ret=find_files(ff, conf,
						p1cntr,
						conf->incexcdir[ex]->path,
						ff_dir->dev,
						false))==FF_NOT_FOUND) { }
				}
				break;
			}
			if(ex==conf->iecount) ff_ret=FF_NOT_FOUND;
*/
		}
		free(path);

		if(ff_dir->c>=ff_dir->count)
		{
			free_ff_dir(ff->ff_dir);
			ff->ff_dir=ff_dir->next;
		}

		if(ff_ret!=FF_NOT_FOUND)
		{
			if(deal_with_ff_ret(ff, ff_ret)) goto error;
			return 0;
		}
	}

	if(sd>=conf->sdcount)
	{
		// No more to do.
		return 1;
	}
	if(conf->startdir[sd]->flag)
	{
		// Keep going until it does not give 'not found'.
		while((ff_ret=find_files(ff, conf, p1cntr,
			conf->startdir[sd]->path,
			(dev_t)-1, 1 /* top_level */))==FF_NOT_FOUND) { }
		sd++;

		if(deal_with_ff_ret(ff, ff_ret)) goto error;
	}

	return 0;
error:
	// FIX THIS: Free stuff here.
	return -1;
}
