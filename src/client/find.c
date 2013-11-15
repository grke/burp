#include "include.h"

#ifdef HAVE_DARWIN_OS
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/attr.h>
#endif
#ifdef HAVE_LINUX_OS
#include <sys/statfs.h>
#endif

#include <dirent.h>

// File types.
#define FT_LNK_H      1  // hard link to file already saved.
#define FT_REG        3  // Regular file.
#define FT_LNK_S      4  // Soft Link.
#define FT_DIR        5  // Directory.
#define FT_SPEC       6  // Special file -- chr, blk, fifo, sock.
#define FT_NOFOLLOW   8  // Could not follow link.
#define FT_NOSTAT     9  // Could not stat file.
#define FT_NOFSCHG   14  // Different file system, prohibited.
#define FT_NOOPEN    15  // Could not open directory.
#define FT_RAW       16  // Raw block device.
#define FT_FIFO      17  // Raw fifo device.
#define FT_REPARSE   21  // Win NTFS reparse point.
#define FT_JUNCTION  26  // Win32 Junction point.

static int32_t name_max; // Filename max length.
static int32_t path_max; // path name max length.

static int sd=0; // starting directory index.

typedef struct ff_dir ff_dir_t;

struct ff_dir
{
	struct dirent **nl;
	int count;
	int c;
	char *dirname;
	dev_t dev;
	struct ff_dir *next;
};

static struct ff_dir *ff_dir_list=NULL;

static uint8_t top_level=0;

/*
 * Structure for keeping track of hard linked files, we
 *   keep an entry for each hardlinked file that we save,
 *   which is the first one found. For all the other files that
 *   are linked to this one, we save only the directory
 *   entry so we can link it.
 */
typedef struct f_link link_t;
struct f_link
{
	struct f_link *next;
	dev_t dev;           // Device.
	ino_t ino;           // Inode with device is unique.
	char *name;          // The name.
};

// List of all hard linked files found.
static struct f_link **linkhash=NULL;

#define LINK_HASHTABLE_BITS 16
#define LINK_HASHTABLE_SIZE (1<<LINK_HASHTABLE_BITS)
#define LINK_HASHTABLE_MASK (LINK_HASHTABLE_SIZE-1)

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
int find_files_init(void)
{
	if(!(linkhash=(link_t **)
		calloc(1, LINK_HASHTABLE_SIZE*sizeof(link_t *))))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}

	// Get system path and filename maximum lengths.
	init_max(&path_max, _PC_PATH_MAX);
	init_max(&name_max, _PC_NAME_MAX);

	sd=0;

	return 0;
}

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

static void free_linkhash(void)
{
	int i;
	int count=0;
	struct f_link *lp;
	struct f_link *lc;

	if(!linkhash) return;

	for(i=0; i<LINK_HASHTABLE_SIZE; i++)
	{
		// Free up list of hard linked files.
		lp=linkhash[i];
		while(lp)
		{
			lc=lp;
			lp=lp->next;
			if(lc)
			{
				if(lc->name) free(lc->name);
				free(lc);
				count++;
			}
		}
		linkhash[i]=NULL;
	}
	free(linkhash);
	linkhash=NULL;
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
void find_files_free(void)
{
	free_linkhash();
	// Should probably attempt to free the whole ff_dir list here.
	if(ff_dir_list) free_ff_dir(ff_dir_list);
}

static int myalphasort(const struct dirent **a, const struct dirent **b)
{
	return pathcmp((*a)->d_name, (*b)->d_name);
}

// Return 1 to include the file, 0 to exclude it.
static int in_include_ext(struct strlist **incext, int incount, const char *path)
{
	int i=0;
	const char *cp=NULL;
	// If not doing include_ext, let the file get backed up. 
	if(!incount) return 1;
printf("check inc %d: %s\n", incount, path);

	// The flag of the first item contains the maximum number of characters
	// that need to be checked.
	for(cp=path+strlen(path)-1; i<incext[0]->flag && cp>=path; cp--, i++)
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

static int in_exclude_ext(struct strlist **excext, int excount, const char *path)
{
	int i=0;
	const char *cp=NULL;
	// If not doing exclude_ext, let the file get backed up.
	if(!excount) return 0;

	// The flag of the first item contains the maximum number of characters
	// that need to be checked.
	for(cp=path+strlen(path)-1; i<excext[0]->flag && cp>=path; cp--, i++)
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
static int in_exclude_comp(struct strlist **excom, int excmcount, const char *path, int compression)
{
	int i=0;
	const char *cp=NULL;
	// If not doing compression, or there are no excludes, return
	// straight away.
	if(!compression || !excmcount) return compression;

	// The flag of the first item contains the maximum number of characters
	// that need to be checked.
	for(cp=path+strlen(path)-1; i<excom[0]->flag && cp>=path; cp--, i++)
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
static int in_include_regex(struct strlist **increg, int ircount, const char *path)
{
	int i;
	// If not doing include_regex, let the file get backed up.
	if(!ircount) return 1;
	for(i=0; i<ircount; i++)
	{
		if(check_regex(increg[i]->re, path))
			return 1;
	}
	return 0;
}
*/

static int in_exclude_regex(struct strlist **excreg, int ercount, const char *path)
{
	int i;
	// If not doing exclude_regex, let the file get backed up.
	//if(!ercount) return 0; (will return 0 anyway)
	for(i=0; i<ercount; i++)
        {
		if(check_regex(excreg[i]->re, path))
			return 1;
	}
	return 0;
}

// When recursing into directories, do not want to check the include_ext list.
static int file_is_included_no_incext(struct strlist **ielist, int iecount, struct strlist **excext, int excount, struct strlist **excreg, int ercount, const char *path)
{
	int i=0;
	int ret=0;
	int longest=0;
	int matching=0;
	int best=-1;

	if(in_exclude_ext(excext, excount, path)
	  || in_exclude_regex(excreg, ercount, path))
		return 0;

	// Check include/exclude directories.
	for(i=0; i<iecount; i++)
	{
		//logp("try: %d %s\n", i, ielist[i]->path);
		matching=is_subdir(ielist[i]->path, path);
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

static int file_is_included(struct strlist **ielist, int iecount,
	struct strlist **incexc, int incount,
	struct strlist **excext, int excount,
	struct strlist **increg, int ircount,
	struct strlist **excreg, int ercount,
	const char *path)
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
	  && !in_include_ext(incexc, incount, path)) return 0;

	return file_is_included_no_incext(ielist, iecount,
		excext, excount, excreg, ercount, path);
}

static int fs_change_is_allowed(struct config *conf, const char *path)
{
	int i=0;
	if(conf->cross_all_filesystems) return 1;
	for(i=0; i<conf->fscount; i++)
		if(!strcmp(conf->fschgdir[i]->path, path)) return 1;
	return 0;
}

static int need_to_read_fifo(struct config *conf, const char *path)
{
	int i=0;
	if(conf->read_all_fifos) return 1;
	for(i=0; i<conf->ffcount; i++)
		if(!strcmp(conf->fifos[i]->path, path)) return 1;
	return 0;
}

static int need_to_read_blockdev(struct config *conf, const char *path)
{
	int i=0;
	if(conf->read_all_blockdevs) return 1;
	for(i=0; i<conf->bdcount; i++)
		if(!strcmp(conf->blockdevs[i]->path, path)) return 1;
	return 0;
}

static int nobackup_directory(struct config *conf, const char *path)
{
	int i=0;
	struct stat statp;
	for(i=0; i<conf->nbcount; i++)
	{
		char *fullpath=NULL;
		if(!(fullpath=prepend_s(path, conf->nobackup[i]->path)))
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
static ff_e found_regular_file(struct sbuf *sb, struct config *conf,
	char *path)
{
	// If the user specified a minimum or maximum file size, obey it.
	if(conf->min_file_size
		&& sb->statp.st_size<(unsigned int)conf->min_file_size)
			return FF_NOT_FOUND;
	if(conf->max_file_size
		&& sb->statp.st_size>(unsigned int)conf->max_file_size)
			return FF_NOT_FOUND;

	sb->ftype=FT_REG;

	return FF_FOUND;
}

static ff_e found_soft_link(struct sbuf *sb, struct config *conf, char *path)
{
	int size;
	char *linkto=NULL;
	if(!(linkto=(char *)malloc(path_max+name_max+102)))
	{
		log_out_of_memory(__FUNCTION__);
		return FF_ERROR;
	}

	if((size=readlink(path, linkto, path_max+name_max+101))<0)
	{
		/* Could not follow link */
		sb->ftype=FT_NOFOLLOW;
		free(linkto);
		return FF_FOUND;
	}
	linkto[size]=0;
	sb->lbuf.cmd=CMD_SOFT_LINK;
	sb->lbuf.buf=linkto;
	sb->lbuf.len=strlen(linkto);
	sb->ftype=FT_LNK_S;
	return FF_FOUND;
}

static int fstype_excluded(struct config *conf, const char *path)
{
#if defined(HAVE_LINUX_OS)
	int i=0;
	struct statfs buf;
	if(statfs(path, &buf))
	{
		logp("Could not statfs %s: %s\n", path, strerror(errno));
		return -1;
	}
	for(i=0; i<conf->exfscount; i++)
	{
		if(conf->excfs[i]->flag==buf.f_type)
		{
			//printf("excluding: %s (%s)\n",
			//	path, conf->excfs[i]->path);
			return -1;
		}
	}
#endif
	return 0;
}

#if defined(HAVE_WIN32)
static void windows_reparse_point_fiddling(struct sbuf *sb)
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
	if(sb->statp.st_rdev==WIN32_REPARSE_POINT)
		sb->ftype = FT_REPARSE;
	else if(sb->statp.st_rdev==WIN32_JUNCTION_POINT)
		sb->ftype = FT_JUNCTION;
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

static ff_e found_directory(struct sbuf *sb, struct config *conf,
	char *path, dev_t parent_device)
{
	int nbret=0;

	/*
	 * Ignore this directory and everything below if one of the files
	 * defined by the 'nobackup' option exists.
	 */
	if((nbret=nobackup_directory(conf, sb->pbuf.buf)))
	{
		if(nbret<0) return FF_ERROR;
		return FF_NOT_FOUND;
	}

#if defined(HAVE_WIN32)
	windows_reparse_point_fiddling(sb);
	// Do not treat them like real directories that get descended into.
	if(sb->ftype==FT_REPARSE || sb->ftype==FT_JUNCTION)
		return FF_FOUND;
#endif

	/*
	 * If we are crossing file systems, we are either not allowed
	 * to cross, or we may be restricted by a list of permitted
	 * file systems.
	 */
	if(!top_level
	  && (parent_device!=sb->statp.st_dev
#if defined(HAVE_WIN32)
		|| sb->statp.st_rdev==WIN32_MOUNT_POINT
#endif
		))
	{
		if(fstype_excluded(conf, sb->pbuf.buf))
		{
			// Just back up the directory entry, not the contents.
			sb->ftype=FT_DIR;
			return FF_FOUND;
		}
		if(!fs_change_is_allowed(conf, sb->pbuf.buf))
		{
			sb->ftype=FT_NOFSCHG;
			return FF_FOUND;
		}
	}

	sb->ftype=FT_DIR;
	return FF_DIRECTORY;
}

static ff_e found_other(struct sbuf *sb, struct config *conf, char *path)
{
#ifdef HAVE_FREEBSD_OS
	/*
	 * On FreeBSD, all block devices are character devices, so
	 *   to be able to read a raw disk, we need the check for
	 *   a character device.
	 * crw-r----- 1 root  operator - 116, 0x00040002 Jun 9 19:32 /dev/ad0s3
	 * crw-r----- 1 root  operator - 116, 0x00040002 Jun 9 19:32 /dev/rad0s3
	 */
	if((S_ISBLK(sb->statp.st_mode) || S_ISCHR(sb->statp.st_mode))
		&& need_to_read_blockdev(conf, sb->pbuf.buf))
	{
#else
	if(S_ISBLK(sb->statp.st_mode)
		&& need_to_read_blockdev(conf, sb->pbuf.buf))
	{
#endif
		/* raw partition */
		sb->ftype = FT_RAW;
	}
	else if(S_ISFIFO(sb->statp.st_mode)
		&& need_to_read_fifo(conf, sb->pbuf.buf))
	{
		sb->ftype=FT_FIFO;
	}
	else
	{
		/* The only remaining are special (character, ...) files */
		sb->ftype=FT_SPEC;
	}
	return FF_FOUND;
}

static ff_e find_files(struct sbuf *sb, struct config *conf,
	char *path, dev_t parent_device)
{
	if(sb->pbuf.buf) free(sb->pbuf.buf);
	if(!(sb->pbuf.buf=strdup(path)))
	{
                log_out_of_memory(__FUNCTION__);
		return FF_ERROR;
	}

#ifdef HAVE_WIN32
	if(win32_lstat(path, &sb->statp, &sb->winattr))
#else
	if(lstat(path, &sb->statp))
#endif
	{
		sb->ftype=FT_NOSTAT;
		return FF_FOUND;
	}

	sb->compression=in_exclude_comp(conf->excom, conf->excmcount,
		sb->pbuf.buf, conf->compression);
	if(attribs_encode(sb)) return FF_ERROR;

	/*
	 * Handle hard linked files.
	 * Maintain a list of hard linked files already backed up. This
	 *  allows us to ensure that the data of each file gets backed
	 *  up only once.
	 */
	if(sb->statp.st_nlink > 1
	  && (S_ISREG(sb->statp.st_mode)
		|| S_ISCHR(sb->statp.st_mode)
		|| S_ISBLK(sb->statp.st_mode)
		|| S_ISFIFO(sb->statp.st_mode)
		|| S_ISSOCK(sb->statp.st_mode)))
	{

		struct f_link *lp;
		const int linkhash_ind=LINKHASH(sb->statp);

		// Search link list of hard linked files
		for(lp=linkhash[linkhash_ind]; lp; lp=lp->next)
		{
			if(lp->ino==(ino_t)sb->statp.st_ino
				&& lp->dev==(dev_t)sb->statp.st_dev)
			{
				sb->lbuf.cmd=CMD_HARD_LINK;
				if(!(sb->lbuf.buf=strdup(lp->name)))
				{
                			log_out_of_memory(__FUNCTION__);
					return FF_ERROR;
				}
				sb->lbuf.len=strlen(sb->lbuf.buf);
				// Handle link, file already saved.
				sb->ftype=FT_LNK_H;
				return FF_FOUND;
			}
		}

		// File not previously dumped. Chain it into our list.
		if(!(lp=(struct f_link *)malloc(sizeof(struct f_link)))
		  || !(lp->name=strdup(path)))
		{
			log_out_of_memory(__FUNCTION__);
			return FF_ERROR;
		}
		lp->ino=sb->statp.st_ino;
		lp->dev=sb->statp.st_dev;

		lp->next=linkhash[linkhash_ind];
		linkhash[linkhash_ind]=lp;
	}

	// This is not a link to a previously dumped file, so dump it.
	if(S_ISREG(sb->statp.st_mode))
	{
		return found_regular_file(sb, conf, path);
	}
	else if(S_ISDIR(sb->statp.st_mode))
	{
		return found_directory(sb, conf, path, parent_device);
	}
	else if(S_ISLNK(sb->statp.st_mode))
	{
#ifdef S_IFLNK
		/* A symlink.
		   If they have specified the symlink in a read_blockdev
		   argument, treat it as a block device.
		*/
		int i=0;
		for(i=0; i<conf->bdcount; i++)
		{
			if(!strcmp(conf->blockdevs[i]->path, path))
			{
				sb->statp.st_mode ^= S_IFLNK;
				sb->statp.st_mode |= S_IFBLK;
				return found_other(sb, conf, path);
			}
		}
#endif
		return found_soft_link(sb, conf, path);
	}
	else
	{
		return found_other(sb, conf, path);
	}
}

static int set_up_new_ff_dir(struct sbuf *sb, struct config *conf)
{
	static DIR *directory;
	static struct ff_dir *ff_dir;
	static size_t len;

	len=strlen(sb->pbuf.buf)+2;
	if(!(ff_dir=(struct ff_dir *)calloc(1, sizeof(struct ff_dir)))
	  || !(ff_dir->dirname=(char *)malloc(len)))
	{
		free(ff_dir);
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	snprintf(ff_dir->dirname, len, "%s", sb->pbuf.buf);

	errno = 0;
#ifdef O_DIRECTORY
	int dfd=-1;
	// Shenanigans to set O_NOATIME on a directory.
	if((dfd=open(sb->pbuf.buf, O_RDONLY|O_DIRECTORY|O_NOATIME))<0
	  || !(directory=fdopendir(dfd)))
#else
	if(!(directory=opendir(sb->pbuf.buf)))
#endif
	{
#ifdef O_DIRECTORY
		if(dfd>=0) close(dfd);
#endif
		sb->ftype=FT_NOOPEN;
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

	ff_dir->dev=sb->statp.st_dev;

	// Strip all trailing slashes.
	len=strlen(ff_dir->dirname);
	while(len >= 1 && IsPathSeparator(ff_dir->dirname[len - 1])) len--;
	// Add one back.
	ff_dir->dirname[len++]='/';
	ff_dir->dirname[len]=0;

	// Add it to the beginning of our list.
	ff_dir->next=ff_dir_list;
	ff_dir_list=ff_dir;
	return 0;
}

static int deal_with_ff_ret(struct sbuf *sb, ff_e ff_ret, struct config *conf)
{
	switch(ff_ret)
	{
		case FF_DIRECTORY:
			if(set_up_new_ff_dir(sb, conf)) return -1;
			// Fall through to record the directory itself.
		case FF_FOUND:
			// Now sb should be set up with the next entry.
			return 0;
		case FF_NOT_FOUND:
			return 0;
		case FF_ERROR:
		default:
			break;
	}
	return -1;
}

// Returns -1 on error. 1 on finished, 0 on more stuff to do.
// Fills ff with information about the next file to back up.
int find_file_next(struct sbuf *sb, struct config *conf)
{
	static ff_e ff_ret;

	if(ff_dir_list)
	{
		// Have already recursed into a directory.
		// Get the next entry.
		static struct dirent *nl;
		static struct ff_dir *ff_dir;
		char *path=NULL;

		if(top_level) top_level=0;

		ff_dir=ff_dir_list;
		nl=ff_dir->nl[ff_dir->c++];

		if(!(path=prepend(ff_dir->dirname,
			nl->d_name, strlen(nl->d_name), NULL))) goto error;
		free(nl);

		if(file_is_included_no_incext(conf->incexcdir, conf->iecount,
			conf->excext, conf->excount,
			conf->excreg, conf->ercount,
			path))
		{
			ff_ret=find_files(sb, conf, path, ff_dir->dev);
			//if(ff_ret==FF_NOT_FOUND)
			//	return find_file_next(sb, conf);
		}
		else
		{
			ff_ret=FF_NOT_FOUND;
/* BIG FIX THIS: Make this bit work. Probably have to remember that we are
   inside a directory that was excluded.
			// Excluded, but there might be a subdirectory that is
			// included.
			int ex=0;
			for(ex=0; ex<conf->iecount; ex++)
			{
				if(conf->incexcdir[ex]->flag
				  && is_subdir(path, conf->incexcdir[ex]->path))
				{
					while((ff_ret=find_files(sb, conf,
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
			ff_dir_list=ff_dir->next;
			free_ff_dir(ff_dir);
		}

		if(deal_with_ff_ret(sb, ff_ret, conf)) goto error;
		return 0;
	}

	if(sd>=conf->sdcount)
	{
		// No more to do.
		return 1;
	}
	if(conf->startdir[sd]->flag)
	{
		// Keep going until it does not give 'not found'.
		top_level=1;
		while((ff_ret=find_files(sb, conf,
			conf->startdir[sd]->path,
			(dev_t)-1))==FF_NOT_FOUND)
		{
			if(top_level) top_level=0;
		}
		sd++;

		if(deal_with_ff_ret(sb, ff_ret, conf)) goto error;
	}

	return 0;
error:
	// FIX THIS: Free stuff here.
	return -1;
}






// Should somehow merge the FT_ and the CMD_ stuff.

static int ft_err(struct sbuf *sb, struct config *conf, const char *msg)
{
	logw(conf->p1cntr, _("Err: %s %s: %s"),
		msg, sb->pbuf.buf, strerror(errno));
	return -1;
}

// Return -1 if the entry is not to be sent, 0 if it is.
int ftype_to_cmd(struct sbuf *sb, struct config *conf)
{
	if(!file_is_included(conf->incexcdir, conf->iecount,
		conf->incext, conf->incount,
		conf->excext, conf->excount,
		conf->increg, conf->ircount,
		conf->excreg, conf->ercount,
		sb->pbuf.buf)) return -1;

#ifdef HAVE_WIN32
	if(sb->winattr & FILE_ATTRIBUTE_ENCRYPTED)
	{
		if(sb->ftype==FT_REG
		  || sb->ftype==FT_DIR)
		{
			sb->pbuf.cmd=CMD_EFS_FILE;
			sb->pbuf.len=strlen(sb->pbuf.buf);
			return 0;
		}

		// Hopefully, here is never reached.
		logw(conf->p1cntr, "EFS type %d not yet supported: %s",
			sb->ftype, sb->pbuf.buf);
		return -1;
	}
#endif
	//logp("%d: %s\n", sb->type, sb->path);

	switch(sb->ftype)
	{
		case FT_REG:
		case FT_FIFO:
		case FT_RAW:
			if(conf->encryption_password) sb->pbuf.cmd=CMD_ENC_FILE;
			else sb->pbuf.cmd=CMD_FILE;
			sb->pbuf.len=strlen(sb->pbuf.buf);
			return 0;
		case FT_DIR:
		case FT_REPARSE:
		case FT_JUNCTION:
#ifdef HAVE_WIN32
			if(conf->encryption_password) sb->pbuf.cmd=CMD_ENC_FILE;
			else sb->pbuf.cmd=CMD_FILE;
#else
			sb->pbuf.cmd=CMD_DIRECTORY;
#endif
			sb->pbuf.len=strlen(sb->pbuf.buf);
			return 0;
		case FT_NOFSCHG:
			logw(conf->p1cntr, "%s%s [will not descend: file system change not allowed]\n", "Dir: ", sb->pbuf.buf);
			return -1;
#ifndef HAVE_WIN32
		case FT_SPEC: // special file - fifo, socket, device node...
			sb->pbuf.cmd=CMD_SPECIAL;
			sb->pbuf.len=strlen(sb->pbuf.buf);
			return 0;
		case FT_LNK_S:
			sb->pbuf.cmd=CMD_SOFT_LINK;
			sb->pbuf.len=strlen(sb->pbuf.buf);
			return 0;
		case FT_LNK_H:
			sb->pbuf.cmd=CMD_HARD_LINK;
			sb->pbuf.len=strlen(sb->pbuf.buf);
			return 0;
#endif
		case FT_NOFOLLOW:
			return ft_err(sb, conf, "Could not follow link");
		case FT_NOSTAT:
			return ft_err(sb, conf, "Could not stat");
		case FT_NOOPEN:
			return ft_err(sb, conf, "Could not open directory");
	}
	logw(conf->p1cntr, _("Err: Unknown file sb->ftype %d: %s"),
		sb->ftype, sb->pbuf.buf);
	return -1;
}
