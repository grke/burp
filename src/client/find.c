#include "include.h"

#include "../legacy/burpconfig.h"

#ifdef HAVE_LINUX_OS
#include <sys/statfs.h>
#endif

int32_t name_max;	/* filename max length */
int32_t path_max;	/* path name max length */

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
	dev_t dev;		/* device */
	ino_t ino;		/* inode with device is unique */
	char *name;		/* The name */
};

// List of all hard linked files found.
static struct f_link **linkhash=NULL;

#define LINK_HASHTABLE_BITS 16
#define LINK_HASHTABLE_SIZE (1<<LINK_HASHTABLE_BITS)
#define LINK_HASHTABLE_MASK (LINK_HASHTABLE_SIZE-1)

static void init_max(int32_t *max, int32_t default_max)
{
	*max=pathconf(".", default_max);
	if(*max<1024) *max=1024;
	// Add for EOS.
	(*max)++;
}

// Initialize the find files "global" variables
FF_PKT *find_files_init(void)
{
	FF_PKT *ff;

	if(!(ff=(FF_PKT *)calloc(1, sizeof(FF_PKT)))
	  || !(linkhash=(f_link **)
		calloc(1, LINK_HASHTABLE_SIZE*sizeof(f_link *))))
	{
		log_out_of_memory(__FUNCTION__);
		return NULL;
	}

	// Get system path and filename maximum lengths.
	init_max(&path_max, _PC_PATH_MAX);
	init_max(&name_max, _PC_NAME_MAX);

	return ff;
}

static inline int LINKHASH(const struct stat &info)
{
	int hash=info.st_dev;
	unsigned long long i=info.st_ino;
	hash ^= i;
	i >>= 16;
	hash ^= i;
	i >>= 16;
	hash ^= i;
	i >>= 16;
	hash ^= i;
	return hash & LINK_HASHTABLE_MASK;
}

static int free_linkhash(void)
{
	int i;
	int count=0;
	struct f_link *lp;
	struct f_link *lc;

	if(!linkhash) return 0;

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
	return count;
}

void find_files_free(FF_PKT *ff)
{
	free_linkhash();
	free(ff);
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

int file_is_included(struct conf *conf, const char *fname, bool top_level)
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
			free(fullpath);
			return 1;
		}
		free(fullpath);
	}
	return 0;
}

static int found_regular_file(FF_PKT *ff_pkt, struct conf *conf,
	char *fname, bool top_level)
{
	boffset_t sizeleft;

	sizeleft=ff_pkt->statp.st_size;

	// If the user specified a minimum or maximum file size, obey it.
	if(conf->min_file_size && sizeleft<(boffset_t)conf->min_file_size)
		return 0;
	if(conf->max_file_size && sizeleft>(boffset_t)conf->max_file_size)
		return 0;

	ff_pkt->type=FT_REG;

	return send_file(ff_pkt, top_level, conf);
}

static int found_soft_link(FF_PKT *ff_pkt, struct conf *conf,
	char *fname, bool top_level)
{
	int size;
	char *buffer=(char *)alloca(path_max+name_max+102);

	if((size=readlink(fname, buffer, path_max+name_max+101))<0)
	{
		/* Could not follow link */
		ff_pkt->type=FT_NOFOLLOW;
		return send_file(ff_pkt, top_level, conf);
	}
	buffer[size]=0;
	ff_pkt->link=buffer;	/* point to link */
	ff_pkt->type=FT_LNK_S;	/* got a soft link */
	return send_file(ff_pkt, top_level, conf);
}

int fstype_excluded(struct conf *conf, const char *fname)
{
#if defined(HAVE_LINUX_OS)
	struct statfs buf;
	struct strlist *l;
	if(statfs(fname, &buf))
	{
		logw(conf->p1cntr, "Could not statfs %s: %s\n",
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
	   TODO: split into a scandir function
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
		status=readdir_r(directory, entry, &result);
		if(status || !result)
		{
			free(entry);
			break;
		}

		p=entry->d_name;
		ASSERT(name_max+1 > (int)sizeof(struct dirent)+strlen(p));

		/* Skip `.', `..', and excluded file names.  */
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
				realloc (*nl, allocated*sizeof(**nl))))
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

/* prototype, because process_files_in_directory() recurses using find_files()
 */
static int find_files(FF_PKT *ff_pkt, struct conf *conf,
	char *fname, dev_t parent_device, bool top_level);

static int process_files_in_directory(struct dirent **nl, int count, int *rtn_stat, char **link, size_t len, size_t *link_len, struct conf *conf, FF_PKT *ff_pkt, dev_t our_device)
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
			if(!(*link=(char *)realloc(*link, (*link_len)+1)))
			{
				log_out_of_memory(__FUNCTION__);
				return -1;
			}
		}
		q=(*link)+len;
		for(i=0; i<strlen(nl[m]->d_name); i++)
			*q++=*p++;
		*q=0;
		ff_pkt->flen=i;

		if(file_is_included_no_incext(conf, *link))
		{
			*rtn_stat=find_files(ff_pkt,
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
					if((*rtn_stat=find_files(ff_pkt, conf,
						x->path, our_device, false)))
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
		free(nl[m]);
		if(*rtn_stat) break;
	}
	return 0;
}

static int found_directory(FF_PKT *ff_pkt, struct conf *conf,
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
	if(!(link=(char *)malloc(link_len+2)))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
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

	rtn_stat=send_file(ff_pkt, top_level, conf);
	if(rtn_stat || ff_pkt->type==FT_REPARSE || ff_pkt->type==FT_JUNCTION)
	{
		 /* ignore or error status */
		free(link);
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
		if(fstype_excluded(conf, ff_pkt->fname))
		{
			free(link);
			return send_file(ff_pkt, top_level, conf);
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
		free(link);
		return send_file(ff_pkt, top_level, conf);
	}

	/* reset "link" */
	ff_pkt->link=ff_pkt->fname;

	/*
	* Descend into or "recurse" into the directory to read
	*   all the files in it.
	*/
	errno = 0;
#ifdef O_DIRECTORY
	int dfd=-1;
	if((dfd=open(fname, O_RDONLY|O_DIRECTORY|O_NOATIME))<0
	  || !(directory=fdopendir(dfd)))
#else
	if(!(directory=opendir(fname)))
#endif
	{
#ifdef O_DIRECTORY
		if(dfd>=0) close(dfd);
#endif
		ff_pkt->type=FT_NOOPEN;
		rtn_stat=send_file(ff_pkt, top_level, conf);
		free(link);
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
		free(link);
		return -1;
	}
	closedir(directory);

	rtn_stat=0;
	if(nl)
	{
		if(process_files_in_directory(nl, count,
			&rtn_stat, &link, len, &link_len, conf,
			ff_pkt, our_device))
		{
			free(link);
			if(nl) free(nl);
			return -1;
		}
	}
	free(link);
	if(nl) free(nl);

	return rtn_stat;
}

static int found_other(FF_PKT *ff_pkt, struct conf *conf,
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
	return send_file(ff_pkt, top_level, conf);
}

/*
 * Find a single file.
 * p is the filename
 * parent_device is the device we are currently on
 * top_level is 1 when not recursing or 0 when
 *  descending into a directory.
 */
static int find_files(FF_PKT *ff_pkt, struct conf *conf,
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
		return send_file(ff_pkt, top_level, conf);
	}

	/*
	 * Handle hard linked files
	 * Maintain a list of hard linked files already backed up. This
	 *  allows us to ensure that the data of each file gets backed
	 *  up only once.
	 */
	if(ff_pkt->statp.st_nlink > 1
	  && (S_ISREG(ff_pkt->statp.st_mode)
		|| S_ISCHR(ff_pkt->statp.st_mode)
		|| S_ISBLK(ff_pkt->statp.st_mode)
		|| S_ISFIFO(ff_pkt->statp.st_mode)
		|| S_ISSOCK(ff_pkt->statp.st_mode)))
	{
		struct f_link *lp;
		const int linkhash_ind=LINKHASH(ff_pkt->statp);

		/* Search link list of hard linked files */
		for(lp=linkhash[linkhash_ind]; lp; lp=lp->next)
		{
			if(lp->ino==(ino_t)ff_pkt->statp.st_ino
			  && lp->dev==(dev_t)ff_pkt->statp.st_dev)
			{
				if(!strcmp(lp->name, fname)) return 0;
				ff_pkt->link=lp->name;
				/* Handle link, file already saved */
				ff_pkt->type=FT_LNK_H;
				return send_file(ff_pkt, top_level, conf);
			}
		}

		// File not previously dumped. Chain it into our list.
		if(!(lp=(struct f_link *)malloc(sizeof(struct f_link)))
		  || !(lp->name=strdup(fname)))
		{
			log_out_of_memory(__FUNCTION__);
			return -1;
		}
		lp->ino=ff_pkt->statp.st_ino;
		lp->dev=ff_pkt->statp.st_dev;
		lp->next=linkhash[linkhash_ind];
		linkhash[linkhash_ind]=lp;
	}

	/* This is not a link to a previously dumped file, so dump it.  */
	if(S_ISREG(ff_pkt->statp.st_mode))
		return found_regular_file(ff_pkt, conf, fname, top_level);
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
				return found_other(ff_pkt, conf, fname,
					top_level);
			}
		}
#endif
		return found_soft_link(ff_pkt, conf, fname, top_level);
	}
	else if(S_ISDIR(ff_pkt->statp.st_mode))
		return found_directory(ff_pkt, conf, fname,
			parent_device, top_level);
	else
		return found_other(ff_pkt, conf, fname, top_level);
}

int find_files_begin(FF_PKT *ff_pkt, struct conf *conf, char *fname)
{
	return find_files(ff_pkt, conf, fname, (dev_t)-1, 1 /* top_level */);
}
