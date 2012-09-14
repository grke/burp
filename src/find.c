#include "burp.h"
#include "prog.h"
#include "find.h"
#include "log.h"
#include "asyncio.h"
#include "handy.h"
#include "regexp.h"
#include "backup_phase1_client.h"
#ifdef HAVE_DARWIN_OS
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/attr.h>
#endif
#ifdef HAVE_LINUX_OS
#include <sys/statfs.h>
#endif

extern int32_t name_max;              /* filename max length */
extern int32_t path_max;              /* path name max length */

int32_t name_max;              /* filename max length */
int32_t path_max;              /* path name max length */

static const int fnmode = 0;

/*
 * Initialize the find files "global" variables
 */
FF_PKT *init_find_files()
{
  FF_PKT *ff;

  ff = (FF_PKT *)malloc(sizeof(FF_PKT));
  memset(ff, 0, sizeof(FF_PKT));

   /* Get system path and filename maximum lengths */
   path_max = pathconf(".", _PC_PATH_MAX);
   if (path_max < 1024) {
      path_max = 1024;
   }

   name_max = pathconf(".", _PC_NAME_MAX);
   if (name_max < 1024) {
      name_max = 1024;
   }
   path_max++;                        /* add for EOS */
   name_max++;                        /* add for EOS */

  return ff;
}

/*
 * Structure for keeping track of hard linked files, we
 *   keep an entry for each hardlinked file that we save,
 *   which is the first one found. For all the other files that
 *   are linked to this one, we save only the directory
 *   entry so we can link it.
 */
struct f_link {
    struct f_link *next;
    dev_t dev;                        /* device */
    ino_t ino;                        /* inode with device is unique */
    uint32_t FileIndex;               /* FileIndex of this file */
    char name[1];                     /* The name */
};

typedef struct f_link link_t;
#define LINK_HASHTABLE_BITS 16
#define LINK_HASHTABLE_SIZE (1<<LINK_HASHTABLE_BITS)
#define LINK_HASHTABLE_MASK (LINK_HASHTABLE_SIZE-1)

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
   struct f_link *lp, *lc;
   int count = 0;
   int i;

   
   if (ff->linkhash == NULL) return 0;

   for (i =0 ; i < LINK_HASHTABLE_SIZE; i ++) {
   /* Free up list of hard linked files */
       lp = ff->linkhash[i];
       while (lp) {
      lc = lp;
      lp = lp->next;
      if (lc) {
         free(lc);
         count++;
      }
   }
       ff->linkhash[i] = NULL;
   }
   free(ff->linkhash);
   ff->linkhash = NULL;
   return count;
}

/*
 * Terminate find_files() and release
 * all allocated memory
 */
int
term_find_files(FF_PKT *ff)
{
   int hard_links;

   hard_links = term_find_one(ff);
   free(ff);
   return hard_links;
}

/*
 * Create a new directory Find File packet, but copy
 *   some of the essential info from the current packet.
 *   However, be careful to zero out the rest of the 
 *   packet.
 */
static FF_PKT *new_dir_ff_pkt(FF_PKT *ff_pkt)
{
   FF_PKT *dir_ff_pkt = NULL;
   if(!(dir_ff_pkt=(FF_PKT *)malloc(sizeof(FF_PKT))))
   {
	logp("out of memory\n");
	return NULL;
   }
   memcpy(dir_ff_pkt, ff_pkt, sizeof(FF_PKT));
   dir_ff_pkt->fname = strdup(ff_pkt->fname);
   dir_ff_pkt->link = strdup(ff_pkt->link);
   dir_ff_pkt->linkhash = NULL;
   return dir_ff_pkt;
}

/*
 * Free the temp directory ff_pkt
 */
static void free_dir_ff_pkt(FF_PKT *dir_ff_pkt)
{
   free(dir_ff_pkt->fname);
   free(dir_ff_pkt->link);
   free(dir_ff_pkt);
}

/*
 * check for BSD nodump flag
 */
static bool no_dump(FF_PKT *ff_pkt)
{
#if defined(HAVE_CHFLAGS) && defined(UF_NODUMP)
   if ( (ff_pkt->flags & FO_HONOR_NODUMP) &&
        (ff_pkt->statp.st_flags & UF_NODUMP) ) {
      fprintf(stderr, _("     NODUMP flag set - will not process %s\n"),
           ff_pkt->fname);
      return true;                    /* do not backup this file */
   }
#endif
   return false;                      /* do backup */
}

static int myalphasort (const struct dirent **a, const struct dirent **b)
{
	return pathcmp ((*a)->d_name, (*b)->d_name);
}

/* Return 1 to include the file, 0 to exclude it. */
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
	// If not doing compression, or there are no excludes, return 0
	// straight away.
	if(!compression || !excmcount) return 0;

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

/* Return 1 to include the file, 0 to exclude it. */
/* Currently not used - it needs more thinking about. */
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

static int found_regular_file(FF_PKT *ff_pkt, struct config *conf,
	struct cntr *cntr, char *fname, bool top_level,
	struct utimbuf *restore_times)
{
	int rtn_stat;
	boffset_t sizeleft;

	sizeleft=ff_pkt->statp.st_size;

	// If the user specified a minimum or maximum file size, obey it.
	if(conf->min_file_size && sizeleft<(boffset_t)conf->min_file_size)
		return 0;
	if(conf->max_file_size && sizeleft>(boffset_t)conf->max_file_size)
		return 0;

	/* Don't bother opening empty, world readable files.  Also do not open
	files when archive is meant for /dev/null.  */
	if(!sizeleft && MODE_RALL==(MODE_RALL & ff_pkt->statp.st_mode))
		ff_pkt->type=FT_REGE;
	else
		ff_pkt->type=FT_REG;
	rtn_stat=send_file(ff_pkt, top_level, conf, cntr);
	if(ff_pkt->linked) ff_pkt->linked->FileIndex=ff_pkt->FileIndex;
	return rtn_stat;
}

static int found_soft_link(FF_PKT *ff_pkt, struct config *conf,
	struct cntr *cntr, char *fname, bool top_level)
{
	int size;
	int rtn_stat;
	char *buffer=(char *)alloca(path_max+name_max+102);

	if((size=readlink(fname, buffer, path_max+name_max+101))<0)
	{
		/* Could not follow link */
		ff_pkt->type=FT_NOFOLLOW;
		ff_pkt->ff_errno=errno;
		rtn_stat=send_file(ff_pkt, top_level, conf, cntr);
		if(ff_pkt->linked)
			ff_pkt->linked->FileIndex=ff_pkt->FileIndex;
		return rtn_stat;
	}
	buffer[size]=0;
	ff_pkt->link=buffer;	/* point to link */
	ff_pkt->type=FT_LNK;	/* got a real link */
	rtn_stat = send_file(ff_pkt, top_level, conf, cntr);
	if(ff_pkt->linked) ff_pkt->linked->FileIndex=ff_pkt->FileIndex;
	return rtn_stat;
}

static int backup_dir_and_return(FF_PKT *ff_pkt, struct config *conf, struct cntr *cntr, const char *fname, bool top_level, FF_PKT *dir_ff_pkt, struct utimbuf *restore_times)
{
	int rtn_stat=send_file(ff_pkt, top_level, conf, cntr);
	if(ff_pkt->linked)
		ff_pkt->linked->FileIndex=ff_pkt->FileIndex;
	free_dir_ff_pkt(dir_ff_pkt);
	/* reset "link" */
	ff_pkt->link=ff_pkt->fname;
	return rtn_stat;
}

int fstype_excluded(struct config *conf, const char *fname, struct cntr *cntr)
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
			logp("out of memory\n");
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
				logp("out of memory\n");
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
static int
find_files(FF_PKT *ff_pkt, struct config *conf, struct cntr *cntr,
  char *fname, dev_t parent_device, bool top_level);

static int process_files_in_directory(struct dirent **nl, int count, int *rtn_stat, char *link, size_t len, size_t link_len, struct config *conf, struct cntr *cntr, FF_PKT *ff_pkt, dev_t our_device)
{
	int m=0;
	for(m=0; m<count; m++)
	{
		size_t i;
		char *p=NULL;
		char *q=NULL;

		p=nl[m]->d_name;

		if(strlen(p)+len>=link_len)
		{
			link_len=len+strlen(p)+1;
			if(!(link=(char *)realloc(link, link_len+1)))
			{
				logp("out of memory\n");
				return -1;
			}
		}
		q=link+len;
		for(i=0; i<strlen(nl[m]->d_name); i++) *q++=*p++;
		*q=0;

		if(file_is_included_no_incext(conf->incexcdir, conf->iecount,
			conf->excext, conf->excount,
			conf->excreg, conf->ercount,
			link))
		{
			*rtn_stat=find_files(ff_pkt,
				conf, cntr, link, our_device, false);
			if(ff_pkt->linked)
				ff_pkt->linked->FileIndex = ff_pkt->FileIndex;
		}
		else
		{ 
			// Excluded, but there might be a subdirectory that is
			// included.
			int ex=0;
			for(ex=0; ex<conf->iecount; ex++)
			{
				if(conf->incexcdir[ex]->flag
				  && is_subdir(link, conf->incexcdir[ex]->path))
				{
					int ey;
					if((*rtn_stat=find_files(ff_pkt, conf,
						cntr, conf->incexcdir[ex]->path,
						 our_device, false)))
							break;
					// Now need to skip subdirectories of
					// the thing that we just stuck in
					// find_one_file(), or we might get
					// some things backed up twice.
					for(ey=ex+1; ey<conf->iecount; ey++)
					  if(is_subdir(
						conf->incexcdir[ex]->path,
						conf->incexcdir[ey]->path))
							ex++;
				}
			}
		}
		free(nl[m]);
		if(*rtn_stat) break;
	}
	return 0;
}

static int found_directory(FF_PKT *ff_pkt, struct config *conf,
	struct cntr *cntr, char *fname, dev_t parent_device, bool top_level,
	struct utimbuf *restore_times)
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
	bool volhas_attrlist;
	struct dirent **nl=NULL;

	recurse=true;
	our_device=ff_pkt->statp.st_dev;
	/* Remember volhas_attrlist if we recurse */
	volhas_attrlist=ff_pkt->volhas_attrlist;

	/*
	* Ignore this directory and everything below if one of the files defined
	* by the 'nobackup' option exists.
	*/
	if((nbret=nobackup_directory(conf, ff_pkt->fname)))
	{
		if(nbret<0) return -1; // error
		return 0; // do not back it up.
	}

	/* Build a canonical directory name with a trailing slash in link var */
	len=strlen(fname);
	link_len=len+200;
	if(!(link=(char *)malloc(link_len+2)))
	{
		logp("out of memory\n");
		return -1;
	}
	snprintf(link, link_len, "%s", fname);

	/* Strip all trailing slashes */
	while(len >= 1 && IsPathSeparator(link[len - 1])) len--;
	/* add back one */
	link[len++]='/';
	link[len]=0;

	ff_pkt->link=link;
	ff_pkt->type=FT_DIRBEGIN;

#if defined(HAVE_WIN32)
	windows_reparse_point_fiddling(ff_pkt);
#endif

	rtn_stat=send_file(ff_pkt, top_level, conf, cntr);
	if(rtn_stat || ff_pkt->type==FT_REPARSE || ff_pkt->type==FT_JUNCTION)
	{
		 /* ignore or error status */
		free(link);
		return rtn_stat;
	}

	/* Done with DIRBEGIN, next call will be DIREND */
	/* Graham says: burp does not use DIREND, so this can be simplified. */
	if(ff_pkt->type==FT_DIRBEGIN) ff_pkt->type=FT_DIREND;

	/*
	* Create a temporary ff packet for this directory
	*   entry, and defer handling the directory until
	*   we have recursed into it.  This saves the
	*   directory after all files have been processed, and
	*   during the restore, the directory permissions will
	*   be reset after all the files have been restored.
	*/
	/* Graham says: what the fuck? Variables declared in the middle of
	   the function? */ 
	FF_PKT *dir_ff_pkt;
	if(!(dir_ff_pkt=new_dir_ff_pkt(ff_pkt))) return -1;

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
		if(fstype_excluded(conf, ff_pkt->fname, cntr))
		{
			free(link);
			return backup_dir_and_return(ff_pkt, conf, cntr,
				fname, top_level, dir_ff_pkt, restore_times);
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
		return backup_dir_and_return(ff_pkt, conf, cntr,
			fname, top_level, dir_ff_pkt, restore_times);
	}

	/* reset "link" */
	ff_pkt->link=ff_pkt->fname;

	/*
	* Descend into or "recurse" into the directory to read
	*   all the files in it.
	*/
	errno = 0;
	if(!(directory=opendir(fname)))
	{
		ff_pkt->type=FT_NOOPEN;
		ff_pkt->ff_errno=errno;
		rtn_stat=send_file(ff_pkt, top_level, conf, cntr);
		if(ff_pkt->linked)
			ff_pkt->linked->FileIndex=ff_pkt->FileIndex;
		free(link);
		free_dir_ff_pkt(dir_ff_pkt);
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
			&rtn_stat, link, len, link_len, conf, cntr,
			ff_pkt, our_device))
		{
			free(link);
			if(nl) free(nl);
			return -1;
		}
	}
	free(link);
	if(nl) free(nl);

	/*
	* Now that we have recursed through all the files in the
	*  directory, we "save" the directory so that after all
	*  the files are restored, this entry will serve to reset
	*  the directory modes and dates.  Temp directory values
	*  were used without this record.
	*/
		/* handle directory entry */
	if(!rtn_stat)
		send_file(dir_ff_pkt, top_level, conf, cntr);
	if(ff_pkt->linked)
		ff_pkt->linked->FileIndex = dir_ff_pkt->FileIndex;
	free_dir_ff_pkt(dir_ff_pkt);

	/* Restore value in case it changed. */
	ff_pkt->volhas_attrlist=volhas_attrlist;
	return rtn_stat;
}

static int found_other(FF_PKT *ff_pkt, struct config *conf,
	struct cntr *cntr, char *fname, bool top_level)
{
	int rtn_stat;
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
	rtn_stat=send_file(ff_pkt, top_level, conf, cntr);
	if(ff_pkt->linked) ff_pkt->linked->FileIndex = ff_pkt->FileIndex;
	return rtn_stat;
}

/*
 * Find a single file.
 * p is the filename
 * parent_device is the device we are currently on
 * top_level is 1 when not recursing or 0 when
 *  descending into a directory.
 */
static int
find_files(FF_PKT *ff_pkt, struct config *conf, struct cntr *cntr,
  char *fname, dev_t parent_device, bool top_level)
{
	int len;
	int rtn_stat;
	struct utimbuf restore_times;

	ff_pkt->fname=ff_pkt->link=fname;

#ifdef HAVE_WIN32
	if(win32_lstat(fname, &ff_pkt->statp, &ff_pkt->winattr))
#else
	if(lstat(fname, &ff_pkt->statp))
#endif
	{
		ff_pkt->type=FT_NOSTAT;
		ff_pkt->ff_errno=errno;
		return send_file(ff_pkt, top_level, conf, cntr);
	}

	/* Save current times of this directory in case we need to
	 * reset them because the user doesn't want them changed.
	 */
	restore_times.actime=ff_pkt->statp.st_atime;
	restore_times.modtime=ff_pkt->statp.st_mtime;

	if(no_dump(ff_pkt)) return 0;

#ifdef HAVE_DARWIN_OS
	if(ff_pkt->flags & FO_HFSPLUS
		&& ff_pkt->volhas_attrlist
		&& S_ISREG(ff_pkt->statp.st_mode))
	{
		/* TODO: initialise attrList once elsewhere? */
		struct attrlist attrList;
		memset(&attrList, 0, sizeof(attrList));
		attrList.bitmapcount = ATTR_BIT_MAP_COUNT;
		attrList.commonattr = ATTR_CMN_FNDRINFO;
		attrList.fileattr = ATTR_FILE_RSRCLENGTH;
		if(getattrlist(fname, &attrList, &ff_pkt->hfsinfo,
			sizeof(ff_pkt->hfsinfo), FSOPT_NOFOLLOW))
		{
			ff_pkt->type=FT_NOSTAT;
			ff_pkt->ff_errno=errno;
			return send_file(ff_pkt, top_level, conf, cntr);
		}
	}
#endif

	ff_pkt->LinkFI=0;
	/*
	* Handle hard linked files
	*
	* Maintain a list of hard linked files already backed up. This
	*  allows us to ensure that the data of each file gets backed
	*  up only once.
	*/
	if (!(ff_pkt->flags & FO_NO_HARDLINK)
	  && ff_pkt->statp.st_nlink > 1
	  && (S_ISREG(ff_pkt->statp.st_mode)
		|| S_ISCHR(ff_pkt->statp.st_mode)
		|| S_ISBLK(ff_pkt->statp.st_mode)
		|| S_ISFIFO(ff_pkt->statp.st_mode)
		|| S_ISSOCK(ff_pkt->statp.st_mode)))
	{

		struct f_link *lp;
		if(!(ff_pkt->linkhash))
		{
			if(!(ff_pkt->linkhash=(link_t **)malloc(
				LINK_HASHTABLE_SIZE*sizeof(link_t *))))
			{
				logp("out of memory doing link hash\n");
				return -1;
			}
			memset(ff_pkt->linkhash, 0,
				LINK_HASHTABLE_SIZE*sizeof(link_t *));
		}
		const int linkhash=LINKHASH(ff_pkt->statp);

		/* Search link list of hard linked files */
		for(lp=ff_pkt->linkhash[linkhash]; lp; lp=lp->next)
		{
		  if(lp->ino==(ino_t)ff_pkt->statp.st_ino
			&& lp->dev==(dev_t)ff_pkt->statp.st_dev)
		  {
			/* If we have already backed up the hard linked file
				don't do it again */
			if(!strcmp(lp->name, fname)) return 0;
			ff_pkt->link=lp->name;
			/* Handle link, file already saved */
			ff_pkt->type=FT_LNKSAVED;
			ff_pkt->LinkFI=lp->FileIndex;
			ff_pkt->linked=0;
			rtn_stat=send_file(ff_pkt, top_level, conf, cntr);
			return rtn_stat;
		  }
		}

		/* File not previously dumped. Chain it into our list. */
		len=strlen(fname)+1;
		if(!(lp=(struct f_link *)malloc(sizeof(struct f_link)+len)))
		{
			logp("out of memory\n");
			return -1;
		}
		lp->ino=ff_pkt->statp.st_ino;
		lp->dev=ff_pkt->statp.st_dev;
		/* set later */
		lp->FileIndex=0;
		snprintf(lp->name, len, "%s", fname);
		lp->next=ff_pkt->linkhash[linkhash];
		ff_pkt->linkhash[linkhash]=lp;
		/* mark saved link */
		ff_pkt->linked=lp;
	}
	else
	{
		ff_pkt->linked=NULL;
	}

	/* This is not a link to a previously dumped file, so dump it.  */
	if(S_ISREG(ff_pkt->statp.st_mode))
		return found_regular_file(ff_pkt, conf, cntr, fname,
			top_level, &restore_times);
	else if(S_ISLNK(ff_pkt->statp.st_mode))
		return found_soft_link(ff_pkt, conf, cntr, fname, top_level);
	else if(S_ISDIR(ff_pkt->statp.st_mode))
		return found_directory(ff_pkt, conf, cntr, fname,
			parent_device, top_level, &restore_times);
	else
		return found_other(ff_pkt, conf, cntr, fname, top_level);
}

int find_files_begin(FF_PKT *ff_pkt, struct config *conf, char *fname, struct cntr *cntr)
{
	return find_files(ff_pkt, conf, cntr, fname, (dev_t)-1,
		1 /* top_level */);
}
