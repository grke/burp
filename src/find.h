#ifndef __FIND_H
#define __FIND_H

#include "conf.h"
#include "counter.h"

#if HAVE_UTIME_H
#include <utime.h>
#else
struct utimbuf {
    long actime;
    long modtime;
};
#endif

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

struct ff_pkt
{
	char *fname;             /* full filename */
	char *link;              /* link if file linked */
	struct stat statp;       /* stat packet */
	int64_t winattr;         /* windows attributes */
	int ftype;                /* FT_ type from burpconfig.h */

	/* List of all hard linked files found */
	struct f_link **linkhash;

	struct ff_dir *ff_dir;
};

extern ff_pkt *find_files_init(void);
extern int find_file_next(ff_pkt *ff, struct config *conf, struct cntr *p1cntr, bool *top_level);
extern void find_files_free(ff_pkt *ff);

extern int pathcmp(const char *a, const char *b);
extern int file_is_included(struct strlist **ielist, int iecount,
	struct strlist **incext, int incount,
	struct strlist **excext, int excount,
	struct strlist **increg, int ircount,
	struct strlist **excreg, int ercount,
	const char *fname, bool top_level);

// Returns the level of compression.
extern int in_exclude_comp(struct strlist **excom, int excmcount, const char *fname, int compression);

#ifndef HAVE_READDIR_R
int readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result);
#endif

#endif /* __FIND_H */
