#ifndef __FILES_H
#define __FILES_H

#include "bfile.h"
#include "conf.h"
#include "counter.h"

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

#include <sys/file.h>
#include <sys/param.h>
#if HAVE_UTIME_H
#include <utime.h>
#else
struct utimbuf {
    long actime;
    long modtime;
};
#endif

#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

#ifndef HAVE_READDIR_R
int readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result);
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

struct FF_PKT
{
	char *fname;             /* full filename */
	char *link;              /* link if file linked */
	struct stat statp;       /* stat packet */
	int64_t winattr;         /* windows attributes */
	struct f_link *linked;   /* Set if this file is hard linked */
	int type;                /* FT_ type from burpconfig.h */

	/* List of all hard linked files found */
	struct f_link **linkhash;

	struct ff_dir *ff_dir;
};

FF_PKT *find_files_init(void);
int find_files_free(FF_PKT *ff);
int find_file_next(FF_PKT *ff, struct config *conf, struct cntr *p1cntr, bool *top_level);

int pathcmp(const char *a, const char *b);
int file_is_included(struct strlist **ielist, int iecount,
	struct strlist **incext, int incount,
	struct strlist **excext, int excount,
	struct strlist **increg, int ircount,
	struct strlist **excreg, int ercount,
	const char *fname, bool top_level);
int in_include_regex(struct strlist **incre, int incount, const char *fname);
int in_exclude_regex(struct strlist **excre, int excount, const char *fname);
// Returns the level of compression.
int in_exclude_comp(struct strlist **excom, int excmcount, const char *fname, int compression);

#endif /* __FILES_H */
