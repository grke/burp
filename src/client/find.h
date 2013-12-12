#ifndef _FIND_H
#define _FIND_H

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

#include <sys/file.h>
#include <sys/param.h>
#if HAVE_UTIME_H
#include <utime.h>
#else
struct utimbuf
{
	long actime;
	long modtime;
};
#endif

#define MODE_RALL (S_IRUSR|S_IRGRP|S_IROTH)

#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

#ifndef HAVE_READDIR_R
int readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result);
#endif

/*
 * Definition of the find_files packet passed as the
 * first argument to the find_files callback subroutine.
 */
struct FF_PKT
{
	char *top_fname;	/* full filename before descending */
	char *fname;		/* full filename */
	long flen;		/* length of name component */
	char *link;		/* link if file linked */
	struct stat statp;	/* stat packet */
	uint64_t winattr;	/* windows attributes */
	int type;		/* FT_ type from above */
};

extern FF_PKT *find_files_init(void);
extern void find_files_free(FF_PKT *ff);
extern int find_files_begin(FF_PKT *ff_pkt, struct config *conf, char *fname);
extern int file_is_included(struct strlist **ielist, int iecount,
	struct strlist **incext, int incount,
	struct strlist **excext, int excount,
	struct strlist **increg, int ircount,
	struct strlist **excreg, int ercount,
	const char *fname, bool top_level);
extern int in_include_regex(struct strlist **incre, int incount,
	const char *fname);
extern int in_exclude_regex(struct strlist **excre, int excount,
	const char *fname);
// Returns the level of compression.
extern int in_exclude_comp(struct strlist **excom, int excmcount,
	const char *fname, int compression);

#endif
