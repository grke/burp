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
	char *fname;             /* full filename */
	char *link;              /* link if file linked */
	struct stat statp;       /* stat packet */
	int64_t winattr;         /* windows attributes */
	struct f_link *linked;   /* Set if this file is hard linked */
	int type;                /* FT_ type from above */
	int ff_errno;            /* errno */

	/* List of all hard linked files found */
	struct f_link **linkhash;
};

FF_PKT *init_find_files();
int term_find_files(FF_PKT *ff);
int find_files_begin(FF_PKT *ff_pkt, struct config *conf, char *fname, struct cntr *cntr);
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

/* from attribs.c */
void encode_stat(char *buf, struct stat *statp, int64_t winattr, int compression);
void decode_stat(const char *buf, struct stat *statp, int64_t *winattr, int *compression);
bool set_attributes(const char *path, char cmd, struct stat *statp, int64_t winattr, struct cntr *cntr);

#endif /* __FILES_H */
