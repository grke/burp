#ifndef _STRLIST_H
#define _STRLIST_H

#if defined(HAVE_PCREPOSIX)
#include <pcreposix.h>
#else
#include <regex.h>
#endif

typedef struct strlist strlist_t;

struct strlist
{
	long flag;
	char *path;
	regex_t *re;
	strlist_t *next;
};

extern void strlists_free(struct strlist **strlist);
extern int strlist_add(struct strlist **strlist,
	const char *path, long flag);
extern int strlist_add_sorted(struct strlist **strlist,
	const char *path, long flag);
extern int strlist_add_sorted_uniq(struct strlist **strlist,
	const char *path, long flag);
extern int strlist_compile_regexes(struct strlist *strlist);
extern int strlist_find(struct strlist *strlist, const char *path, long flag);

#endif
