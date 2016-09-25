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
	unsigned int flag;
	char *path;
	regex_t *re;
};

extern void strlists_free(struct strlist **bd, int count);
extern int strlist_add(struct strlist ***bdlist, int *count, char *path, unsigned int flag);
extern int strlist_sort(struct strlist **a, struct strlist **b);

#endif
