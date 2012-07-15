#ifndef _STRLIST_H
#define _STRLIST_H

#include <regex.h>

typedef struct strlist strlist_t;

struct strlist
{
	long flag;
	char *path;
        regex_t *re;
};

extern void strlists_free(struct strlist **bd, int count);
extern int strlist_add(struct strlist ***bdlist, int *count, char *path, long flag);
extern int strlist_sort(struct strlist **a, struct strlist **b);

#endif
