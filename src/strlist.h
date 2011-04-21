#ifndef _STRLIST_H
#define _STRLIST_H

typedef struct strlist strlist_t;

struct strlist
{
	int flag;
	char *path;
};

extern void strlists_free(struct strlist **bd, int count);
extern int strlist_add(struct strlist ***bdlist, int *count, char *path, int flag);
extern int strlist_sort(struct strlist **a, struct strlist **b);

#endif
