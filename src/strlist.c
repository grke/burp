#include "include.h"

// Maybe rename this stuff to 'struct pathlist'.

static void strlist_free(struct strlist *strlist)
{
	if(!strlist) return;
	if(strlist->path) free(strlist->path);
	if(strlist->re) regfree(strlist->re);
	free(strlist);
}

void strlists_free(struct strlist **strlist)
{
	struct strlist *s;
	struct strlist *shead=*strlist;
	while(shead)
	{
		s=shead;
		shead=shead->next;
		strlist_free(s);
	}
	*strlist=NULL;
}

static struct strlist *strlist_alloc(char *path, long flag)
{
	struct strlist *slnew=NULL;
	if(!path)
	{
		logp("%s called with NULL path!\n", __FUNCTION__);
		return NULL;
	}
	if(!(slnew=(struct strlist *)calloc(1, sizeof(struct strlist)))
	  || !(slnew->path=strdup(path)))
	{
		log_out_of_memory(__FUNCTION__);
		return NULL;
	}
	slnew->flag=flag;
	return slnew;
}

static int do_strlist_add(struct strlist **strlist,
	char *path, long flag, int sorted)
{
	struct strlist *s=NULL;
	struct strlist *slast=NULL;
	struct strlist *slnew=NULL;

	if(!(slnew=strlist_alloc(path, flag))) return -1;

	// Insert into a sorted position in the list, or if the sorted flag
	// was zero, add to the end of the list.
	// FIX THIS: Unsorted means that it goes through the whole list to
	// find the last entry. Can this be made better?
	for(s=*strlist; s; s=s->next)
	{
		if(sorted && pathcmp(path, s->path)<0) break;
		slast=s;
	}
	if(slast)
	{
		slnew->next=slast->next;
		slast->next=slnew;
	}
	else
	{
		*strlist=slnew;
		slnew->next=s;
	}

	return 0;
}

int strlist_add(struct strlist **strlist, char *path, long flag)
{
	return do_strlist_add(strlist, path, flag, 0 /* unsorted */);
}

int strlist_add_sorted(struct strlist **strlist, char *path, long flag)
{
	return do_strlist_add(strlist, path, flag, 1 /* sorted */);
}

int strlist_compile_regexes(struct strlist *strlist)
{
        struct strlist *l;
        for(l=strlist; l; l=l->next) compile_regex(&l->re, l->path);
	return 0;
}
