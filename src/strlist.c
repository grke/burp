#include "burp.h"
#include "alloc.h"
#include "log.h"
#include "pathcmp.h"
#include "regexp.h"
#include "strlist.h"

// Maybe rename this stuff to 'struct pathlist'.

static void strlist_free(struct strlist *strlist)
{
	if(!strlist) return;
	regex_free(&strlist->re);
	free_w(&strlist->path);
	free_v((void **)&strlist);
}

void strlists_free(struct strlist **strlist)
{
	struct strlist *s;
	struct strlist *shead;
	if(!strlist) return;
	shead=*strlist;
	while(shead)
	{
		s=shead;
		shead=shead->next;
		strlist_free(s);
	}
	*strlist=NULL;
}

static struct strlist *strlist_alloc(const char *path, long flag)
{
	struct strlist *slnew=NULL;
	if(!path)
	{
		logp("%s called with NULL path!\n", __func__);
		return NULL;
	}
	if(!(slnew=(struct strlist *)
		calloc_w(1, sizeof(struct strlist), __func__))
	  || !(slnew->path=strdup_w(path, __func__)))
		return NULL;
	slnew->flag=flag;
	return slnew;
}

static int do_strlist_add(struct strlist **strlist,
	const char *path, long flag, int sorted, int uniq)
{
	int p=0;
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
		if(uniq && !pathcmp(path, s->path) && flag==s->flag)
		{
			strlist_free(slnew);
			return 0;
		}
		if(sorted) {
			if((p=pathcmp(path, s->path))<0)
				break;
			if(!p && flag<s->flag)
				break;
		}
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

int strlist_add(struct strlist **strlist,
	const char *path, long flag)
{
	return do_strlist_add(strlist, path, flag, 0 /* unsorted */, 0 /* not uniq */);
}

int strlist_add_sorted(struct strlist **strlist,
	const char *path, long flag)
{
	return do_strlist_add(strlist, path, flag, 1 /* sorted */, 0 /* not uniq */);
}

int strlist_add_sorted_uniq(struct strlist **strlist,
	const char *path, long flag)
{
	return do_strlist_add(strlist, path, flag, 1 /* sorted */, 1 /* uniq */);
}

int strlist_compile_regexes(struct strlist *strlist)
{
        struct strlist *l;
	// FIX THIS: when the regex does not compile, should remove the
	// strlist entry completely.
        for(l=strlist; l; l=l->next)
		if(!(l->re=regex_compile_backup(l->path)))
			logp("unable to compile regex: %s\n", l->path);
	return 0;
}

int strlist_find(struct strlist *strlist, const char *path, long flag)
{
	struct strlist *s;
	for(s=strlist; s; s=s->next)
		if(!strcmp(path, s->path) && flag==s->flag)
			return 1;
	return 0;
}
