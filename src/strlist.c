#include "burp.h"
#include "conf.h"
#include "prog.h"
#include "find.h"
#include "log.h"

void strlists_free(struct strlist **bd, int count)
{
	int b=0;
	if(bd)
	{
		for(b=0; b<count; b++)
		{
			if(bd[b])
			{
				if(bd[b]->path) free(bd[b]->path);
				free(bd[b]);
			}
		}
		free(bd);
	}
}

int strlist_add(struct strlist ***bdlist, int *count, char *path, long flag)
{
	//int b=0;
	struct strlist *bdnew=NULL;
	struct strlist **bdtmp=NULL;
	if(!path)
	{
		logp("add_strlist called with NULL path!\n");
		return -1;
	}
	if(!(bdtmp=(struct strlist **)realloc(*bdlist,
		((*count)+1)*sizeof(struct strlist *))))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	*bdlist=bdtmp;
	if(!(bdnew=(struct strlist *)malloc(sizeof(struct strlist)))
	  || !(bdnew->path=strdup(path)))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	bdnew->flag=flag;
	(*bdlist)[(*count)++]=bdnew;

	//for(b=0; b<*count; b++)
	//	printf("now: %d %s\n", b, (*bdlist)[b]->path);
	return 0;
}

int strlist_sort(struct strlist **a, struct strlist **b)
{
	return pathcmp((*a)->path, (*b)->path);
}
