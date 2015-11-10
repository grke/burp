#include "../../burp.h"
#include "../../alloc.h"
#include "../../log.h"
#include "lline.h"

static void lline_free_content(struct lline *lline)
{
	free_w(&lline->line);
}

static void lline_free(struct lline **lline)
{
	if(!lline || !*lline) return;
	lline_free_content(*lline);
	free_v((void **)lline);
}

void llines_free(struct lline **lline)
{
	struct lline *l;
	struct lline *lhead=*lline;
	while(lhead)
	{
		l=lhead;
		lhead=lhead->next;
		lline_free(&l);
	}
	*lline=NULL;
}

static struct lline *lline_alloc(char *line)
{
	struct lline *llnew=NULL;
	if(!line)
	{
		logp("%s called with NULL line!\n", __func__);
		return NULL;
	}
	if(!(llnew=(struct lline *)
		calloc_w(1, sizeof(struct lline), __func__))
	  || !(llnew->line=strdup_w(line, __func__)))
		return NULL;
	return llnew;
}

int lline_add(struct lline **lline, char *line)
{
	struct lline *l=NULL;
	struct lline *llast=NULL;
	struct lline *llnew=NULL;

	if(!(llnew=lline_alloc(line))) return -1;

	for(l=*lline; l; l=l->next)
	{
		l->prev=llast;
		llast=l;
	}
	if(llast)
	{
		llnew->next=llast->next;
		llast->next=llnew;
		llnew->prev=llast;
	}
	else
	{
		*lline=llnew;
		llnew->next=l;
	}

	return 0;
}
