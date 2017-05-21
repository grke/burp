#include "burp.h"
#include "alloc.h"
#include "bu.h"
#include "cstat.h"
#include "log.h"
#include "prepend.h"
#include "strlist.h"

struct cstat *cstat_alloc(void)
{
	return (struct cstat *)calloc_w(1, sizeof(struct cstat), __func__);
}

int cstat_init(struct cstat *cstat,
	const char *name, const char *clientconfdir)
{
	if((clientconfdir && !(cstat->conffile=prepend_s(clientconfdir, name)))
	  || !(cstat->name=strdup_w(name, __func__)))
		return -1;
	return 0;
}

static void cstat_free_content(struct cstat *c)
{
	if(!c) return;
	bu_list_free(&c->bu);
	free_w(&c->name);
	free_w(&c->conffile);
	strlists_free(&c->labels);
	cntrs_free(&c->cntrs);
	if(c->sdirs) logp("%s() called without freeing sdirs\n", __func__);
	c->clientdir_mtime=0;
}

void cstat_add_cntr_to_list(struct cstat *c, struct cntr *cntr)
{
	cntr->next=c->cntrs;
	c->cntrs=cntr;
}

void cstat_remove_cntr_from_list(struct cstat *c, struct cntr *cntr)
{
	struct cntr *x;
	if(!c || !cntr)
		return;
	if(c->cntrs==cntr)
	{
		c->cntrs=cntr->next;
		return;
	}
	for(x=c->cntrs; x; x=x->next)
	{
		if(x->next==cntr)
		{
			x->next=cntr->next;
			return;
		}
	}
}

void cstat_free(struct cstat **cstat)
{
	if(!cstat || !*cstat) return;
	cstat_free_content(*cstat);
	free_v((void **)cstat);
}

void cstat_add_to_list(struct cstat **clist, struct cstat *cnew)
{
	struct cstat *c=NULL;
	struct cstat *clast=NULL;

	for(c=*clist; c; c=c->next)
	{
		if(strcmp(cnew->name, c->name)<0)
		{
			c->prev=cnew;
			break;
		}
		c->prev=clast;
		clast=c;
	}
	if(clast)
	{
		cnew->next=clast->next;
		clast->next=cnew;
		cnew->prev=clast;
	}
	else
	{
		*clist=cnew;
		cnew->next=c;
	}
}

void cstat_list_free(struct cstat **clist)
{
        struct cstat *c;
        struct cstat *next;
        struct cstat *prev=NULL;
        if(*clist) prev=(*clist)->prev;
        for(c=*clist; c; c=next)
        {
                next=c->next;
                cstat_free(&c);
        }
        // Do it in both directions.
        for(c=prev; c; c=prev)
        {
                prev=c->prev;
                cstat_free(&c);
        }
        *clist=NULL;
}

const char *run_status_to_str(struct cstat *cstat)
{
	switch(cstat->run_status)
	{
		case RUN_STATUS_IDLE:
			return RUN_STATUS_STR_IDLE;
		case RUN_STATUS_RUNNING:
			return RUN_STATUS_STR_RUNNING;
		default:
			return "unknown";
	}
}

enum run_status run_str_to_status(const char *str)
{
	if(!strcmp(str, RUN_STATUS_STR_IDLE))
		return RUN_STATUS_IDLE;
	else if(!strcmp(str, RUN_STATUS_STR_RUNNING))
		return RUN_STATUS_RUNNING;
	return RUN_STATUS_UNSET;
}

struct cstat *cstat_get_by_name(struct cstat *clist, const char *name)
{
	struct cstat *c;
        for(c=clist; c; c=c->next) if(!strcmp(c->name, name)) return c;
        return NULL;
}

int cstat_count(struct cstat *clist)
{
	int count=0;
	struct cstat *c;
        for(c=clist; c; c=c->next)
		count++;
	return count;
}
