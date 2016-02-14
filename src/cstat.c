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

int cstat_init_with_cntr(struct cstat *cstat,
	const char *name, const char *clientconfdir)
{
	if(cstat_init(cstat, name, clientconfdir)
	  || !(cstat->cntr=cntr_alloc())
	  || cntr_init(cstat->cntr, name))
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
	cntr_free(&c->cntr);
	if(c->sdirs) logp("%s() called without freeing sdirs\n", __func__);
	c->clientdir_mtime=0;
	c->lockfile_mtime=0;
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
		case RUN_STATUS_CLIENT_CRASHED:
			return RUN_STATUS_STR_CLIENT_CRASHED;
		case RUN_STATUS_SERVER_CRASHED:
			return RUN_STATUS_STR_SERVER_CRASHED;
		case RUN_STATUS_RUNNING:
			return RUN_STATUS_STR_RUNNING;
		default: return "unknown";
	}
}

enum run_status run_str_to_status(const char *str)
{
	if(!strcmp(str, RUN_STATUS_STR_IDLE)) return RUN_STATUS_IDLE;
	else if(!strcmp(str, RUN_STATUS_STR_RUNNING)) return RUN_STATUS_RUNNING;
	else if(!strcmp(str, RUN_STATUS_STR_CLIENT_CRASHED))
		return RUN_STATUS_CLIENT_CRASHED;
	else if(!strcmp(str, RUN_STATUS_STR_SERVER_CRASHED))
		return RUN_STATUS_CLIENT_CRASHED;
	else if(!strcmp(str, RUN_STATUS_STR_RUNNING)) return RUN_STATUS_RUNNING;
	return RUN_STATUS_UNSET;
}

struct cstat *cstat_get_by_name(struct cstat *clist, const char *name)
{
	struct cstat *c;
        for(c=clist; c; c=c->next) if(!strcmp(c->name, name)) return c;
        return NULL;
}
