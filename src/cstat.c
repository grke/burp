#include "include.h"

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
	free_w(&c->running_detail);
	if(c->sdirs) logp("%s() called without freeing sdirs\n");
	c->clientdir_mtime=0;
	c->lockfile_mtime=0;
}

void cstat_free(struct cstat **cstat)
{
	if(!cstat || !*cstat) return;
	cstat_free_content(*cstat);
	free_v((void **)cstat);
}

int cstat_add_to_list(struct cstat **clist, struct cstat *cnew)
{
	struct cstat *c=NULL;
	struct cstat *clast=NULL;

	for(c=*clist; c; c=c->next)
	{
		if(strcmp(cnew->name, c->name)<0) break;
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

	return 0;
}

const char *cstat_status_to_str(struct cstat *cstat)
{
	switch(cstat->status)
	{
		case STATUS_IDLE: return STATUS_STR_IDLE;
		case STATUS_CLIENT_CRASHED: return STATUS_STR_CLIENT_CRASHED;
		case STATUS_SERVER_CRASHED: return STATUS_STR_SERVER_CRASHED;
		case STATUS_RUNNING: return STATUS_STR_RUNNING;
		case STATUS_SCANNING: return STATUS_STR_SCANNING;
		case STATUS_BACKUP: return STATUS_STR_BACKUP;
		case STATUS_MERGING: return STATUS_STR_MERGING;
		case STATUS_SHUFFLING: return STATUS_STR_SHUFFLING;
		case STATUS_LISTING: return STATUS_STR_LISTING;
		case STATUS_RESTORING: return STATUS_STR_RESTORING;
		case STATUS_VERIFYING: return STATUS_STR_VERIFYING;
		case STATUS_DELETING: return STATUS_STR_DELETING;
		default: return "unknown";
	}
}

enum cstat_status cstat_str_to_status(const char *str)
{
	if(!strcmp(str, STATUS_STR_IDLE)) return STATUS_IDLE;
	else if(!strcmp(str, STATUS_STR_RUNNING)) return STATUS_RUNNING;
	else if(!strcmp(str, STATUS_STR_CLIENT_CRASHED))
		return STATUS_CLIENT_CRASHED;
	else if(!strcmp(str, STATUS_STR_SERVER_CRASHED))
		return STATUS_CLIENT_CRASHED;
	else if(!strcmp(str, STATUS_STR_RUNNING)) return STATUS_RUNNING;
	else if(!strcmp(str, STATUS_STR_SCANNING)) return STATUS_SCANNING;
	else if(!strcmp(str, STATUS_STR_BACKUP)) return STATUS_BACKUP;
	else if(!strcmp(str, STATUS_STR_MERGING)) return STATUS_MERGING;
	else if(!strcmp(str, STATUS_STR_SHUFFLING)) return STATUS_SHUFFLING;
	else if(!strcmp(str, STATUS_STR_LISTING)) return STATUS_LISTING;
	else if(!strcmp(str, STATUS_STR_RESTORING)) return STATUS_RESTORING;
	else if(!strcmp(str, STATUS_STR_VERIFYING)) return STATUS_VERIFYING;
	else if(!strcmp(str, STATUS_STR_DELETING)) return STATUS_DELETING;
	return STATUS_UNSET;
}

struct cstat *cstat_get_by_name(struct cstat *clist, const char *name)
{
	struct cstat *c;
        for(c=clist; c; c=c->next) if(!strcmp(c->name, name)) return c;
        return NULL;
}
