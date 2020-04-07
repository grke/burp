#include "burp.h"
#include "alloc.h"
#include "bu.h"
#include "prepend.h"
// balh

struct bu *bu_alloc(void)
{
	return (struct bu *)calloc_w(1, sizeof(struct bu), __func__);
}

int bu_init(struct bu *bu, char *fullpath, char *basename,
	char *timestampstr, uint16_t flags)
{
	if(!(bu->data=prepend_s(fullpath, "data"))
	  || !(bu->delta=prepend_s(fullpath, "deltas.reverse")))
		goto error;
	bu->path=fullpath;
	bu->basename=basename;
	bu->timestamp=timestampstr;
	bu->flags=flags;
	bu->bno=strtoul(timestampstr, NULL, 10);
	return 0;
error:
	free_w(&bu->data);
	free_w(&bu->delta);
	return -1;
}

static void bu_free_content(struct bu *bu)
{
	if(!bu) return;
	free_w(&bu->path);
	free_w(&bu->basename);
	free_w(&bu->data);
	free_w(&bu->delta);
	free_w(&bu->timestamp);
}

void bu_free(struct bu **bu)
{
	if(!bu || !*bu) return;
	bu_free_content(*bu);
	free_v((void **)bu);
}

void bu_list_free(struct bu **bu_list)
{
	struct bu *bu;
	struct bu *next;
	struct bu *prev=NULL;
	if(*bu_list) prev=(*bu_list)->prev;
	for(bu=*bu_list; bu; bu=next)
	{
		next=bu->next;
		bu_free(&bu);
	}
	// Do it in both directions.
	for(bu=prev; bu; bu=prev)
	{
		prev=bu->prev;
		bu_free(&bu);
	}
	*bu_list=NULL;
}

static struct bu *bu_find(struct bu *bu, uint16_t flag)
{
	struct bu *cbu=NULL;
	if(!bu) return NULL;
	if(bu->flags & flag) return bu;
	// Search in both directions.
	if(bu->next)
		for(cbu=bu; cbu; cbu=cbu->next)
			if(cbu->flags & flag) return cbu;
	if(bu->prev)
		for(cbu=bu; cbu; cbu=cbu->prev)
			if(cbu->flags & flag) return cbu;
	return cbu;
}

struct bu *bu_find_current(struct bu *bu)
{
	return bu_find(bu, BU_CURRENT);
}

struct bu *bu_find_working_or_finishing(struct bu *bu)
{
	struct bu *cbu=NULL;
	if((cbu=bu_find(bu, BU_WORKING))) return cbu;
	return bu_find(bu, BU_FINISHING);
}
