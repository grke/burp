#include "include.h"

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

void bu_free(struct bu **bu)
{
	if(!bu || !*bu) return;
	free_w(&((*bu)->path));
	free_w(&((*bu)->basename));
	free_w(&((*bu)->data));
	free_w(&((*bu)->delta));
	free_w(&((*bu)->timestamp));
	*bu=NULL;
}

void bu_list_free(struct bu **bu_list)
{
	struct bu *bu;
	struct bu *next;
	for(bu=*bu_list; bu; bu=next)
	{
		next=bu->next;
		bu_free(&bu);
	}
	*bu_list=NULL;
}

struct bu *bu_find_current(struct bu *bu)
{
	struct bu *cbu=NULL;
        for(cbu=bu; cbu; cbu=cbu->prev)
                if(cbu->flags & BU_CURRENT)
                        break;
	return cbu;
}
