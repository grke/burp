#include "include.h"

struct slist *slist_alloc(void)
{
	return (struct slist *)calloc_w(1, sizeof(struct slist), __func__);
}

void slist_free(struct slist *slist)
{
	struct sbuf *sb;
	struct sbuf *shead;
	if(!slist) return;
	shead=slist->head;
	while(shead)
	{
		sb=shead;
		shead=shead->next;
		sbuf_free(sb);
	}
	free(slist);
}

void slist_add_sbuf(struct slist *slist, struct sbuf *sb)
{
	if(slist->tail)
	{
		// Add to the end of the list.
		slist->tail->next=sb;
		slist->tail=sb;
		// Markers might have fallen off the end. Start them again
		// on the tail.
		if(!slist->last_requested) slist->last_requested=slist->tail;
		if(!slist->add_sigs_here) slist->add_sigs_here=slist->tail;
		if(!slist->blks_to_request) slist->blks_to_request=slist->tail;
		if(!slist->blks_to_send) slist->blks_to_send=slist->tail;
	}
	else
	{
		// Start the list.
		slist->head=sb;
		slist->tail=sb;
		// Pointers to the head that can move along the list
		// at a different rate.
		slist->last_requested=sb;
		slist->add_sigs_here=sb;
		slist->blks_to_request=sb;
		slist->blks_to_send=sb;
	}
}
