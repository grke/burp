#include "burp.h"
#include "alloc.h"
#include "log.h"
#include "sbuf.h"
#include "slist.h"

struct slist *slist_alloc(void)
{
	struct slist *slist=NULL;
	if(!(slist=(struct slist *)calloc_w(1, sizeof(struct slist), __func__)))
		slist_free(&slist);
	return slist;
}

void slist_free(struct slist **slist)
{
	struct sbuf *sb;
	struct sbuf *shead;
	if(!slist || !*slist)
		return;
	shead=(*slist)->head;
	while(shead)
	{
		sb=shead;
		shead=shead->next;
		sbuf_free(&sb);
	}
	free_v((void **)slist);
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
		if(!slist->last_requested)
			slist->last_requested=slist->tail;
		if(!slist->add_sigs_here)
			slist->add_sigs_here=slist->tail;
		if(!slist->blks_to_request)
			slist->blks_to_request=slist->tail;
		if(!slist->blks_to_send)
			slist->blks_to_send=slist->tail;
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
	slist->count++;
}

static void adjust_dropped_markers(struct slist *slist, struct sbuf *sb)
{
        if(sb==slist->tail)
		slist->tail=sb->next;
        if(sb==slist->last_requested)
		slist->last_requested=sb->next;
        if(sb==slist->add_sigs_here)
		slist->add_sigs_here=sb->next;
        if(sb==slist->blks_to_request)
		slist->blks_to_request=sb->next;
        if(sb==slist->blks_to_send)
		slist->blks_to_send=sb->next;
}

int slist_del_sbuf(struct slist *slist, struct sbuf *sb)
{
	struct sbuf *s;
	if(!slist)
		return 0;

	if(slist->head==sb)
	{
		// There is one entry in the list.
		slist->head=slist->head->next;
		slist->count--;
	}
	else
	{
		for(s=slist->head; s; s=s->next)
		{
			if(s->next!=sb) continue;
			s->next=sb->next;
			if(!sb->next)
				slist->tail=s;
			slist->count--;
			break;
		}
	}

        // It is possible for the markers to drop behind.
	adjust_dropped_markers(slist, sb);

	return 0;
}

void slist_advance(struct slist *slist)
{
	struct sbuf *sb;
	sb=slist->head;

        // It is possible for the markers to drop behind.
	adjust_dropped_markers(slist, sb);

	slist->head=sb->next;

	slist->count--;

	sbuf_free(&sb);
}
