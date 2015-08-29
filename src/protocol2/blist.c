#include "../burp.h"
#include "blist.h"
#include "blk.h"
#include "../alloc.h"

struct blist *blist_alloc(void)
{
	return (struct blist *)calloc_w(1, sizeof(struct blist), __func__);
}

void blist_free(struct blist **blist)
{
	struct blk *b;
	struct blk *head;
	if(!blist || !*blist) return;
	b=(*blist)->head;
	head=b;
	while(head)
	{
		b=head;
		head=head->next;
		blk_free(&b);
	}
	free_v((void **)blist);
}

void blist_add_blk(struct blist *blist, struct blk *blk)
{
	blk->index=++(blist->last_index);

	if(blist->tail)
	{
		// Add to the end of the list.
		blist->tail->next=blk;
		blist->tail=blk;
		// Markers might have fallen off the end. Start them again
		// on the tail.
		if(!blist->last_requested) blist->last_requested=blist->tail;
		if(!blist->last_sent) blist->last_sent=blist->tail;
		return;
	}

	// Start the list.
	blist->head=blk;
	blist->tail=blk;
	// Pointers to the head that can move along the list
	// at a different rate.
	blist->blk_for_champ_chooser=NULL;
	blist->blk_from_champ_chooser=blk;
	blist->last_requested=blk;
	blist->last_sent=blk;
	blist->blk_to_dedup=blk;
}
