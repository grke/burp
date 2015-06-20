#ifndef __RABIN_BLK_LIST_H
#define __RABIN_BLK_LIST_H

#include "../burp.h"
#include "blk.h"

struct blist
{
	struct blk *head;
	struct blk *tail;
// On the server, keep track of the next blk to send to the champ chooser.
	struct blk *blk_for_champ_chooser;
// On the server, keep track of the last blk received from the champ chooser.
	struct blk *blk_from_champ_chooser;
// On the client, keep track of last blk requested by the server.
	struct blk *last_requested;
// On the client, keep track of last data sent by the client.
	struct blk *last_sent;
// On the champ chooser, keep track of where to deduplicate from next.
	struct blk *blk_to_dedup;
	uint64_t last_index;
};

extern struct blist *blist_alloc(void);
extern void blist_free(struct blist **blist);
extern void blist_add_blk(struct blist *blist, struct blk *blk);

#endif
