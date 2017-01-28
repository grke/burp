#ifndef _SLIST_H
#define _SLIST_H

#include "sbuf.h"

struct slist
{
	int count;
	struct sbuf *head;
	struct sbuf *tail;
	// The following stuff is for burp-2 only.
	struct sbuf *last_requested; // last file requested
	struct sbuf *add_sigs_here; // server only
	struct sbuf *blks_to_request; // server only
	struct sbuf *blks_to_send; // client only

	struct blist *blist;
};

extern struct slist *slist_alloc(void);
extern void slist_free(struct slist **slist);
extern void slist_add_sbuf(struct slist *slist, struct sbuf *sb);
extern int slist_del_sbuf(struct slist *slist, struct sbuf *sb);
extern int slist_del_sbuf_by_index(struct slist *slist, uint64_t index);
extern void slist_advance(struct slist *slist);

#endif
