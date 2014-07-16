#ifndef _SLIST_H
#define _SLIST_H

struct slist
{
	struct sbuf *head;
	struct sbuf *tail;
	struct sbuf *last_requested; // last file requested
	struct sbuf *add_sigs_here; // server only
	struct sbuf *blks_to_request; // server only
	struct sbuf *blks_to_send; // client only
};

extern struct slist *slist_alloc(void);
extern void slist_free(struct slist **slist);
extern void slist_add_sbuf(struct slist *slist, struct sbuf *sb);

#endif
