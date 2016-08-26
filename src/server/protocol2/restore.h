#ifndef _RESTORE_SERVER_PROTOCOL2_H
#define _RESTORE_SERVER_PROTOCOL2_H

struct blk;
struct sbuf;
struct slist;

extern int protocol2_extra_restore_stream_bits(struct asfd *asfd,
	struct blk *blk, struct slist *slist, enum action act,
	struct sbuf *need_data, int last_ent_was_dir, struct cntr *cntr);

extern int restore_sbuf_protocol2(struct asfd *asfd, struct sbuf *sb,
	enum action act, struct cntr *cntr, struct sbuf *need_data);

#endif
