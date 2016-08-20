#ifndef _RESTORE_SERVER_PROTOCOL2_H
#define _RESTORE_SERVER_PROTOCOL2_H

#include "action.h"
#include "cntr.h"
#include "sbuf.h"
#include "slist.h"

extern int protocol2_extra_restore_stream_bits(struct asfd *asfd,
	struct blk *blk, struct slist *slist, enum action act,
	struct sbuf *need_data, int last_ent_was_dir, struct cntr *cntr);

extern int restore_sbuf_protocol2(struct asfd *asfd, struct sbuf *sb,
	enum action act, enum cntr_status cntr_status,
	struct cntr *cntr, struct sbuf *need_data);

#endif
