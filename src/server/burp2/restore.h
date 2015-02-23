#ifndef _RESTORE_SERVER_BURP2_H
#define _RESTORE_SERVER_BURP2_H

extern int burp2_extra_restore_stream_bits(struct asfd *asfd, struct blk *blk,
	struct slist *slist, struct sbuf *sb, enum action act,
	struct sbuf *need_data, int last_ent_was_dir, struct conf *cconf);

extern int restore_sbuf_burp2(struct asfd *asfd, struct sbuf *sb,
	enum action act, enum cntr_status cntr_status,
	struct conf *conf, struct sbuf *need_data);

#endif
