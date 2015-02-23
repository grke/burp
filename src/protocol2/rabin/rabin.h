#ifndef __RABIN_H
#define __RABIN_H

#include "include.h"

extern int blks_generate_init(struct conf *conf);
extern int blks_generate(struct asfd *asfd, struct conf *conf,
	struct sbuf *sb, struct blist *blist, struct win *win);
extern int blk_read_verify(struct blk *blk_to_verify, struct conf *conf);

#endif
