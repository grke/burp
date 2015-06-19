#ifndef PROTOCOL1_SBUF_H
#define PROTOCOL1_SBUF_H

#include "../sbuf.h"

extern int sbufl_fill_from_net(struct sbuf *sb, struct asfd *asfd,
	struct conf **confs);

#endif
