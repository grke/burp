#ifndef _RESTORE_SERVER_PROTOCOL1_H
#define _RESTORE_SERVER_PROTOCOL1_H

#include "../../action.h"
#include "../restore.h"

struct sbuf;

extern int restore_sbuf_protocol1(struct asfd *asfd, struct sbuf *sb,
	struct bu *bu, enum action act, struct sdirs *sdirs,
	enum cntr_status cntr_status, struct conf **cconfs);

#endif
