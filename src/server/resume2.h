#ifndef _BACKUP_RESUME2_H
#define _BACKUP_RESUME2_H

#include "../fzp.h"
#include "manio.h"

extern man_off_t *do_resume2(struct sdirs *sdirs,
	struct dpth *dpth, struct conf **cconfs);

extern int do_forward(struct manio *manio, struct iobuf *result,
	struct iobuf *target, struct cntr *cntr,
	int same, struct dpth *dpth, struct conf **cconfs,
	man_off_t **pos, man_off_t **lastpos);

#endif
