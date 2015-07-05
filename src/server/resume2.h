#ifndef _BACKUP_RESUME2_H
#define _BACKUP_RESUME2_H

#include "../fzp.h"
#include "manio.h"

extern man_off_t *do_resume2(struct sdirs *sdirs,
	struct dpth *dpth, struct conf **cconfs);

#endif
