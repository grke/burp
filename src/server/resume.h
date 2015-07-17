#ifndef _BACKUP_RESUME_H
#define _BACKUP_RESUME_H

#include "../fzp.h"
#include "manio.h"

extern man_off_t *do_resume(struct sdirs *sdirs,
	struct dpth *dpth, struct conf **cconfs);

#endif
