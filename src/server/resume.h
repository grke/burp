#ifndef _BACKUP_RESUME3_H
#define _BACKUP_RESUME3_H

#include "../fzp.h"
#include "manio.h"

struct dpth;

extern int do_resume(
	man_off_t **pos_phase1,
	man_off_t **pos_current,
	struct sdirs *sdirs,
	struct dpth *dpth,
	struct conf **cconfs
);

#ifdef UTEST
// For changed manifest.
extern int get_last_good_entry(struct manio *manio, struct iobuf *result,
	struct cntr *cntr, struct dpth *dpth, enum protocol protocol,
	man_off_t **pos);
// For phase 1 manifest.
extern int forward_past_entry(struct manio *manio, struct iobuf *target,
	enum protocol protocol, man_off_t **pos);
// For unchanged manifest.
extern int forward_before_entry(struct manio *manio, struct iobuf *target,
	struct cntr *cntr, struct dpth *dpth, enum protocol protocol,
	man_off_t **pos);
#endif

#endif
