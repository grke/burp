#ifndef _RESTORE_SBUF_H
#define _RESTORE_SBUF_H

#include "../action.h"
#include "../sbuf.h"
#include "restore.h"

extern int restore_sbuf_all(struct asfd *asfd, struct sbuf *sb,
	struct bu *bu, enum action act, struct sdirs *sdirs,
	struct conf **cconfs);

#ifdef UTEST
extern int verify_file(struct asfd *asfd, struct sbuf *sb,
	int patches, const char *best, struct cntr *cntr);
extern int restore_file(struct asfd *asfd, struct bu *bu,
        struct sbuf *sb, enum action act,
        struct sdirs *sdirs, struct conf **cconfs);
#endif

#endif
