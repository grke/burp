#ifndef _BACKUP_PHASE4_SERVER_PROTOCOL1_H
#define _BACKUP_PHASE4_SERVER_PROTOCOL1_H

#include <stdbool.h>

extern int do_patch(struct asfd *asfd,
	const char *dst, const char *del, const char *upd,
	bool gzupd, int compression);

extern int backup_phase4_server_protocol1(struct sdirs *sdirs,
	struct conf **cconfs);

#endif
