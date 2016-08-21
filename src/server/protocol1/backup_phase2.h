#ifndef _BACKUP_PHASE2_SERVER_PROTOCOL1_H
#define _BACKUP_PHASE2_SERVER_PROTOCOL1_H

#include "async.h"
#include "conf.h"
#include "server/sdirs.h"

extern int backup_phase2_server_protocol1(struct async *as, struct sdirs *sdirs,
	const char *incexc, int resume, struct conf **cconfs);

#endif
