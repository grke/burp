#ifndef _BACKUP_PHASE1_CLIENT_H
#define _BACKUP_PHASE1_CLIENT_H

#include "asfd.h"
#include "conf.h"

extern int backup_phase1_client(struct asfd *asfd, struct conf **confs,
	int estimate);

#endif
