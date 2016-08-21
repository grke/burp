#ifndef _BACKUP_CLIENT_PHASE2_H
#define _BACKUP_CLIENT_PHASE2_H

#include "asfd.h"
#include "conf.h"

extern int backup_phase2_client_protocol2(struct asfd *asfd,
	struct conf **confs, int resume);

#endif
