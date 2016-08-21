#ifndef _BACKUP_PHASE2_CLIENT_PROTOCOL1_H
#define _BACKUP_PHASE2_CLIENT_PROTOCOL1_H

#include "asfd.h"
#include "conf.h"

extern int backup_phase2_client_protocol1(struct asfd *asfd,
	struct conf **confs, int resume);

#endif
