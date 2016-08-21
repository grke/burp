#ifndef _BACKUP_CLIENT_H
#define _BACKUP_CLIENT_H

#include "action.h"
#include "asfd.h"
#include "conf.h"

extern int do_backup_client(struct asfd *asfd,
	struct conf **confs, enum action act, int resume);

#endif
