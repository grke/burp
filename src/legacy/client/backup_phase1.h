#ifndef _BACKUP_PHASE1_CLIENT_H
#define _BACKUP_PHASE1_CLIENT_H

#include "find.h"
#include "include.h"

extern int send_file(FF_PKT *ff, bool top_level,
	struct config *conf);
extern int backup_phase1_client(struct config *conf,
	long name_max, int estimate);

#endif
