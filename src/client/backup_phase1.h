#ifndef _BACKUP_PHASE1_CLIENT_H
#define _BACKUP_PHASE1_CLIENT_H

#include "include.h"
#include "find.h"

extern int send_file(FF_PKT *ff, bool top_level, struct conf *conf);
extern int backup_phase1_client(struct conf *conf,
	long name_max, int estimate);

#endif
