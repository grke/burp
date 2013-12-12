#ifndef _BACKUP_PHASE1_CLIENT_LEGACY_H
#define _BACKUP_PHASE1_CLIENT_LEGACY_H

#include "include.h"
#include "../../client/find.h"

extern int send_file_legacy(FF_PKT *ff, bool top_level, struct config *conf);
extern int backup_phase1_client_legacy(struct config *conf,
	long name_max, int estimate);

#endif
