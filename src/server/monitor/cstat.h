#ifndef _CSTAT_SERVER_H
#define _CSTAT_SERVER_H

#include "include.h"

extern int cstat_load_data_from_disk(struct cstat **clist,
	struct conf **globalcs);
extern int cstat_set_run_status(struct cstat *cstat);
extern int cstat_set_backup_list(struct cstat *cstat);

#endif
