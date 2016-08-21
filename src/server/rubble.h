#ifndef _RUBBLE_H
#define _RUBBLE_H

#include "async.h"
#include "conf.h"
#include "server/sdirs.h"

// Return 1 if the backup is now finalising.
extern int check_for_rubble(struct async *as,
	struct sdirs *sdirs, const char *incexc,
	int *resume, struct conf **cconfs);

#endif
