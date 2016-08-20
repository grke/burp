#ifndef _EXTRA_COMMS_H
#define _EXTRA_COMMS_H

#include "async.h"
#include "conf.h"

extern int extra_comms(struct async *as, char **incexc,
	int *srestore, struct conf **confs, struct conf **cconfs);

#endif
