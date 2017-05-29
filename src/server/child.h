#ifndef _CHILD_H
#define _CHILD_H

#include "monitor/cstat.h"

struct async;

extern int write_status(enum cntr_status cntr_status,
	const char *path, struct cntr *cntr);

extern int child(struct async *as,
	int is_status_server,
	int status_wfd,
	struct conf **confs,
	struct conf **cconfs);

#endif
