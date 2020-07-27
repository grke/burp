#ifndef _CHILD_H
#define _CHILD_H

#include "monitor/cstat.h"

struct async;

extern int timed_operation(
	enum cntr_status cntr_status,
	const char *path,
	struct asfd *asfd,
	struct sdirs *sdirs,
	struct conf **confs
);
extern int timed_operation_status_only(
	enum cntr_status cntr_status,
	const char *path,
	struct conf **confs
);

extern int child(struct async *as,
	int is_status_server,
	int status_wfd,
	struct conf **confs,
	struct conf **cconfs);

#endif
