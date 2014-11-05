#ifndef _CHILD_H
#define _CHILD_H

#include "monitor/cstat.h"

extern int write_status(enum cstat_status status,
	const char *path, struct conf *conf);

extern int child(struct async *as, int status_wfd,
	struct conf *conf, struct conf *cconf);

#endif
