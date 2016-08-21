#ifndef _DIFF_SERVER_H
#define _DIFF_SERVER_H

#include "asfd.h"
#include "conf.h"
#include "server/sdirs.h"

extern int do_diff_server(struct asfd *asfd,
	struct sdirs *sdirs, struct cntr *cntr, enum protocol protocol,
	const char *backup1, const char *backup2);

#endif
