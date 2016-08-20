#ifndef _AUTOUPGRADE_SERVER_H
#define _AUTOUPGRADE_SERVER_H

#include "cntr.h"

extern int autoupgrade_server(struct async *as,
	long ser_ver, long cli_ver, const char *os, struct cntr *cntr,
	const char *autoupgrade_dir);

#endif
