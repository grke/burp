#ifndef _BROWSE_H
#define _BROWSE_H

#include "bu.h"
#include "conf.h"
#include "cstat.h"

extern int browse_manifest(struct cstat *cstat,
	struct bu *bu, const char *browse, int use_cache);

#endif
