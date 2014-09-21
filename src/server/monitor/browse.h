#ifndef _BROWSE_H
#define _BROWSE_H

#include "include.h"

extern int browse_manifest(struct asfd *srfd, struct cstat *cstat,
	struct bu *bu, const char *browse, struct conf *conf);

#endif
