#ifndef _QUOTA_H
#define _QUOTA_H

#include "async.h"
#include "cntr.h"

#include <inttypes.h>

extern int check_quota(struct async *as, struct cntr *cntr,
	uint64_t hard_quota, uint64_t soft_quota);

#endif
