#ifndef _QUOTA_H
#define _QUOTA_H

extern int check_quota(struct async *as, struct cntr *cntr,
	uint64_t hard_quota, uint64_t soft_quota);

#endif
