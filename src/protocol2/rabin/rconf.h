#ifndef __RCONF_H
#define __RCONF_H

#define RABIN_MIN	4096
#define RABIN_AVG	5000
#define RABIN_MAX	8192

#include "../../burp.h"

struct rconf
{
	uint64_t prime;

	uint32_t win_min;
	uint32_t win_size;
	uint32_t win_max;
	
	uint32_t blk_min;
	uint32_t blk_avg;
	uint32_t blk_max;

	uint64_t multiplier;
};

extern void rconf_init(struct rconf *rconf);
extern int rconf_check(struct rconf *rconf);

#endif
