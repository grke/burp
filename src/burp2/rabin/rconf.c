#include "include.h"

static uint64_t get_multiplier(uint32_t win, uint64_t prime)
{
	unsigned int i;
	uint64_t multiplier=1;

	for(i=0; i < win; i++) multiplier*=prime;

	return multiplier;
}

// Hey you. Probably best not fuck with these.
void rconf_init(struct rconf *rconf)
{
	rconf->prime=3;		// Not configurable.

	rconf->win_min=17;	// Not configurable.
	rconf->win=31;		// Sliding window size.
	rconf->win_max=63;	// Not configurable.

	rconf->blk_min=RABIN_MIN; // Minimum block size.
	rconf->blk_avg=RABIN_AVG; // Average block size.
	rconf->blk_max=RABIN_MAX; // Maximum block size.

	rconf->multiplier=get_multiplier(rconf->win, rconf->prime);
}

int rconf_check(struct rconf *rconf)
{
	if(rconf->win < rconf->win_min || rconf->win > rconf->win_max)
	{
		logp("Sliding window size not between %u and %u.\n",
			rconf->win_min, rconf->win_max);
		return -1;
	}
	if(rconf->blk_min >= rconf->blk_max)
	{
		logp("Minimum block size must be less than the maximum block size.\n");
		return -1;
	}
	if( rconf->blk_avg < rconf->blk_min
	 || rconf->blk_avg > rconf->blk_max)
	{
		logp("Average block size must be between the minimum and maximum block sizes, %u and %u\n", rconf->blk_min, rconf->blk_max);
		return -1;
	}
	
	return 0;
}
