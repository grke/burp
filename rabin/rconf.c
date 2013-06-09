#include <stdio.h>
#include <stdint.h>

#include "rconf.h"

void rconf_init(struct rconf *rconf)
{
	rconf->prime=3;		// Not configurable.

	rconf->win_min=17;	// Not configurable.
	rconf->win=31;		// Sliding window size.
	rconf->win_max=63;	// Not configurable.

	rconf->blk_min=4096;	// Minimum block size.
	rconf->blk_avg=5000;	// Average block size.
	rconf->blk_max=8192;	// Maximum block size.
}

int rconf_check(struct rconf *rconf)
{
	if(rconf->win < rconf->win_min || rconf->win > rconf->win_max)
	{
		fprintf(stderr, "Sliding window size not between %u and %u.\n",
			rconf->win_min, rconf->win_max);
		return -1;
	}
	if(rconf->blk_min >= rconf->blk_max)
	{
		fprintf(stderr, "Minimum block size must be less than the maximum block size.\n");
		return -1;
	}
	if( rconf->blk_avg < rconf->blk_min
	 || rconf->blk_avg > rconf->blk_max)
	{
		fprintf(stderr, "Average block size must be between the minimum and maximum block sizes, %u and %u\n", rconf->blk_min, rconf->blk_max);
		return -1;
	}
	
	return 0;
}
