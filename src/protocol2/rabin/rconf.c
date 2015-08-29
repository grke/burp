#include "../../burp.h"
#include "rconf.h"
#include "../../log.h"

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
	rconf->win_size=31;	// Sliding window size.
	rconf->win_max=63;	// Not configurable.

	rconf->blk_min=RABIN_MIN; // Minimum block size.
	rconf->blk_avg=RABIN_AVG; // Average block size.
	rconf->blk_max=RABIN_MAX; // Maximum block size.

	rconf->multiplier=get_multiplier(rconf->win_size, rconf->prime);
}
