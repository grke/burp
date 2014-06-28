#include "include.h"
#include "../backup_phase1.h"

#include <librsync.h>
#include <math.h>

/* Need to base librsync block length on the size of the old file, otherwise
   the risk of librsync collisions and silent corruption increases as the
   size of the new file gets bigger. */
size_t get_librsync_block_len(const char *endfile)
{
	size_t ret=0;
	unsigned long long oldlen=0;
	oldlen=strtoull(endfile, NULL, 10);
	ret=(size_t)(ceil(sqrt(oldlen)/16)*16); // round to a multiple of 16.
	if(ret<64) return 64; // minimum of 64 bytes.
	return ret;
}
