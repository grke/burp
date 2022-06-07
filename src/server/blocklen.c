#include "../burp.h"
#include "backup_phase1.h"
#include "blocklen.h"

#include <math.h>

// Use the same MAX_BLOCK_SIZE as rsync.
#define MAX_BLOCK_SIZE ((uint32_t)1 << 17)

/* Need to base librsync block length on the size of the old file, otherwise
   the risk of librsync collisions and silent corruption increases as the
   size of the new file gets bigger. */
size_t get_librsync_block_len(const char *endfile)
{
	size_t ret=0;
	uint64_t oldlen=0;
	oldlen=strtoull(endfile, NULL, 10);
	// round to a multiple of 16.
	ret=(size_t)(ceil((sqrt((double)oldlen))/16)*16);
	if(ret<64) return 64; // minimum of 64 bytes.
	if(ret>MAX_BLOCK_SIZE) return MAX_BLOCK_SIZE;
	return ret;
}
