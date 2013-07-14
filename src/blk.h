#ifndef __RABIN_BLK_H
#define __RABIN_BLK_H

#include <stdio.h>
#include <stdint.h>
#include <openssl/md5.h>
#include "rconf.h"

// The fingerprinted block.
struct blk
{
	char *data;
	uint32_t length;
	uint64_t fingerprint;
	unsigned char md5sum[MD5_DIGEST_LENGTH+1];
};

extern struct blk *blk_alloc(uint32_t max_data_length);
extern void        blk_free(struct blk *blk);
extern int         blk_output(struct rconf *rconf, struct blk *blk);

#endif // __RABIN_BLK_H
