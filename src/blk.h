#ifndef __RABIN_BLK_H
#define __RABIN_BLK_H

#include <stdio.h>
#include <stdint.h>
#include <openssl/md5.h>
#include "rconf.h"

#define SIG_MAX 0xFFF

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
extern int         blk_md5_update(struct blk *blk);
extern char *      blk_get_md5sum_str(unsigned char *checksum);

// Groups of blocks.
typedef struct blkgrp blkgrp_t;

struct blkgrp
{
	uint64_t path_index;
	char *buf;
	char *buf_end;
	char *cp;
	int b;
	struct blk *blks[SIG_MAX];
	struct blkgrp *next;
};

extern struct blkgrp *blkgrp_alloc(struct rconf *rconf);
extern void blkgrp_free(struct blkgrp *blkgrp);

#endif // __RABIN_BLK_H
