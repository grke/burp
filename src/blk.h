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

	// FIX THIS: Only for ease of use while developing.
	char weak[16+1];
	char strong[32+1];

	// On the server, used to mark blocks that we already have.
	int got;
	int requested;
};

extern struct blk *blk_alloc(void);
extern struct blk *blk_alloc_with_data(uint32_t max_data_length);
extern void        blk_free(struct blk *blk);
extern int         blk_md5_update(struct blk *blk);
extern char *      blk_get_md5sum_str(unsigned char *checksum);

// Groups of blocks.
typedef struct blkgrp blkgrp_t;

struct blkgrp
{
	uint64_t index;
	char *buf;
	char *buf_end;
	char *cp;
	int b;
	int req_blk;
	struct blk *blks[SIG_MAX];
	struct blkgrp *next;
};

extern struct blkgrp *blkgrp_alloc(struct rconf *rconf);
extern void blkgrp_free(struct blkgrp *blkgrp);

#endif // __RABIN_BLK_H
