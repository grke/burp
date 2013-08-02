#ifndef __RABIN_BLK_H
#define __RABIN_BLK_H

#include <stdio.h>
#include <stdint.h>
#include <openssl/md5.h>
#include "rconf.h"

#define SIG_MAX 0xFFF

typedef struct blk blk_t;

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

	int requested;
	int got;
	uint64_t index;
	struct blk *next;
};

extern struct blk *blk_alloc(void);
extern struct blk *blk_alloc_with_data(uint32_t max_data_length);
extern void        blk_free(struct blk *blk);
extern int         blk_md5_update(struct blk *blk);
extern char *      blk_get_md5sum_str(unsigned char *checksum);

struct blist
{
	struct blk *head;
	struct blk *tail;
// On the client, keep track of last blk requested by the server.
	struct blk *bark1;
// On the client, keep track of last data sent by the client.
	struct blk *bark2;
};

extern struct blist *blist_init(void);
extern void blist_free(struct blist *blist);
extern void blk_add_to_list(struct blk *blk, struct blist *blist);

#endif // __RABIN_BLK_H
