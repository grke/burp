#ifndef __RABIN_BLK_H
#define __RABIN_BLK_H

#include <openssl/md5.h>

// The highest number of blocks that the client will hold in memory.
#define BLKS_MAX_IN_MEM		20000

// 4096 signatures per data file.
#define DATA_FILE_SIG_MAX	0x1000

// Range from 3596 to 4096 signatures for each manifest component.
// This will allow the decision of where to split them to be dynamic in order
// to reduce the number of candidate manifests a little bit.
#define MANIFEST_SIG_MIN	0x0e0c
#define MANIFEST_SIG_MAX	0x1000

#define SAVE_PATH_LEN		8

enum blk_got
{
	BLK_INCOMING=0,
	BLK_NOT_GOT,
	BLK_GOT
};

typedef struct blk blk_t;

// The fingerprinted block.
struct blk
{
	char *data;
	uint8_t got;
	uint8_t requested;
	uint8_t got_save_path;
	uint8_t pad;
	uint32_t length;
	uint64_t fingerprint;
	uint8_t md5sum[MD5_DIGEST_LENGTH];
	uint8_t savepath[SAVE_PATH_LEN];
	uint64_t index;
	struct blk *next;
};

extern struct blk *blk_alloc(void);
extern struct blk *blk_alloc_with_data(uint32_t max_data_length);
extern void blk_free(struct blk **blk);
extern int blk_md5_update(struct blk *blk);
extern char *blk_get_md5sum_str(uint8_t *checksum);
extern void blk_print_alloc_stats(void);

#endif
