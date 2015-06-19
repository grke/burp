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

#define FINGERPRINT_LEN		8
//#define MD5_DIGEST_LENGTH	16 // This is set in <openssl/md5.h>.
#define CHECKSUM_LEN		FINGERPRINT_LEN+MD5_DIGEST_LENGTH
#define SAVE_PATH_LEN		8 // This is set in hexmap.h.

enum blk_got
{
	BLK_INCOMING=0,
	BLK_NOT_GOT,
	BLK_GOT
};

typedef struct blk blk_t;

// The fingerprinted block. 64 bytes.
struct blk
{
	char *data;				// 8
	uint8_t got;				// 1
	uint8_t requested;			// 1
	uint8_t got_save_path;			// 1
	uint8_t pad;				// 1
	uint32_t length;			// 4
	uint64_t fingerprint;			// 8
	uint8_t md5sum[MD5_DIGEST_LENGTH];	// 16
	uint8_t savepath[SAVE_PATH_LEN];	// 8
	uint64_t index;				// 8
	struct blk *next;			// 8
};

extern struct blk *blk_alloc(void);
extern struct blk *blk_alloc_with_data(uint32_t max_data_length);
extern void blk_free(struct blk **blk);
extern int blk_md5_update(struct blk *blk);
extern int blk_is_zero_length(struct blk *blk);
extern int blk_verify(struct blk *blk, struct conf **confs);

#endif
