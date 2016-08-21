#ifndef __RABIN_BLK_H
#define __RABIN_BLK_H

#include "../burp.h"

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

struct fzp;
struct iobuf;

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
	uint64_t savepath;			// 8
	uint64_t index;				// 8
	struct blk *next;			// 8
};

extern struct blk *blk_alloc(void);
extern struct blk *blk_alloc_with_data(uint32_t max_data_length);
extern void blk_free_content(struct blk *blk);
extern void blk_free(struct blk **blk);
extern int blk_md5_update(struct blk *blk);
extern int blk_is_zero_length(struct blk *blk);

extern int blk_verify(uint64_t fingerprint, uint8_t *md5sum,
	char *data, size_t length);
extern int blk_fingerprint_is_hook(struct blk *blk);

extern int blk_set_from_iobuf_sig(struct blk *blk, struct iobuf *iobuf);
extern int blk_set_from_iobuf_sig_and_savepath(struct blk *blk,
	struct iobuf *iobuf);
extern int blk_set_from_iobuf_fingerprint(struct blk *blk, struct iobuf *iobuf);
extern int blk_set_from_iobuf_savepath(struct blk *blk, struct iobuf *iobuf);
extern int blk_set_from_iobuf_index_and_savepath(struct blk *blk,
	struct iobuf *iobuf);
extern int blk_set_from_iobuf_wrap_up(struct blk *blk, struct iobuf *iobuf);

extern void blk_to_iobuf_sig(struct blk *blk, struct iobuf *iobuf);
extern void blk_to_iobuf_sig_and_savepath(struct blk *blk, struct iobuf *iobuf);
extern void blk_to_iobuf_fingerprint(struct blk *blk, struct iobuf *iobuf);
extern void blk_to_iobuf_savepath(struct blk *blk, struct iobuf *iobuf);
extern void blk_to_iobuf_index_and_savepath(struct blk *blk,
	struct iobuf *iobuf);
extern void blk_to_iobuf_wrap_up(struct blk *blk, struct iobuf *iobuf);

extern int to_fzp_fingerprint(struct fzp *fzp, uint64_t fingerprint);

#endif
