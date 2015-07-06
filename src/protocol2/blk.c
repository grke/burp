#include <stdlib.h>

#include "blk.h"
#include "../alloc.h"
#include "../hexmap.h"
#include "../log.h"
#include "../protocol2/rabin/rabin.h"
#include "rabin/rconf.h"

struct blk *blk_alloc(void)
{
	return (struct blk *)calloc_w(1, sizeof(struct blk), __func__);
}

struct blk *blk_alloc_with_data(uint32_t max_data_length)
{
	struct blk *blk=NULL;
	if(!(blk=blk_alloc())) return NULL;
	if((blk->data=(char *)
	  calloc_w(1, sizeof(char)*max_data_length, __func__)))
		return blk;
	blk_free(&blk);
	return NULL;
}

static void blk_free_content(struct blk *blk)
{
	if(!blk) return;
	free_w(&blk->data);
}

void blk_free(struct blk **blk)
{
	if(!blk || !*blk) return;
	blk_free_content(*blk);
	free_v((void **)blk);
}

static int md5_generation(uint8_t md5sum[], const char *data, uint32_t length)
{
	MD5_CTX md5;
	if(!MD5_Init(&md5)
	  || !MD5_Update(&md5, data, length)
	  || !MD5_Final(md5sum, &md5))
	{
		logp("MD5 generation failed.\n");
		return -1;
	}
	return 0;
}

int blk_md5_update(struct blk *blk)
{
	return md5_generation(blk->md5sum, blk->data, blk->length);
}

int blk_is_zero_length(struct blk *blk)
{
	return !blk->fingerprint // All zeroes.
	  && !memcmp(blk->md5sum, md5sum_of_empty_string, MD5_DIGEST_LENGTH);
}

int blk_verify(struct blk *blk, struct conf **confs)
{
	uint8_t md5sum[MD5_DIGEST_LENGTH];
	// Check rabin fingerprint.
	switch(blk_read_verify(blk, confs))
	{
		case 1: break; // Match.
		case 0: return 0; // Did not match.
		default: return -1;
	}
	// Check md5sum.
	if(md5_generation(md5sum, blk->data, blk->length))
		return -1;
	if(!memcmp(md5sum, blk->md5sum, MD5_DIGEST_LENGTH)) return 1;
	return 0;
}
