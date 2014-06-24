#include <malloc.h>

#include "include.h"
#include "rabin/rconf.h"

static int alloc_count=0;
static int free_count=0;
static int data_count=0;
static int data_free_count=0;

struct blk *blk_alloc(void)
{
	struct blk *blk=NULL;
	if((blk=(struct blk *)calloc_w(1, sizeof(struct blk), __func__)))
	{
		alloc_count++;
//printf("alloc: %p\n", blk);
		return blk;
	}
	return NULL;
}

struct blk *blk_alloc_with_data(uint32_t max_data_length)
{
	struct blk *blk=NULL;
	if(!(blk=blk_alloc())) return NULL;
	if((blk->data=(char *)
		calloc_w(1, sizeof(char)*max_data_length, __func__)))
	{
		data_count++;
		return blk;
	}
	blk_free(&blk);
	return NULL;
}

void blk_free(struct blk **blk)
{
	if(!blk || !*blk) return;
//printf("free: %p %d\n", blk, blk->got); fflush(stdout);
	if((*blk)->data)
	{
		data_free_count++;
		free((*blk)->data);
	}
	free_v((void **)blk);
free_count++;
}

void blk_print_alloc_stats(void)
{
//	printf("alloc_count: %d, free_count: %d\n", alloc_count, free_count);
//	printf("data_count: %d, data_free_count: %d\n", data_count, data_free_count);
}

int blk_md5_update(struct blk *blk)
{
	MD5_CTX md5;
	if(!MD5_Init(&md5)
	  || !MD5_Update(&md5, blk->data, blk->length)
	  || !MD5_Final(blk->md5sum, &md5))
	{
		logp("MD5 failed.\n");
		return -1;
	}
	return 0;
}

int blk_is_zero_length(struct blk *blk)
{
	return !blk->fingerprint // All zeroes.
	  && !memcmp(blk->md5sum, md5sum_of_empty_string, MD5_DIGEST_LENGTH);
}
