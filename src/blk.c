#include <malloc.h>

#include "rconf.h"
#include "blk.h"
#include "log.h"

struct blk *blk_alloc(uint32_t max_data_length)
{
	struct blk *blk=NULL;
	if((blk=(struct blk *)calloc(1, sizeof(struct blk)))
	  && (blk->data=(char *)calloc(1, sizeof(char)*max_data_length)))
		return blk;
	log_out_of_memory(__FUNCTION__);
	blk_free(blk);
	return NULL;
}

void blk_free(struct blk *blk)
{
	if(!blk) return;
	if(blk->data) free(blk->data);
	free(blk);
}

char *blk_get_md5sum_str(unsigned char *checksum)
{
	static char str[33]="";
	snprintf(str, sizeof(str),
	  "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
		checksum[0], checksum[1],
		checksum[2], checksum[3],
		checksum[4], checksum[5],
		checksum[6], checksum[7],
		checksum[8], checksum[9],
		checksum[10], checksum[11],
		checksum[12], checksum[13],
		checksum[14], checksum[15]);
	return str;
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

struct blkgrp *blkgrp_alloc(struct rconf *rconf)
{
	struct blkgrp *blkgrp=NULL;
	if(!(blkgrp=(struct blkgrp *)calloc(1, sizeof(struct blkgrp)))
	// I guess buf could be much bigger than this.
	  || !(blkgrp->buf=(char *)malloc(rconf->blk_max)))
	{
		log_out_of_memory(__FUNCTION__);
		return NULL;
	}
	blkgrp->buf_end=blkgrp->buf;
	blkgrp->cp=blkgrp->buf;

	if(!(blkgrp->blks[0]=blk_alloc(rconf->blk_max))) return NULL;

	return blkgrp;
}

void blkgrp_free(struct blkgrp *blkgrp)
{
	int b;
	if(!blkgrp) return;
	for(b=0; b<blkgrp->b+1; b++)
		if(blkgrp->blks[b]) blk_free(blkgrp->blks[b]);
	if(blkgrp->buf) free(blkgrp->buf);
	free(blkgrp);
}
