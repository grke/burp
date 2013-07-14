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
	if(blk) free(blk);
	return NULL;
}

void blk_free(struct blk *blk)
{
	if(!blk) return;
	free(blk->data);
	free(blk);
}

static char *get_md5sum_str(unsigned char *checksum)
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

static int md5_update(struct blk *blk)
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

int blk_output(struct rconf *rconf, struct blk *blk)
{
	if(md5_update(blk)) return -1;
printf("send block here\n");
/*

	fprintf(ofp,
		// The length of this record.
		"s0031"
		// Fingerprint is 4 bytes.
		"%016lX"
		// MD5sum is 32 characters long.
		"%s"
		// Offset is 4 bytes, so means pack files can be up to
		// 16EB
	//	"%016lX"
		"\n"
		,
		blk->fingerprint,
		get_md5sum_str(blk->md5sum)
	//	blk->offset
		);

	// Block length can be 2 bytes, giving a max length of 64KB.
	fprintf(ofp, "a%04X", blk->length);

	fwrite(blk->data, blk->length, 1, ofp);
*/

	return 0;
}
