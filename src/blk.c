#include <malloc.h>

#include "rconf.h"
#include "blk.h"
#include "log.h"

struct blk *blk_alloc(void)
{
	struct blk *blk=NULL;
	if((blk=(struct blk *)calloc(1, sizeof(struct blk))))
		return blk;
	log_out_of_memory(__FUNCTION__);
	return NULL;
}

struct blk *blk_alloc_with_data(uint32_t max_data_length)
{
	struct blk *blk=NULL;
	if(!(blk=blk_alloc())) return NULL;
	if((blk->data=(char *)calloc(1, sizeof(char)*max_data_length)))
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

struct blist *blist_init(void)
{
	struct blist *blist;
	if(!(blist=(struct blist *)calloc(1, sizeof(struct blist))))
		log_out_of_memory(__FUNCTION__);
	return blist;
}

void blist_free(struct blist *blist)
{
	struct blk *b;
	struct blk *head;
	if(!blist) return;
	b=blist->head;
	head=b;
	while(head)
	{
		b=head;
		head=head->next;
		blk_free(b);
	}
	free(blist);
}

void blk_add_to_list(struct blk *blk, struct blist *blist)
{
	static int bindex=1;
	blk->index=bindex++;
	if(blist->tail)
	{
		// Add to the end of the list.
		blist->tail->next=blk;
		blist->tail=blk;
		// Markers might have fallen off the end. Start them again
		// on the tail.
		if(!blist->last_requested) blist->last_requested=blist->tail;
		if(!blist->last_sent) blist->last_sent=blist->tail;
	}
	else
	{
		// Start the list.
		blist->head=blk;
		blist->tail=blk;
		// Pointers to the head that can move along the list
		// at a different rate.
		blist->last_requested=blk;
		blist->last_sent=blk;
	}
}
