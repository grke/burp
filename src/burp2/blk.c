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
	if((blk=(struct blk *)calloc(1, sizeof(struct blk))))
	{
		alloc_count++;
//printf("alloc: %p\n", blk);
		return blk;
	}
	log_out_of_memory(__FUNCTION__);
	return NULL;
}

struct blk *blk_alloc_with_data(uint32_t max_data_length)
{
	struct blk *blk=NULL;
	if(!(blk=blk_alloc())) return NULL;
	if((blk->data=(char *)calloc(1, sizeof(char)*max_data_length)))
	{
		data_count++;
		return blk;
	}
	log_out_of_memory(__FUNCTION__);
	blk_free(blk);
	return NULL;
}

void blk_free(struct blk *blk)
{
	if(!blk) return;
//printf("free: %p %d\n", blk, blk->got); fflush(stdout);
	if(blk->data)
	{
		data_free_count++;
		free(blk->data);
	}
	free(blk);
free_count++;
}

void blk_print_alloc_stats(void)
{
//	printf("alloc_count: %d, free_count: %d\n", alloc_count, free_count);
//	printf("data_count: %d, data_free_count: %d\n", data_count, data_free_count);
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

struct blist *blist_alloc(void)
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
//printf("blk_add_to_list: %d\n", bindex);
	if(blist->tail)
	{
		blk->index=blist->tail->index+1;
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
		blk->index=1;
		// Start the list.
		blist->head=blk;
		blist->tail=blk;
		// Pointers to the head that can move along the list
		// at a different rate.
		blist->last_requested=blk;
		blist->last_sent=blk;
	}
}
