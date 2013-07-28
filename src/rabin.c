#include <stdlib.h>
#include <string.h>

#include "blk.h"
#include "rabin.h"
#include "rabin_win.h"
#include "log.h"

static struct blk *blk=NULL;
static char *gcp=NULL;
static char *gbuf=NULL;
static char *gbuf_end=NULL;

static void add_blk_to_list(struct blk *blk, struct sbuf *sb, uint64_t *bindex)
{
//printf("add blk to list\n");
	blk->index=(*bindex)++;
	if(sb->btail)
	{
		// Add a new one.
		sb->btail->next=blk;
		sb->btail=blk;
	}
	else
	{
		// Start the list.
		sb->bhead=blk;
		sb->btail=blk;
		sb->bsighead=blk;
	}
}

// This is where the magic happens.
static int blk_read(struct rconf *rconf, char *buf, char *buf_end, struct win *win, struct sbuf *sb, uint64_t *bindex)
{
	char c;
	char *cp;

	if(!blk && !(blk=blk_alloc_with_data(rconf->blk_max)))
		return -1;

	for(cp=gcp; cp!=gbuf_end; cp++)
	{
		c=*cp;

		blk->fingerprint = (blk->fingerprint * rconf->prime) + c;
		win->checksum    = (win->checksum    * rconf->prime) + c
				   - (win->data[win->pos] * rconf->multiplier);
		win->data[win->pos] = c;

		win->pos++;
		win->total_bytes++;
		blk->data[blk->length++] = c;

		if(win->pos == rconf->win) win->pos=0;

		if( blk->length >= rconf->blk_min
		 && (blk->length == rconf->blk_max
		  || (win->checksum % rconf->blk_avg) == rconf->prime))
		{
			add_blk_to_list(blk, sb, bindex);
			blk=NULL;

			// Maybe we have enough blocks to return now.
			//if(++(sb->b)==SIG_MAX) return 0;

			// Make space for another.
			if(!(blk=blk_alloc_with_data(rconf->blk_max)))
				return -1;
		}
	}
	gcp=buf;
	return 0;
}

int blks_generate(struct rconf *rconf, struct sbuf *sb, struct win *win, uint64_t *bindex)
{
	ssize_t bytes;

	if(!gbuf)
	{
		if(!(gbuf=(char *)malloc(rconf->blk_max)))
		{
			log_out_of_memory(__FUNCTION__);
			return -1;
		}
		gbuf_end=gbuf;
		gcp=gbuf;
	}

	if(gcp!=gbuf)
	{
		// Could have got a fill before buf ran out -
		// need to resume from the same place in that case.
		if(blk_read(rconf, gbuf, gbuf_end, win, sb, bindex))
			return -1;
	}
	while((bytes=sbuf_read(sb, gbuf, rconf->blk_max)))
	{
		gcp=gbuf;
		gbuf_end=gbuf+bytes;
		if(blk_read(rconf, gbuf, gbuf_end, win, sb, bindex))
			return -1;
		// Maybe we have enough blocks to return now.
		//if(sb->b==SIG_MAX) return 0;
	}

	// Getting here means there is no more to read from the file.
	// Make sure to deal with anything left over.
	if(blk)
	{
		if(blk->length) add_blk_to_list(blk, sb, bindex);
		else blk_free(blk);
		blk=NULL;
	}
	return 1;
}
