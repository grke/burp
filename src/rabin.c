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

static int first=0;

// This is where the magic happens.
static int blk_read(struct rconf *rconf, char *buf, char *buf_end, struct win *win, struct sbuf *sb, struct blist *blist)
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
			if(first)
			{
				sb->bstart=blk;
				sb->bsighead=blk;
				first=0;
			}
			blk_add_to_list(blk, blist);
			blk=NULL;

			// Maybe we have enough blocks to return now.
			//if(++(sb->b)==SIG_MAX) return 0;

			// Make space for another.
			//if(!(blk=blk_alloc_with_data(rconf->blk_max)))
			//	return -1;
			return 0;
		}
	}
	gcp=buf;
	return 0;
}

int blks_generate(struct config *conf, struct sbuf *sb, struct blist *blist, struct win *win)
{
	ssize_t bytes;

	if(!sb->opened)
	{
		if(sbuf_open_file(sb, conf)) return -1;
		first=1;
	}

	if(!gbuf)
	{
		if(!(gbuf=(char *)malloc(conf->rconf.blk_max)))
		{
			log_out_of_memory(__FUNCTION__);
			sbuf_close_file(sb);
			return -1;
		}
		gbuf_end=gbuf;
		gcp=gbuf;
	}

	if(gcp!=gbuf)
	{
		// Could have got a fill before buf ran out -
		// need to resume from the same place in that case.
		if(blk_read(&conf->rconf, gbuf, gbuf_end, win, sb, blist))
		{
			sbuf_close_file(sb);
			return -1;
		}
	}
	while((bytes=sbuf_read(sb, gbuf, conf->rconf.blk_max)))
	{
		gcp=gbuf;
		gbuf_end=gbuf+bytes;
		if(blk_read(&conf->rconf, gbuf, gbuf_end, win, sb, blist))
			return -1;
		// Maybe we have enough blocks to return now.
		//if(sb->b==SIG_MAX) return 0;
		return 0;
	}

	// Getting here means there is no more to read from the file.
	// Make sure to deal with anything left over.
	if(blk)
	{
		if(blk->length)
		{
			if(first)
			{
				sb->bstart=blk;
				sb->bsighead=blk;
				first=0;
			}
			blk_add_to_list(blk, blist);
		}
		else blk_free(blk);
		blk=NULL;
	}
	if(blist->tail) sb->bend=blist->tail;
	sbuf_close_file(sb);
	return 0;
}
