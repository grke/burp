#include <stdlib.h>
#include <string.h>

#include "blk.h"
#include "rabin.h"
#include "rabin_win.h"
#include "log.h"

/*
static int blks_output(struct rconf *rconf, struct blk **blkbuf, int *b)
{
	int d;
	for(d=0; d<*b; d++)
	{
		if(blk_output(rconf, blkbuf[d]))
			return -1;
		blkbuf[d]->length=0;
		blkbuf[d]->fingerprint=0;
	}
	*b=0;
	return 0;
}
*/

// This is where the magic happens.
static int blk_read(struct rconf *rconf, char *buf, char *buf_end, struct win *win, struct blkgrp *blkgrp)
{
	char c;
	char *cp;
	struct blk *blk;

	for(cp=blkgrp->cp; cp!=buf_end; cp++)
	{
		blk=blkgrp->blks[blkgrp->b];
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
			// Maybe we have enough blocks to return now.
			if(++(blkgrp->b)==SIG_MAX) return 0;
			// Make space for another.
			if(!(blkgrp->blks[blkgrp->b]=blk_alloc(rconf->blk_max)))
				return -1;
		}
	}
	blkgrp->cp=buf;
	return 0;
}

static int do_blks_generate(struct blkgrp *blkgrp, struct rconf *rconf, struct sbuf *sb, struct win *win)
{
	ssize_t bytes;
	if(blkgrp->cp!=blkgrp->buf)
	{
		// Could have got a fill of blkgrp before buf ran out -
		// need to resume from the same place in that case.
		if(blk_read(rconf, blkgrp->buf, blkgrp->buf_end, win, blkgrp))
			return -1;
	}
	while((bytes=sbuf_read(sb, blkgrp->buf, rconf->blk_max)))
	{
		blkgrp->cp=blkgrp->buf;
		blkgrp->buf_end=blkgrp->buf+bytes;
		if(blk_read(rconf, blkgrp->buf, blkgrp->buf_end, win, blkgrp))
			return -1;
		// Maybe we have enough blocks to return now.
		if(blkgrp->b==SIG_MAX) return 0;
	}

	// Getting here means there is no more to read from the file.
	// Make sure to deal with anything left over.
	if(blkgrp->blks[blkgrp->b]->length) blkgrp->b++;
	return 0;
}

int blks_generate(struct blkgrp **bnew, struct rconf *rconf, struct sbuf *sb, struct win *win)
{
	if(!(*bnew=blkgrp_alloc(rconf))) return -1;

	if(!do_blks_generate(*bnew, rconf, sb, win)) return 0;

	blkgrp_free(*bnew); *bnew=NULL;
	return -1;
}
