#include <stdlib.h>
#include <string.h>

#include "blk.h"
#include "win.h"
#include "rabin.h"

#define SIG_MAX	0xFFF

static uint64_t get_multiplier(struct rconf *rconf)
{
	int i;
	uint64_t multiplier=1;

	for(i=0; i < rconf->win; i++) multiplier *= rconf->prime;

	return multiplier;
}

static int blks_output(struct rconf *rconf, FILE *ofp, struct blk **blkbuf, int *b)
{
	int d;
	for(d=0; d<*b; d++)
	{
		if(blk_output(rconf, ofp, blkbuf[d]))
			return -1;
		blkbuf[d]->length=0;
		blkbuf[d]->fingerprint=0;
	}
	*b=0;
	return 0;
}

static int blk_read(struct rconf *rconf, FILE *ofp, uint64_t multiplier, char *buf, char *buf_end, struct win *win, struct blk **blkbuf, int *b)
{
	char c;
	char *cp;
	struct blk *blk;

	for(cp=buf; cp!=buf_end; cp++)
	{
		blk=blkbuf[*b];
		c=*cp;

		blk->fingerprint = (blk->fingerprint * rconf->prime) + c;
		win->checksum    = (win->checksum    * rconf->prime) + c
				   - (win->data[win->pos] * multiplier);
		win->data[win->pos] = c;

		win->pos++;
		win->total_bytes++;
		blk->data[blk->length++] = c;

		if(win->pos == rconf->win) win->pos=0;

		if( blk->length >= rconf->blk_min
		 && (blk->length == rconf->blk_max
		  || (win->checksum % rconf->blk_avg) == rconf->prime))
		{
			(*b)++;
			if(*b<SIG_MAX) continue;
			if(blks_output(rconf, ofp, blkbuf, b))
				return -1;
		}
	}
	return 0;
}

int blks_generate(struct rconf *rconf, FILE *ifp, FILE *ofp)
{
	int ret=0;
	ssize_t bytes;
	char *buf=NULL;
	struct win *win;
	uint64_t multiplier;
	struct blk *blkbuf[SIG_MAX];
	int b=0;

	buf=malloc(rconf->blk_max);

	if(!(multiplier=get_multiplier(rconf))
	  || !(win=win_alloc(rconf)))
		goto error;

	for(b=0; b<SIG_MAX; b++)
		if(!(blkbuf[b]=blk_alloc(rconf->blk_max)))
			goto error;
	b=0;

	while((bytes=fread(buf, 1, rconf->blk_max, ifp)))
		if(blk_read(rconf, ofp, multiplier, buf, buf+bytes, win,
			blkbuf, &b))
				goto error;

	if(blkbuf[b]->length) b++;

	if(b)
	{
	//	blk->offset = win->total_bytes - blk->length;
		if(blks_output(rconf, ofp, blkbuf, &b))
			goto error;
	}

	goto end;
error:
	ret=-1;
end:
	win_free(win);
	for(b=0; b<SIG_MAX; b++)
		blk_free(blkbuf[b]);
	return ret;
}
