#include "../../burp.h"
#include "rabin.h"
#include "rconf.h"
#include "win.h"
#include "../../alloc.h"
#include "../blk.h"
#include "../blist.h"
#include "../../sbuf.h"
#include "../../client/protocol2/rabin_read.h"

static struct blk *blk=NULL;
static char *gcp=NULL;
static char *gbuf=NULL;
static char *gbuf_end=NULL;
static struct rconf rconf;
static struct win *win=NULL; // Rabin sliding window.
static int first=0;

int blks_generate_init(void)
{
	rconf_init(&rconf);
	if(!(win=win_alloc(&rconf))
	  || !(gbuf=(char *)malloc_w(rconf.blk_max, __func__)))
		return -1;
	gbuf_end=gbuf;
	gcp=gbuf;
	return 0;
}

void blks_generate_free(void)
{
	free_w(&gbuf);
	blk_free(&blk);
	win_free(&win);
}

// This is where the magic happens.
// Return 1 for got a block, 0 for no block got.
static int blk_read(void)
{
	unsigned char c;

	for(; gcp<gbuf_end; gcp++)
	{
		c=(unsigned char)*gcp;

		blk->fingerprint = (blk->fingerprint * rconf.prime) + c;
		win->checksum    = (win->checksum    * rconf.prime) + c
				   - (win->data[win->pos] * rconf.multiplier);
		win->data[win->pos] = c;

		win->pos++;
		if(blk->data)
			blk->data[blk->length] = c;
		blk->length++;

		if(win->pos == rconf.win_size)
			win->pos=0;
		if( blk->length >= rconf.blk_min
		 && (blk->length == rconf.blk_max
		  || (
			(win->checksum & 1)
			&& (win->checksum & 2)
			&& !(win->checksum & 4)
			&& (win->checksum % rconf.blk_avg) == rconf.prime))
		) {
			gcp++;
			return 1;
		}
	}
	return 0;
}

static void win_reset(void)
{
	win->checksum=0;
	win->pos=0;
	memset(win->data, 0, rconf.win_size);
}

static int blk_read_to_list(struct sbuf *sb, struct blist *blist)
{
	if(!blk_read()) return 0;

	win_reset();

	// Got something.
	if(first)
	{
		sb->protocol2->bstart=blk;
		first=0;
	}
	if(!sb->protocol2->bsighead)
	{
		sb->protocol2->bsighead=blk;
	}
	blist_add_blk(blist, blk);
	blk=NULL;
	return 1;
}

// The client uses this.
// Return 0 for OK. 1 for OK, and file ended, -1 for error.
int blks_generate(struct sbuf *sb, struct blist *blist, int just_opened)
{
	static ssize_t bytes;
	first=just_opened;

	if(!blk && !(blk=blk_alloc_with_data(rconf.blk_max)))
		return -1;

	if(first)
		win_reset();

	if(gcp<gbuf_end)
	{
		// Could have got a fill before buf ran out -
		// need to resume from the same place in that case.
		if(blk_read_to_list(sb, blist))
			return 0; // Got a block.
		// Did not get a block. Carry on and read more.
	}
	while((bytes=rabin_read(sb, gbuf, rconf.blk_max)))
	{
		gcp=gbuf;
		gbuf_end=gbuf+bytes;
		sb->protocol2->bytes_read+=bytes;
		if(blk_read_to_list(sb, blist))
			return 0; // Got a block
		// Did not get a block. Maybe should try again?
		// If there are async timeouts, look at this!
		return 0;
	}

	// Getting here means there is no more to read from the file.
	// Make sure to deal with anything left over.

	if(!sb->protocol2->bytes_read)
	{
		// Empty file, set up an empty block so that the server
		// can skip over it.
		free_w(&blk->data);
		sb->protocol2->bstart=blk;
		sb->protocol2->bsighead=blk;
		blist_add_blk(blist, blk);
		blk=NULL;
	}
	else if(blk)
	{
		if(blk->length)
		{
			if(first)
			{
				sb->protocol2->bstart=blk;
				first=0;
			}
			if(!sb->protocol2->bsighead)
			{
				sb->protocol2->bsighead=blk;
			}
			blist_add_blk(blist, blk);
		}
		else blk_free(&blk);
		blk=NULL;
	}
	if(blist->tail) sb->protocol2->bend=blist->tail;
	return 1;
}

int blk_verify_fingerprint(uint64_t fingerprint, char *data, size_t length)
{
	win_reset();

	memcpy(gbuf, data, length);
	gbuf_end=gbuf+length;
	gcp=gbuf;
	blk_free(&blk);
	if(!blk && !(blk=blk_alloc())) return -1;
	blk->length=0;
	blk->fingerprint=0;

	// FIX THIS: blk_read should return 1 when it has a block.
	// But, if the block is too small (because the end of the file
	// happened), it returns 0, and blks_generate treats it as having found
	// a final block.
	// So, here the return of blk_read is ignored and we look at the
	// position of gcp instead.
	blk_read();
//printf("%d %d\n", blk->length, length);
//printf("%016"PRIX64" %016"PRIX64" ",
//	blk->fingerprint, fingerprint);
//printf("%s\n", blk->fingerprint==fingerprint?"yes":"no");
	if(gcp==gbuf_end
	  && blk->fingerprint==fingerprint)
		return 1;
	return 0;
}
