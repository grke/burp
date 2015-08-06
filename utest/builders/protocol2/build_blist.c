#include <check.h>
#include <stdlib.h>
#include <stdio.h>
#include "../../prng.h"
#include "../../../src/protocol2/blist.h"

static void add_blk(struct blist *blist)
{
	struct blk *blk;
	fail_unless((blk=blk_alloc())!=NULL);
	blk->fingerprint=prng_next64();
	prng_md5sum(blk->md5sum);
	blk->savepath=prng_next64();
	blist_add_blk(blist, blk);
}

void build_blks(struct blist *blist, int wanted)
{
	int i;
	for(i=0; i<wanted; i++)
	{
		add_blk(blist);
	}
}

struct blist *build_blist(int wanted)
{
	struct blist *blist;
	fail_unless((blist=blist_alloc())!=NULL);
	build_blks(blist, wanted);
	return blist;
}
