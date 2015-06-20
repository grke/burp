#include <check.h>
#include <stdlib.h>
#include <stdio.h>
#include "../../prng.h"
#include "../../../src/protocol2/blist.h"

struct blist *build_blist(int wanted)
{
	int i=0;
	struct blist *blist;
	fail_unless((blist=blist_alloc())!=NULL);
	for(i=0; i<wanted; i++)
	{
		struct blk *blk;
		fail_unless((blk=blk_alloc())!=NULL);
		blk->fingerprint=prng_next64();
		prng_md5sum(blk->md5sum);
		blist_add_blk(blist, blk);
	}
	return blist;
}
