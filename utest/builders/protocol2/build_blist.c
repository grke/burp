#include <check.h>
#include <stdlib.h>
#include <stdio.h>
#include "../../prng.h"
#include "../../../src/hexmap.h"
#include "../../../src/protocol2/blist.h"
#include "../../builders/build.h"

static void add_blk(struct blist *blist)
{
	struct blk *blk;
	fail_unless((blk=blk_alloc())!=NULL);
	blk->fingerprint=prng_next64();
	prng_md5sum(blk->md5sum);
	blk->savepath=prng_next64();
	blist_add_blk(blist, blk);
}

static void add_blk_and_data_files(struct blist *blist, uint64_t save_path)
{
	struct blk *blk;
	fail_unless((blk=blk_alloc())!=NULL);
	blk->fingerprint=prng_next64();
	prng_md5sum(blk->md5sum);
	blk->savepath=save_path;
	blist_add_blk(blist, blk);
}

static void build_blks_with_data_files(struct blist *blist,
	int wanted, int blks_per_data_file)
{
	int i;
	int b=0;
	char savepathstr[20];
	static int data_file=0;

	for(i=0; i<wanted; i++)
	{
		snprintf(savepathstr, sizeof(savepathstr),
			"0000/0000/%04X/%04X", data_file, b++);
		if(b==blks_per_data_file)
		{
			b=0;
			data_file++;
		}
		add_blk_and_data_files(blist,
			savepathstr_with_sig_to_uint64(savepathstr));
	}
	data_file++;
}

void build_blks(struct blist *blist, int wanted, int with_data_files)
{
	int i;
	if(with_data_files)
	{
		build_blks_with_data_files(blist, wanted, with_data_files);
		return;
	}
	for(i=0; i<wanted; i++)
		add_blk(blist);
}

struct blist *build_blist(int wanted)
{
	struct blist *blist;
	fail_unless((blist=blist_alloc())!=NULL);
	build_blks(blist, wanted, 0 /* with_data_files */);
	return blist;
}
