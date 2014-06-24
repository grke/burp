#include "include.h"

int champ_chooser_init(const char *datadir, struct conf *conf)
{
	int ret=-1;
	struct stat statp;
	char *sparse_path=NULL;

	// FIX THIS: scores is a global variable.
	if(!scores && !(scores=scores_alloc())) goto end;

	if(!(sparse_path=prepend_s(datadir, "sparse"))) goto end;
	if(lstat(sparse_path, &statp))
	{
		ret=0;
		goto end;
	}
	ret=candidate_load(NULL, sparse_path, conf);
end:
	if(sparse_path) free(sparse_path);
	return ret;
}

#define HOOK_MASK	0xF000000000000000

int is_hook(uint64_t fingerprint)
{
	return (fingerprint&HOOK_MASK)==HOOK_MASK;
}

static int already_got_block(struct asfd *asfd, struct blk *blk)
{
	//static char *path;
	static struct hash_weak *hash_weak;

	// If already got, need to overwrite the references.
	if((hash_weak=hash_weak_find(blk->fingerprint)))
	{
		static struct hash_strong *hash_strong;
		if((hash_strong=hash_strong_find(
			hash_weak, blk->md5sum)))
		{
			memcpy(blk->savepath,
				hash_strong->savepath, SAVE_PATH_LEN);
//printf("FOUND: %s %s\n", blk->weak, blk->strong);
//printf("F");
			blk->got=BLK_GOT;
			asfd->in->got++;
			return 0;
		}
		else
		{
//      printf("COLLISION: %s %s\n", blk->weak, blk->strong);
//                      collisions++;
		}
	}

	blk->got=BLK_NOT_GOT;
//printf(".");
	return 0;
}

#define CHAMPS_MAX 10

int deduplicate(struct asfd *asfd, struct conf *conf)
{
	struct blk *blk;
	struct incoming *in=asfd->in;
	struct candidate *champ;
	struct candidate *champ_last=NULL;
	int count=0;
	int blk_count=0;

printf("in deduplicate()\n");

	if(!in) return 0;

	incoming_found_reset(in);
	count=0;
	while((champ=candidates_choose_champ(in, champ_last)))
	{
		printf("Got champ: %s %d\n", champ->path, *(champ->score));
		if(hash_load(champ->path, conf)) return -1;
		if(++count==CHAMPS_MAX) break;
		champ_last=champ;
	}

	blk_count=0;
	for(blk=asfd->blist->blk_to_dedup; blk; blk=blk->next)
	{
//printf("try: %lu\n", blk->index);
		blk_count++;

		if(!blk->fingerprint // All zeroes.
		  && !memcmp(blk->md5sum,
			md5sum_of_empty_string, MD5_DIGEST_LENGTH))
		{
//printf("got: %s %s\n", blk->weak, blk->strong);
			blk->got=BLK_GOT;
			in->got++;
			continue;
		}

		// If already got, this function will set blk->save_path
		// to be the location of the already got block.
		if(already_got_block(asfd, blk)) return -1;

//printf("after agb: %lu %d\n", blk->index, blk->got);
	}

	printf("%d %s found %d/%d incoming %s\n", count,
		count==1?"champ":"champs", in->got, blk_count,
		blk_count==1?"block":"blocks");
	logp("%d %s found %d/%d incoming %s\n", count,
		count==1?"champ":"champs", in->got, blk_count,
		blk_count==1?"block":"blocks");
	//cntr_add_same_val(conf->cntr, CMD_DATA, in->got);

	// Start the incoming array again.
	in->size=0;
	// Destroy the deduplication hash table.
	hash_delete_all();

	asfd->blist->blk_to_dedup=NULL;

	return 0;
}
