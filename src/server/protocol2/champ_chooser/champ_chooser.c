#include "../../../burp.h"
#include "../../../alloc.h"
#include "../../../asfd.h"
#include "../../../lock.h"
#include "../../../log.h"
#include "../../../prepend.h"
#include "../../../protocol2/blist.h"
#include "../../../protocol2/blk.h"
#include "candidate.h"
#include "champ_chooser.h"
#include "hash.h"
#include "incoming.h"
#include "scores.h"
#include "sparse.h"

static void try_lock_msg(int seconds)
{
	logp("Unable to get sparse lock for %d seconds.\n", seconds);
}

static int try_to_get_lock(struct lock *lock)
{
	// Sleeping for 1800*2 seconds makes 1 hour.
	// This should be super generous.
	int lock_tries=0;
	int lock_tries_max=1800;
	int sleeptime=2;

	while(1)
	{
		lock_get(lock);
		switch(lock->status)
		{
			case GET_LOCK_GOT:
				logp("locked: sparse index\n");
				return 0;
			case GET_LOCK_NOT_GOT:
				lock_tries++;
				if(lock_tries>lock_tries_max)
				{
					try_lock_msg(lock_tries_max*sleeptime);
					logp("Giving up.\n");
					return -1;
				}
				// Log every 10 seconds.
				if(lock_tries%(10/sleeptime))
				{
					try_lock_msg(lock_tries*sleeptime);
				}
				sleep(sleeptime);
				continue;
			case GET_LOCK_ERROR:
			default:
				logp("Unable to get global sparse lock.\n");
				return -1;
		}
	}
	// Never reached.
	return -1;
}

struct lock *try_to_get_sparse_lock(const char *sparse_path)
{
	char *lockfile=NULL;
	struct lock *lock=NULL;
	if(!(lockfile=prepend_n(sparse_path, "lock", strlen("lock"), "."))
	  || !(lock=lock_alloc_and_init(lockfile))
	  || try_to_get_lock(lock))
		lock_free(&lock);
	free_w(&lockfile);
	return lock;
}

static int load_existing_sparse(const char *datadir, struct scores *scores)
{
	int ret=-1;
	struct stat statp;
	struct lock *lock=NULL;
	char *sparse_path=NULL;
	if(!(sparse_path=prepend_s(datadir, "sparse"))) goto end;
	// Best not let other things mess with the sparse lock while we are
	// trying to read it.
	if(!(lock=try_to_get_sparse_lock(sparse_path)))
		goto end;
	if(lstat(sparse_path, &statp))
	{
		ret=0;
		goto end;
	}
	if(candidate_load(NULL, sparse_path, scores))
		goto end;
	ret=0;
end:
	free_w(&sparse_path);
	lock_release(lock);
	lock_free(&lock);
	return ret;
}

struct scores *champ_chooser_init(const char *datadir)
{
	struct scores *scores=NULL;
	if(!(scores=scores_alloc())
	  || load_existing_sparse(datadir, scores))
		goto error;
	return scores;
error:
	scores_free(&scores);
	return NULL;
}

void champ_chooser_free(struct scores **scores)
{
	candidates_free();
	sparse_delete_all();
	scores_free(scores);
}

static int already_got_block(struct asfd *asfd, struct blk *blk)
{
	static struct hash_weak *hash_weak;

	// If already got, need to overwrite the references.
	if((hash_weak=hash_weak_find(blk->fingerprint)))
	{
		static struct hash_strong *hash_strong;
		if((hash_strong=hash_strong_find(
			hash_weak, blk->md5sum)))
		{
			blk->savepath=hash_strong->savepath;
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

int deduplicate(struct asfd *asfd, const char *directory, struct scores *scores)
{
	struct blk *blk;
	struct incoming *in=asfd->in;
	struct candidate *champ;
	struct candidate *champ_last=NULL;
	int count=0;
	int blk_count=0;

	if(!in) return 0;

	incoming_found_reset(in);
	count=0;
	while(count!=CHAMPS_MAX
	  && (champ=candidates_choose_champ(in, champ_last, scores)))
	{
//		printf("Got champ: %s %d\n", champ->path, *(champ->score));
		switch(hash_load(champ->path, directory))
		{
			case HASH_RET_OK:
				count++;
				champ_last=champ;
				break;
			case HASH_RET_PERM:
				return -1;
			case HASH_RET_TEMP:
				champ->deleted=1;
				break;
		}
	}

	blk_count=0;
	for(blk=asfd->blist->blk_to_dedup; blk; blk=blk->next)
	{
//printf("try: %lu\n", blk->index);
		blk_count++;

		if(blk_is_zero_length(blk))
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

	logp("%s: %04d/%04zu - %04d/%04d\n",
		asfd->desc, count, candidates_len, in->got, blk_count);

	// Start the incoming array again.
	in->size=0;
	// Destroy the deduplication hash table.
	hash_delete_all();

	asfd->blist->blk_to_dedup=NULL;

	return 0;
}
