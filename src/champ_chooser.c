#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <uthash.h>

#include "dpth.h"
#include "log.h"
#include "cmd.h"
#include "msg.h"
#include "sbuf.h"
#include "handy.h"
#include "hash.h"
#include "champ_chooser.h"

struct sparse
{
	uint64_t weak;
	size_t size;
	struct candidate **candidates;
	UT_hash_handle hh;
};

static struct sparse *sparse_table=NULL;

static struct sparse *sparse_find(uint64_t weak)
{
	struct sparse *sparse;
	HASH_FIND_INT(sparse_table, &weak, sparse);
	return sparse;
}

static struct sparse *sparse_add(uint64_t weak)
{
        struct sparse *sparse;
        if(!(sparse=(struct sparse *)calloc(1, sizeof(struct sparse))))
        {
                log_out_of_memory(__FUNCTION__);
                return NULL;
        }
        sparse->weak=weak;
//printf("sparse_add: %016lX\n", weak);
        HASH_ADD_INT(sparse_table, weak, sparse);
        return sparse;
}

struct candidate *candidate_alloc(char *path, uint16_t *score)
{
	struct candidate *candidate;
	if((candidate=(struct candidate *)malloc(sizeof(struct candidate))))
	{
		candidate->path=path;
		candidate->score=score;
		return candidate;
	}
	log_out_of_memory(__FUNCTION__);
	return NULL;
}

static int candidate_add(uint64_t weak, struct candidate *candidate)
{
	static struct sparse *sparse;
	sparse=sparse_find(weak);

	if(!sparse && !(sparse=sparse_add(weak)))
		return -1;
	if(!(sparse->candidates=(struct candidate **)
		realloc(sparse->candidates,
			(sparse->size+1)*sizeof(struct candidate *))))
	{
                log_out_of_memory(__FUNCTION__);
		return -1;
	}
	sparse->candidates[sparse->size++]=candidate;
	
	return 0;
}

// Array to keep the scores. Candidates point at a unique entry in the
// array for their scores. Keeping them in an array like this means
// that all the scores can be reset quickly.
struct scores
{
	uint16_t *scores;
	size_t size;
	size_t allocated;
};

static struct scores *scores_alloc(void)
{
	struct scores *scores;
	if((scores=(struct scores *)calloc(1, sizeof(struct scores))))
		return scores;
	log_out_of_memory(__FUNCTION__);
	return NULL;
}

static int scores_grow_maybe(struct scores *scores)
{
	if(++scores->size<scores->allocated) return 0;
	// Make the scores array bigger.
	scores->allocated+=32;
	if((scores->scores=
	  (uint16_t *)realloc(scores->scores, sizeof(uint16_t)*scores->allocated)))
		return 0;
	log_out_of_memory(__FUNCTION__);
	return -1;
}

static void scores_reset(struct scores *scores)
{
	if(!scores->scores) return;
	memset(scores->scores, 0, sizeof(scores->scores[0])*scores->allocated);
}

int champ_chooser_init(const char *datadir, struct config *conf)
{
	int ars;
	int ret=-1;
	uint64_t weak;
	gzFile zp=NULL;
	struct sbuf *sb=NULL;
	struct candidate *candidate=NULL;
	struct scores *scores=NULL;
	char *sparse_path=NULL;
	struct stat statp;

	if(!(sb=sbuf_alloc())
	  || !(scores=scores_alloc())
	  || !(sparse_path=prepend_s(datadir, "sparse", strlen("sparse")))
	  || (!lstat(sparse_path, &statp)
		&& !(zp=gzopen_file(sparse_path, "rb"))))
			goto end;
	while(zp)
	{
		if((ars=sbuf_fill_from_gzfile(sb, zp, NULL, NULL, conf))<0)
			goto end;
		else if(ars>0)
		{
			// Reached the end.
			break;
		}
		if(sb->cmd==CMD_MANIFEST)
		{
			if(scores_grow_maybe(scores)
			  || !(candidate=candidate_alloc(sb->path,
				&(scores->scores[scores->size-1])))) goto end;
			sb->path=NULL;
		}
		else if(sb->cmd==CMD_FINGERPRINT)
		{
			// Convert to uint64_t.
			weak=strtoull(sb->path, 0, 16);
			if(candidate_add(weak, candidate))
				goto end;
//			printf("%s - %s %lu\n",
//				candidate->path, sb->path, weak);
		}
		else
		{
			logp("Unexpected line in %s: %c:%s\n",
				sparse_path, sb->cmd, sb->path);
			goto end;
		}
		sbuf_free_contents(sb);
	}

	scores_reset(scores);
	ret=0;
end:
	gzclose_fp(&zp);
	sbuf_free(sb);
	if(sparse_path) free(sparse_path);
	if(scores)
	{
		if(scores->scores) free(scores->scores);
		free(scores);
	}
	return ret;
}


struct incoming
{
	uint64_t *weak;
	uint16_t size;
	uint16_t allocated;
};

static struct incoming *incoming_alloc(void)
{
	struct incoming *in;
	if((in=(struct incoming *)calloc(1, sizeof(struct incoming))))
		return in;
	log_out_of_memory(__FUNCTION__);
	return NULL;
}

static int incoming_grow_maybe(struct incoming *in)
{
	if(++in->size<in->allocated) return 0;
	// Make the incoming array bigger.
	in->allocated+=32;
	if((in->weak=(uint64_t *)
		realloc(in->weak, in->allocated*sizeof(uint64_t))))
			return 0;
	log_out_of_memory(__FUNCTION__);
	return -1;
}

static char *get_fq_path(const char *path)
{
	static char fq_path[24];
	snprintf(fq_path, sizeof(fq_path), "%s\n", path);
	return fq_path;
}

static int already_got_block(struct blk *blk, struct dpth *dpth)
{
	static struct weak_entry *weak_entry;

	// If already got, need to overwrite the references.
	if((weak_entry=find_weak_entry(blk->fingerprint)))
	{
		static struct strong_entry *strong_entry;
		if((strong_entry=find_strong_entry(weak_entry, blk->strong)))
		{
			snprintf(blk->save_path, sizeof(blk->save_path),
				"%s", get_fq_path(strong_entry->path));
//printf("FOUND: %s %s\n", blk->weak, blk->strong);
			blk->got=GOT;
			return 0;
		}
		else
		{
//      printf("COLLISION: %s %s\n", blk->weak, blk->strong);
//                      collisions++;
		}
	}
	else
	{
		// Add both to hash table.
//		if(!(weak_entry=add_weak_entry(blk->fingerprint)))
//			return -1;
	}

	blk->got=NOT_GOT;

//	if(weak_entry)
//	{
//		// Have a weak entry, still need to add a strong entry.
//		if(!(weak_entry->strong=add_strong_entry(weak_entry,
//			blk->strong, dpth_mk(dpth))))
//				return -1;

		// Set up the details of where the block will be saved.
		snprintf(blk->save_path, sizeof(blk->save_path),
//			"%s", get_fq_path(dpth_mk(dpth)));
			"%s", dpth_mk(dpth));
//printf("here: %s\n", blk->save_path);

//		if(!(blk->dpth_fp=get_dpth_fp(dpth))) return -1;
		if(dpth_incr_sig(dpth)) return -1;

//		return 0;
//	}

	return 0;
}

static struct candidate *champ_chooser(struct incoming *in)
{
	static uint16_t i;
	static uint16_t s;
	static struct sparse *sparse;
	static struct candidate *best;
	best=NULL;
printf("i size: %d\n", in->size);
	for(i=0; i<in->size; i++)
	{
		if(!(sparse=sparse_find(in->weak[i])))
			continue;
		for(s=0; s<sparse->size; s++)
		{
			sparse->candidates[s]->score++;
			if(!best || sparse->candidates[s]->score>best->score)
				best=sparse->candidates[s];
			// FIX THIS: figure out a way of giving preference to
			// newer candidates.
		}
	}
	return best;
}

static struct incoming *in=NULL;

int deduplicate(struct blk *blks, struct dpth *dpth, struct config *conf, uint64_t *wrap_up)
{
	struct blk *blk;
	struct candidate *champ;

printf("in deduplicate()\n");
	//*wrap_up=0;
	if((champ=champ_chooser(in)))
	{
		printf("Got champ: %s\n", champ->path);
	}
	else
	{
		printf("No champ\n");
	}

	// Deduplicate here.
	if(champ)
	{
		if(hash_load(champ->path, conf)) return -1;
	}

	for(blk=blks; blk; blk=blk->next)
	{
//printf("try: %d\n", blk->index);
		// FIX THIS - represents zero length block.
		if(!blk->fingerprint // All zeroes.
		  && !strcmp(blk->strong, "D41D8CD98F00B204E9800998ECF8427E"))
		{
			blk->got=GOT;
			continue;
		}

		// If already got, this function will set blk->save_path
		// to be the location of the already got block.
		if(already_got_block(blk, dpth)) return -1;
printf("after agb: %d %d\n", blk->index, blk->got);

		//if(blk->got==GOT && !*wrap_up) *wrap_up=1;
	}
	//if(*wrap_up) *wrap_up=blist->tail->index;


	// Start the incoming array again.
	in->size=0;
	// Destroy the deduplication hash table.
	hash_delete_all();

	return 0;
}

// Return 0 for OK, -1 for error, 1 to mean that the list of blocks has been
// deduplicated.
int deduplicate_maybe(struct blist *blist, struct blk *blk, struct dpth *dpth, struct config *conf, uint64_t *wrap_up)
{
	static int count=0;
	static struct blk *blks=NULL;
	if(!blks) blks=blk;
	if(!in && !(in=incoming_alloc())) return -1;

	blk->fingerprint=strtoull(blk->weak, 0, 16);
printf("%s\n", blk->weak);
	if(*(blk->weak)=='F')
	{
		if(incoming_grow_maybe(in)) return -1;
		in->weak[in->size-1]=blk->fingerprint;
	}
	if(++count<SIG_MAX) return 0;
	count=0;

	if(deduplicate(blks, dpth, conf, wrap_up)<0) return -1;
	blks=NULL;
printf("\n");
	return 1; // deduplication was successful
}
