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
	struct sparse *sparse=NULL;
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

struct candidate *candidate_alloc(char *path)
{
	struct candidate *candidate;
	if((candidate=(struct candidate *)malloc(sizeof(struct candidate))))
	{
		candidate->path=path;
//printf("candidate alloc: %p %hu\n", score, *score);
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

static struct scores *scores=NULL;

static struct scores *scores_alloc(void)
{
	struct scores *scores;
	if((scores=(struct scores *)calloc(1, sizeof(struct scores))))
		return scores;
	log_out_of_memory(__FUNCTION__);
	return NULL;
}

static void dump_scores(const char *msg, struct scores *scores, int len)
{
	int a;
printf("%p\n", scores);
//printf("%d %d\n", len, scores->allocated);
	for(a=0; a<len; a++)
	{
		printf("%s %d %p: %d\n",
			msg, a, &(scores->scores[a]), scores->scores[a]);
	}
}

// Return -1 or error, 0 on OK.
static int scores_grow(struct scores *scores, size_t count)
{
	printf("grow scores to %lu\n", count);
	scores->size=count;
	scores->allocated=count;
	if((scores->scores=(uint16_t *)realloc(scores->scores,
		sizeof(uint16_t)*scores->allocated)))
			return 0;
	log_out_of_memory(__FUNCTION__);
	return -1;
}

static void scores_reset(struct scores *scores)
{
	if(!scores->scores || !scores->size) return;
	memset(scores->scores, 0, sizeof(scores->scores[0])*scores->size);
}

struct incoming
{
	uint64_t *weak;
	uint8_t *found;
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
printf("grow incoming to %d\n", in->allocated);
	if((in->weak=(uint64_t *)
		realloc(in->weak, in->allocated*sizeof(uint64_t)))
	  && (in->found=(uint8_t *)
		realloc(in->found, in->allocated*sizeof(uint8_t))))
			return 0;
	log_out_of_memory(__FUNCTION__);
	return -1;
}

static void incoming_found_reset(struct incoming *in)
{
	if(!in->found || !in->size) return;
	memset(in->found, 0, sizeof(in->found[0])*in->size);
}

static void set_candidate_score_pointers(struct candidate **candidates, size_t clen, struct scores *scores)
{
	size_t a;
	for(a=0; a<clen; a++)
		candidates[a]->score=&(scores->scores[a]);
}

int champ_chooser_init(const char *datadir, struct config *conf)
{
	int ars;
	int ret=-1;
	uint64_t weak;
	gzFile zp=NULL;
	struct sbuf *sb=NULL;
	struct candidate *candidate=NULL;
	char *sparse_path=NULL;
	struct stat statp;
	struct candidate **candidates=NULL;
	size_t clen=0;

	if(!(sb=sbuf_alloc())
	  || (!scores && !(scores=scores_alloc()))
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
			if(!(candidate=candidate_alloc(sb->path)))
				goto end;

			if(!(candidates=(struct candidate **)
				realloc(candidates,
				(clen+1)*sizeof(struct candidate *))))
			{
				log_out_of_memory(__FUNCTION__);
				return -1;
			}
			candidates[clen++]=candidate;

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

	if(scores_grow(scores, clen)) goto end;
	set_candidate_score_pointers(candidates, clen, scores);

	scores_reset(scores);
	dump_scores("init", scores, scores->size);

	ret=0;
end:
	gzclose_fp(&zp);
	sbuf_free(sb);
	if(sparse_path) free(sparse_path);
	return ret;
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
printf("F");
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
printf(".");

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

static struct candidate *champ_chooser(struct incoming *in, struct candidate *champ_last)
{
	static uint16_t i;
	static uint16_t s;
	static struct sparse *sparse;
	static struct candidate *best;
	static struct candidate *candidate;
	static uint16_t *score;

	best=NULL;

	struct timespec tstart={0,0}, tend={0,0};
	clock_gettime(CLOCK_MONOTONIC, &tstart);

	for(i=0; i<in->size; i++)
	{
		if(in->found[i]) continue;

		if(!(sparse=sparse_find(in->weak[i])))
			continue;
		for(s=0; s<sparse->size; s++)
		{
			candidate=sparse->candidates[s];
			if(candidate==champ_last)
			{
				// Want to exclude sparse entries that have
				// already been found.
				in->found[i]=1;
				// Need to go back up the list, subtracting
				// scores.
				int t;
				for(t=s-1; t>=0; t--)
					(*(candidate->score))--;
				break;
			}
			score=candidate->score;
			(*score)++;
			if(*score>1000)
			{
				dump_scores("exiting", scores, scores->size);
				exit(1);
			}
			if(!best
			// Maybe should check for candidate!=best here too.
			  || *score>*(best->score))
			{
				best=candidate;
				printf("%s is now best:\n",
					best->path);
				printf("    score %p %d\n",
					best->score, *(best->score));
			}
			// FIX THIS: figure out a way of giving preference to
			// newer candidates.
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &tend);
	printf("champ_chooser took about %.5f seconds\n",
		((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - 
		((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));

	if(best)
		printf("%s is choice:\nscore %p %d\n", best->path, best->score, *(best->score));
	else
		printf("no choice\n");
	return best;
}

static struct incoming *in=NULL;

int deduplicate(struct blk *blks, struct dpth *dpth, struct config *conf, uint64_t *wrap_up)
{
	struct blk *blk;
	struct candidate *champ;
	struct candidate *champ_last=NULL;
	static int consecutive_got=0;
	static int count=0;

printf("in deduplicate()\n");

	incoming_found_reset(in);
	count=0;
	while((champ=champ_chooser(in, champ_last)))
	{
		printf("Got champ: %s %d\n", champ->path, *(champ->score));
		scores_reset(scores);
		if(hash_load(champ->path, conf)) return -1;
		if(++count==3)
		{
			printf("Loaded 3 champs\n");
			break;
		}
		champ_last=champ;
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

//printf("after agb: %lu %d\n", blk->index, blk->got);

		// If there are a number of consecutive blocks that we have
		// already got, help the client out and tell it to forget them,
		// because there is a limit to the number that it will keep
		// in memory.
		if(blk->got==GOT)
		{
			if(consecutive_got++>10000)
			{
				*wrap_up=blk->index;
				consecutive_got=0;
			}
		}
		else
			consecutive_got=0;
	}
printf("\n");


	// Start the incoming array again.
	in->size=0;
	// Destroy the deduplication hash table.
	hash_delete_all();

	return 0;
}

// Return 0 for OK, -1 for error, 1 to mean that the list of blocks has been
// deduplicated.
int deduplicate_maybe(struct blk *blk, struct dpth *dpth, struct config *conf, uint64_t *wrap_up)
{
	static int count=0;
	static struct blk *blks=NULL;
	if(!blks && !(blks=blk)) return -1;
	if(!in && !(in=incoming_alloc())) return -1;

	blk->fingerprint=strtoull(blk->weak, 0, 16);
//printf("%s\n", blk->weak);
	if(*(blk->weak)=='F')
	{
		if(incoming_grow_maybe(in)) return -1;
		in->weak[in->size-1]=blk->fingerprint;
	}
	if(++count<SIG_MAX) return 0;
//	if(++count<2) return 0;
	count=0;

	if(deduplicate(blks, dpth, conf, wrap_up)<0) return -1;
	blks=NULL;
//printf("\n");
	return 1; // deduplication was successful
}









static struct blk *gen_test_blk(void)
{
	static int count=0;
	struct blk *blk=NULL;
	if(!(blk=blk_alloc())) return NULL;
	count++;
	snprintf(blk->weak, sizeof(blk->weak), "F363D8CDA1A9B115");
	if(count>100000) exit(1);
	return blk;
}

int champ_test(struct config *conf)
{
	int ia;
	uint64_t wrap_up=0;
	struct dpth *dpth=NULL;
	struct blk *blk=NULL;
	const char *datadir="/var/spool/burp/testclient/data";

	if(!(dpth=dpth_alloc(datadir)) || dpth_init(dpth))
		return -1;

	if(champ_chooser_init(datadir, conf)) return -1;

	while((blk=gen_test_blk()))
	{
		if((ia=deduplicate_maybe(blk, dpth, conf, &wrap_up))<0)
		{
			return -1;
		}
	}
	return -1;
}

