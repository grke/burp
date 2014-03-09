#include <assert.h>

#include "include.h"

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
	HASH_ADD_INT(sparse_table, weak, sparse);
        return sparse;
}

struct candidate *candidate_alloc(void)
{
	struct candidate *candidate;
	if(!(candidate=(struct candidate *)calloc(1, sizeof(struct candidate))))
		log_out_of_memory(__FUNCTION__);
	return candidate;
}

static int candidate_add_to_sparse(const char *weakstr, struct candidate *candidate)
{
	static size_t s;
	static uint64_t weak;
	static struct sparse *sparse;

	// Convert to uint64_t.
	weak=strtoull(weakstr, 0, 16);

	if((sparse=sparse_find(weak)))
	{
		// Do not add it to the list if it has already been added.
		for(s=0; s<sparse->size; s++)
			if((sparse->candidates[s]==candidate))
			{
//				printf("not adding %s\n", candidate->path);
				return 0;
			}
	}

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

	uint16_t got;
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
	in->got=0;
}

static struct candidate **candidates=NULL;
static size_t candidates_len=0;

static void set_candidate_score_pointers(struct candidate **candidates, size_t clen, struct scores *scores)
{
	size_t a;
	for(a=0; a<candidates_len; a++)
		candidates[a]->score=&(scores->scores[a]);
}

static struct candidate *add_new_candidate(void)
{
	struct candidate *candidate;

	if(!(candidate=candidate_alloc())) return NULL;

	if(!(candidates=(struct candidate **) realloc(candidates,
		(candidates_len+1)*sizeof(struct candidate *))))
	{
		log_out_of_memory(__FUNCTION__);
		return NULL;
	}
	candidates[candidates_len++]=candidate;
	return candidate;
}

int champ_chooser_init(const char *datadir, struct config *conf)
{
	int ars;
	int ret=-1;
	gzFile zp=NULL;
	struct sbuf *sb=NULL;
	char *sparse_path=NULL;
	struct stat statp;
	struct candidate *candidate=NULL;

	if(!(sb=sbuf_alloc(conf))
	  || (!scores && !(scores=scores_alloc()))
	  || !(sparse_path=prepend_s(datadir, "sparse"))
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
		if(sb->path.cmd==CMD_MANIFEST)
		{
			if(!(candidate=add_new_candidate())) goto end;
			candidate->path=sb->path.buf;
			sb->path.buf=NULL;
		}
		else if(sb->path.cmd==CMD_FINGERPRINT)
		{
			if(candidate_add_to_sparse(sb->path.buf, candidate))
				goto end;
		}
		else
		{
			iobuf_log_unexpected(&sb->path, __FUNCTION__);
			goto end;
		}
		sbuf_free_contents(sb);
	}

	if(scores_grow(scores, candidates_len)) goto end;
	set_candidate_score_pointers(candidates, candidates_len, scores);
	scores_reset(scores);

	dump_scores("init", scores, scores->size);

	ret=0;
end:
	gzclose_fp(&zp);
	sbuf_free(sb);
	if(sparse_path) free(sparse_path);
	return ret;
}

int is_hook(const char *str)
{
	// FIX THIS: should work on bits, not just the character.
	return *str=='F';
}

// When a backup is ongoing, use this to add newly complete candidates.
int add_fresh_candidate(const char *path, struct config *conf)
{
	int ars;
	int ret=-1;
	gzFile zp=NULL;
	const char *cp=NULL;
	struct sbuf *sb=NULL;
	struct candidate *candidate=NULL;
	struct blk *blk=NULL;

	if(!(candidate=add_new_candidate())) goto end;
	cp=path+strlen(conf->directory);
	while(cp && *cp=='/') cp++;
	if(!(candidate->path=strdup(cp)))
	{
		log_out_of_memory(__FUNCTION__);
		goto end;
	}

	if(!(sb=sbuf_alloc(conf))
	  || !(blk=blk_alloc())
	  || !(zp=gzopen_file(path, "rb")))
		goto end;
	while(zp)
	{
		if((ars=sbuf_fill_from_gzfile(sb, zp, blk, NULL, conf))<0)
			goto end;
		else if(ars>0)
		{
			// Reached the end.
			break;
		}
		if(!*(blk->weak)) continue;
		if(is_hook(blk->weak))
		{
			if(candidate_add_to_sparse(blk->weak,
				candidate)) goto end;
		}
		*blk->weak='\0';
	}

	if(scores_grow(scores, candidates_len)) goto end;
	set_candidate_score_pointers(candidates, candidates_len, scores);
	scores_reset(scores);
	printf("HERE: %d candidates\n", (int)candidates_len);

	ret=0;
end:
	gzclose_fp(&zp);
	sbuf_free(sb);
	blk_free(blk);
	return ret;
}

static char *get_fq_path(const char *path)
{
	static char fq_path[24];
	snprintf(fq_path, sizeof(fq_path), "%s\n", path);
	return fq_path;
}

static struct incoming *in=NULL;

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
//printf("F");
			blk->got=GOT;
			in->got++;
			return 0;
		}
		else
		{
//      printf("COLLISION: %s %s\n", blk->weak, blk->strong);
//                      collisions++;
		}
	}

	blk->got=NOT_GOT;
//printf(".");

	// Set up the details of where the block will be saved.
	snprintf(blk->save_path, sizeof(blk->save_path),
		"%s", dpth_mk(dpth));
	if(dpth_incr_sig(dpth)) return -1;

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

//printf("incoming size: %d\n", in->size);
	scores_reset(scores);

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
				int t;
				// Want to exclude sparse entries that have
				// already been found.
				in->found[i]=1;
				// Need to go back up the list, subtracting
				// scores.
				for(t=s-1; t>=0; t--)
				{
					(*(sparse->candidates[t]->score))--;
//	printf("%d %s   fix: %d\n", i, candidate->path, *(sparse->candidates[t]->score));
				}
				break;
			}
			score=candidate->score;
			(*score)++;
//			printf("%d %s score: %d\n", i, candidate->path, *score);
			assert(*score<=in->size);
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

#define CHAMPS_MAX 10

int deduplicate(struct blk *blks, struct dpth *dpth, struct config *conf, uint64_t *wrap_up)
{
	struct blk *blk;
	struct candidate *champ;
	struct candidate *champ_last=NULL;
	static int consecutive_got=0;
	static int count=0;
	static int blk_count=0;

printf("in deduplicate()\n");

	incoming_found_reset(in);
	count=0;
	while((champ=champ_chooser(in, champ_last)))
	{
		printf("Got champ: %s %d\n", champ->path, *(champ->score));
		if(hash_load(champ->path, conf)) return -1;
		if(++count==CHAMPS_MAX) break;
		champ_last=champ;
	}

	printf("Loaded %d champs\n", count);

	blk_count=0;
	for(blk=blks; blk; blk=blk->next)
	{
//printf("try: %d\n", blk->index);
		blk_count++;

		// FIX THIS - represents zero length block.
		if(!blk->fingerprint // All zeroes.
		  && !strcmp(blk->strong, "D41D8CD98F00B204E9800998ECF8427E"))
		{
			blk->got=GOT;
			in->got++;
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
			if(consecutive_got++>BLKS_CONSECUTIVE_NOTIFY)
			{
				*wrap_up=blk->index;
				consecutive_got=0;
			}
		}
		else
			consecutive_got=0;
	}
printf("     ALREADY GOT %d/%d incoming blocks\n", in->got, blk_count);


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
	if(is_hook(blk->weak))
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







/*
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
*/
