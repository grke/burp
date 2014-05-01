#include <assert.h>

#include "include.h"

struct candidate **candidates=NULL;
size_t candidates_len=0;

struct candidate *candidate_alloc(void)
{
	struct candidate *candidate;
	if(!(candidate=(struct candidate *)calloc(1, sizeof(struct candidate))))
		log_out_of_memory(__func__);
	return candidate;
}

void candidates_set_score_pointers(struct candidate **candidates,
	size_t clen, struct scores *scores)
{
	size_t a;
	for(a=0; a<candidates_len; a++)
		candidates[a]->score=&(scores->scores[a]);
}

struct candidate *candidates_add_new(void)
{
	struct candidate *candidate;

	if(!(candidate=candidate_alloc())) return NULL;

	if(!(candidates=(struct candidate **)realloc(candidates,
		(candidates_len+1)*sizeof(struct candidate *))))
	{
		log_out_of_memory(__func__);
		return NULL;
	}
	candidates[candidates_len++]=candidate;
	return candidate;
}

// When a backup is ongoing, use this to add newly complete candidates.
int candidate_add_fresh(const char *path, struct conf *conf)
{
	int ars;
	int ret=-1;
	gzFile zp=NULL;
	const char *cp=NULL;
	struct sbuf *sb=NULL;
	struct candidate *candidate=NULL;
	struct blk *blk=NULL;

	if(!(candidate=candidates_add_new())) goto end;
	cp=path+strlen(conf->directory);
	while(cp && *cp=='/') cp++;
	if(!(candidate->path=strdup(cp)))
	{
		log_out_of_memory(__func__);
		goto end;
	}

	if(!(sb=sbuf_alloc(conf))
	  || !(blk=blk_alloc())
	  || !(zp=gzopen_file(path, "rb")))
		goto end;
	while(zp)
	{
		if((ars=sbuf_fill_from_gzfile(sb, NULL /* struct async */,
			zp, blk, NULL, conf))<0)
				goto end;
		else if(ars>0)
		{
			// Reached the end.
			break;
		}
		if(!*(blk->weak)) continue;
		if(is_hook(blk->weak))
		{
			if(sparse_add_candidate(blk->weak, candidate))
				goto end;
		}
		*blk->weak='\0';
	}

	if(scores_grow(scores, candidates_len)) goto end;
	candidates_set_score_pointers(candidates, candidates_len, scores);
	scores_reset(scores);
	//printf("HERE: %d candidates\n", (int)candidates_len);

	ret=0;
end:
	gzclose_fp(&zp);
	sbuf_free(sb);
	blk_free(blk);
	return ret;
}

struct candidate *candidates_choose_champ(struct incoming *in,
	struct candidate *champ_last)
{
	static uint16_t i;
	static uint16_t s;
	static struct sparse *sparse;
	static struct candidate *best;
	static struct candidate *candidate;
	static uint16_t *score;

	best=NULL;

	//struct timespec tstart={0,0}, tend={0,0};
	//clock_gettime(CLOCK_MONOTONIC, &tstart);

printf("incoming size: %d\n", in->size);
	scores_reset(scores);
printf("after scores reset\n");

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
/*
				printf("%s is now best:\n",
					best->path);
				printf("    score %p %d\n",
					best->score, *(best->score));
*/
			}
			// FIX THIS: figure out a way of giving preference to
			// newer candidates.
		}
	}
	//clock_gettime(CLOCK_MONOTONIC, &tend);
	//printf("champ_chooser took about %.5f seconds\n",
	//	((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - 
	//	((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));

/*
	if(best)
		printf("%s is choice:\nscore %p %d\n", best->path, best->score, *(best->score));
	else
		printf("no choice\n");
*/
	return best;
}
