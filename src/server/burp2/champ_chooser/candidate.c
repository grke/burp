#include <assert.h>

#include "include.h"

struct candidate **candidates=NULL;
size_t candidates_len=0;

struct candidate *candidate_alloc(void)
{
	return (struct candidate *)
		calloc_w(1, sizeof(struct candidate), __func__);
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

	if(!(candidates=(struct candidate **)realloc_w(candidates,
		(candidates_len+1)*sizeof(struct candidate *), __func__)))
		return NULL;
	candidates[candidates_len++]=candidate;
	return candidate;
}

// This deals with reading in the sparse index, as well as actual candidate
// manifests.
int candidate_load(struct candidate *candidate,
	const char *path, struct conf *conf)
{
	int ret=-1;
	gzFile zp=NULL;
	struct sbuf *sb=NULL;
	struct blk *blk=NULL;

	if(!(sb=sbuf_alloc(conf))
	  || !(blk=blk_alloc())
	  || !(zp=gzopen_file(path, "rb")))
		goto error;
	while(zp)
	{
		switch(sbuf_fill_from_gzfile(sb, NULL, zp, blk, NULL, conf))
		{
			case 1: goto end;
			case -1: goto error;
		}
		if(is_hook(blk->fingerprint))
		{
			if(sparse_add_candidate(&blk->fingerprint, candidate))
				goto error;
		}
		else if(sb->path.cmd==CMD_MANIFEST)
		{
			if(!(candidate=candidates_add_new())) goto error;
			candidate->path=sb->path.buf;
			sb->path.buf=NULL;
		}
		sbuf_free_content(sb);
		blk->fingerprint=0;
	}

end:
	if(scores_grow(scores, candidates_len)) goto end;
	candidates_set_score_pointers(candidates, candidates_len, scores);
	scores_reset(scores);
	//logp("Now have %d candidates\n", (int)candidates_len);
	ret=0;
error:
	gzclose_fp(&zp);
	sbuf_free(&sb);
	blk_free(&blk);
	return ret;
}

// When a backup is ongoing, use this to add newly complete candidates.
int candidate_add_fresh(const char *path, struct conf *conf)
{
	const char *cp=NULL;
	struct candidate *candidate=NULL;

	if(!(candidate=candidates_add_new())) return -1;
	cp=path+strlen(conf->directory);
	while(cp && *cp=='/') cp++;
	if(!(candidate->path=strdup_w(cp, __func__))) return -1;

	return candidate_load(candidate, path, conf);
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

	scores_reset(scores);

	for(i=0; i<in->size; i++)
	{
		if(in->found[i]) continue;

		if(!(sparse=sparse_find(&in->fingerprints[i])))
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
