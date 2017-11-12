#include "../../../burp.h"
#include "../../../alloc.h"
#include "../../../log.h"
#include "../../../sbuf.h"
#include "../../../protocol2/blk.h"
#include "candidate.h"
#include "incoming.h"
#include "scores.h"
#include "sparse.h"

#include <assert.h>

struct candidate **candidates=NULL;
size_t candidates_len=0;

#ifndef UTEST
static
#endif
struct candidate *candidate_alloc(void)
{
	return (struct candidate *)
		calloc_w(1, sizeof(struct candidate), __func__);
}

static void candidate_free_content(struct candidate *c)
{
	if(!c) return;
	free_w(&c->path);
}

#ifndef UTEST
static
#endif
void candidate_free(struct candidate **c)
{
	if(!c) return;
	candidate_free_content(*c);
	free_v((void **)c);
}

void candidates_free(void)
{
	for(size_t c=0; c<candidates_len; c++)
		candidate_free(&(candidates[c]));
	free_v((void **)&candidates);
}

static void candidates_set_score_pointers(struct candidate **candidates,
	struct scores *scores)
{
	size_t a;
	for(a=0; candidates && a<candidates_len; a++)
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
enum cand_ret candidate_load(struct candidate *candidate, const char *path,
	struct scores *scores)
{
	enum cand_ret ret=CAND_RET_PERM;
	struct fzp *fzp=NULL;
	struct sbuf *sb=NULL;
	struct blk *blk=NULL;

	if(!(sb=sbuf_alloc(PROTO_2))
	  || !(blk=blk_alloc()))
	{
		ret=CAND_RET_PERM;
		goto error;
	}
	
	if(!(fzp=fzp_gzopen(path, "rb")))
	{
		ret=CAND_RET_TEMP;
		goto error;
	}
	while(fzp)
	{
		sbuf_free_content(sb);
		switch(sbuf_fill_from_file(sb, fzp, blk))
		{
			case 1: goto end;
			case -1:
				logp("Error reading %s in %s, pos %lld\n",
					path, __func__, (long long)fzp_tell(fzp));
				ret=CAND_RET_TEMP;
				goto error;
		}
		if(blk_fingerprint_is_hook(blk))
		{
			if(sparse_add_candidate(&blk->fingerprint, candidate))
			{
				ret=CAND_RET_PERM;
				goto error;
			}
		}
		else if(sb->path.cmd==CMD_MANIFEST)
		{
			if(!(candidate=candidates_add_new()))
			{
				ret=CAND_RET_PERM;
				goto error;
			}
			candidate->path=sb->path.buf;
			sb->path.buf=NULL;
		}
		blk->fingerprint=0;
	}

end:
	if(scores_grow(scores, candidates_len))
	{
		ret=CAND_RET_PERM;
		goto error;
	}
	candidates_set_score_pointers(candidates, scores);
	scores_reset(scores);
	//logp("Now have %d candidates\n", (int)candidates_len);
	ret=CAND_RET_OK;
error:
	fzp_close(&fzp);
	sbuf_free(&sb);
	blk_free(&blk);
	return ret;
}

// When a backup is ongoing, use this to add newly complete candidates.
int candidate_add_fresh(const char *path, const char *directory,
	struct scores *scores)
{
	const char *cp=NULL;
	struct candidate *candidate=NULL;

	if(!(candidate=candidates_add_new()))
		goto error;
	cp=path+strlen(directory);
	while(cp && *cp=='/') cp++;
	if(!(candidate->path=strdup_w(cp, __func__)))
		goto error;

	switch(candidate_load(candidate, path, scores))
	{
		case CAND_RET_PERM:
			goto error;
		case CAND_RET_TEMP:
			// Had an error - try to carry on. Errors can happen
			// when loading a fresh candidate because the backup
			// process can move to the next phase and rename the
			// candidates.
			logp("Removing candidate.\n");
			candidates_len--;
			sparse_delete_fresh_candidate(candidate);
			candidate_free(&candidate);
			// Fall through.
		case CAND_RET_OK:
			return 0;
	}
error:
	candidate_free(&candidate);
	return -1;
}

struct candidate *candidates_choose_champ(struct incoming *in,
	struct candidate *champ_last, struct scores *scores)
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
			if(candidate->deleted) continue;
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
