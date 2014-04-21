#include <assert.h>

#include "include.h"

struct scores *scores=NULL;

struct scores *scores_alloc(void)
{
	struct scores *scores;
	if((scores=(struct scores *)calloc(1, sizeof(struct scores))))
		return scores;
	log_out_of_memory(__func__);
	return NULL;
}

/*
static void dump_scores(const char *msg, struct scores *scores, int len)
{
	int a;
printf("%p\n", scores);
//printf("%d %d\n", len, scores->size);
	for(a=0; a<len; a++)
	{
		printf("%s %d %p: %d\n",
			msg, a, &(scores->scores[a]), scores->scores[a]);
	}
}
*/

// Return -1 or error, 0 on OK.
int scores_grow(struct scores *scores, int max_score_index, size_t count)
{
	if(!max_score_index || !count) return 0;
	//printf("grow scores to %lu\n", max_score_index*count);
	scores->size=max_score_index*count;
	if((scores->scores=(uint16_t *)realloc(scores->scores,
		sizeof(uint16_t)*scores->size)))
			return 0;
	log_out_of_memory(__func__);
	return -1;
}

void scores_reset(struct scores *scores, int score_index)
{
	if(!scores->scores || !scores->size) return;
	memset(scores->scores[score_index],
		0, sizeof(scores->scores[0])*candidate_len);
}

void scores_reset_all(struct scores *scores)
{
	if(!scores->scores || !scores->size) return;
	memset(scores->scores, 0, sizeof(scores->scores[0])*scores->size);
}
