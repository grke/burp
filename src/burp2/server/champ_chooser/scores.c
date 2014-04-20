#include <assert.h>

#include "include.h"

struct scores *scores=NULL;

struct scores *scores_alloc(void)
{
	struct scores *scores;
	if((scores=(struct scores *)calloc(1, sizeof(struct scores))))
		return scores;
	log_out_of_memory(__FUNCTION__);
	return NULL;
}

/*
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
*/

// Return -1 or error, 0 on OK.
int scores_grow(struct scores *scores, size_t count)
{
	if(!count) return 0;
	//printf("grow scores to %lu\n", count);
	scores->size=count;
	scores->allocated=count;
	if((scores->scores=(uint16_t *)realloc(scores->scores,
		sizeof(uint16_t)*scores->allocated)))
			return 0;
	log_out_of_memory(__FUNCTION__);
	return -1;
}

void scores_reset(struct scores *scores)
{
	if(!scores->scores || !scores->size) return;
	memset(scores->scores, 0, sizeof(scores->scores[0])*scores->size);
}
