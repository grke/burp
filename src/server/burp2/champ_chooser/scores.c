#include <assert.h>

#include "include.h"

struct scores *scores=NULL;

struct scores *scores_alloc(void)
{
	return (struct scores *)calloc_w(1, sizeof(struct scores), __func__);
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
int scores_grow(struct scores *scores, size_t count)
{
	if(!count) return 0;
	scores->size=count;
	if(!(scores->scores=(uint16_t *)realloc_w(scores->scores,
		sizeof(uint16_t)*scores->size, __func__)))
			return -1;
	return 0;
}

void scores_reset(struct scores *scores)
{
	if(!scores->scores || !scores->size)
	{
		return;
	}
	memset(scores->scores, 0, sizeof(scores->scores[0])*scores->size);
}
