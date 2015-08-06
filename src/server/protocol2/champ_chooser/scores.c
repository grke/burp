#include "../../../burp.h"
#include "../../../alloc.h"
#include "scores.h"

struct scores *scores_alloc(void)
{
	return (struct scores *)calloc_w(1, sizeof(struct scores), __func__);
}

static void scores_free_content(struct scores *scores)
{
	if(!scores) return;
	free_v((void **)&scores->scores);
}

void scores_free(struct scores **scores)
{
	if(!scores) return;
	scores_free_content(*scores);
	free_v((void **)scores);
}

// Return -1 or error, 0 on OK.
int scores_grow(struct scores *scores, size_t count)
{
	if(!scores || !count) return 0;
	scores->size=count;
	if(!(scores->scores=(uint16_t *)realloc_w(scores->scores,
		sizeof(uint16_t)*scores->size, __func__)))
			return -1;
	return 0;
}

void scores_reset(struct scores *scores)
{
	if(!scores
	  || !scores->scores
	  || !scores->size)
		return;
	memset(scores->scores, 0, sizeof(scores->scores[0])*scores->size);
}
