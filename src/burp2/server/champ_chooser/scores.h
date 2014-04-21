#ifndef _SCORES_H
#define _SCORES_H

#include "include.h"

// Array to keep the scores. Candidates point at a unique entry in the
// array for their scores. Keeping them in an array like this means
// that all the scores can be reset quickly.
struct scores
{
	uint16_t *scores;
	size_t size;
};

extern struct scores *scores;

extern struct scores *scores_alloc(void);
extern int scores_grow(struct scores *scores,
	int max_score_index, size_t count);
extern void scores_reset_all(struct scores *scores);
extern void scores_reset(struct scores *scores, int score_index);

#endif
