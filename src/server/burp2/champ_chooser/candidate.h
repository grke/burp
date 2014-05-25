#include <assert.h>

#include "include.h"

struct candidate
{
	char *path;
	uint16_t *score;
};

extern struct candidate **candidates;
extern size_t candidates_len;

extern struct candidate *candidate_alloc(void);
extern void candidates_set_score_pointers(struct candidate **candidates,
	size_t clen, struct scores *scores);
extern struct candidate *candidates_add_new(void);
extern int candidate_add_fresh(const char *path, struct conf *conf);
extern struct candidate *candidates_choose_champ(struct incoming *in,
	struct candidate *champ_last);
