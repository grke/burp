#ifndef _CHAMP_CHOOSER_CANDIDATE_H
#define _CHAMP_CHOOSER_CANDIDATE_H

enum cand_ret
{
	CAND_RET_TEMP=-2,
	CAND_RET_PERM=-1,
	CAND_RET_OK=0
};

struct candidate
{
	uint16_t *score;
	uint16_t deleted;
	char *path;
};

extern struct candidate **candidates;
extern size_t candidates_len;

extern struct candidate *candidate_alloc(void);
extern void candidate_free_content(struct candidate *c);
extern void candidate_free(struct candidate **c);
extern void candidates_set_score_pointers(struct candidate **candidates,
	size_t clen, struct scores *scores);
extern struct candidate *candidates_add_new(void);
extern enum cand_ret candidate_load(struct candidate *candidate,
	const char *path, struct scores *scores);
extern int candidate_add_fresh(const char *path, const char *directory,
	struct scores *scores);
extern struct candidate *candidates_choose_champ(struct incoming *in,
	struct candidate *champ_last, struct scores *scores);

#endif
