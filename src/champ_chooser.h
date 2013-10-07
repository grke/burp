#ifndef __CHAMP_CHOOSER_H
#define __CHAMP_CHOOSER_H

struct candidate
{
	char *path;
	uint16_t *score;
};

extern int champ_chooser_init(const char *sparse, struct config *conf);

extern int deduplicate(struct blist *iblist, struct dpth *dpth, struct config *conf, uint64_t *wrap_up);
extern int deduplicate_maybe(struct blist *iblist, struct blk *blk, struct dpth *dpth, struct config *conf, uint64_t *wrap_up);

#endif
