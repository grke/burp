#ifndef __CHAMP_CHOOSER_H
#define __CHAMP_CHOOSER_H

struct candidate
{
	char *path;
	uint16_t *score;
};

extern int champ_chooser_init(const char *sparse, struct conf *conf);
extern int add_fresh_candidate(const char *path, struct conf *conf);

extern int deduplicate(struct blk *blks, struct dpth *dpth, struct conf *conf, uint64_t *wrap_up);
extern int deduplicate_maybe(struct blk *blk, struct dpth *dpth, struct conf *conf, uint64_t *wrap_up);
extern int is_hook(const char *str);

extern int champ_test(struct conf *conf);

#endif
