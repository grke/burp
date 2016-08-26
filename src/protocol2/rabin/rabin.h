#ifndef __RABIN_H
#define __RABIN_H

struct asfd;
struct blist;
struct conf;
struct sbuf;

extern int blks_generate_init(void);
extern void blks_generate_free(void);
extern int blks_generate(struct sbuf *sb, struct blist *blist,
	int just_opened);
extern int blk_verify_fingerprint(uint64_t fingerprint,
	char *data, size_t length);

#endif
