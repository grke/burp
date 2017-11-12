#ifndef _RBLK_H
#define _RBLK_H

extern int rblk_init(void);
extern void rblk_free(void);
extern char *rblk_get_fulldatpath(const char *datpath,
	struct blk *blk, uint16_t *datno);
extern int rblk_retrieve_data(const char *fulldatpath,
	struct blk *blk, uint16_t datno);

#endif
