#ifndef _RBLK_H
#define _RBLK_H

extern int rblk_init(void);
extern void rblk_free(void);
extern int rblk_retrieve_data(const char *datpath, struct blk *blk);

#endif
