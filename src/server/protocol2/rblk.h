#ifndef _RBLK_H
#define _RBLK_H

#include <uthash.h>

extern void rblks_init(ssize_t rblk_memory_max);
extern void rblks_free(void);
extern int rblk_retrieve_data(struct asfd *asfd, struct cntr *cntr,
	struct blk *blk, const char *datpath);

#endif
