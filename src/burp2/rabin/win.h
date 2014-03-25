#ifndef __RABIN_WIN_H
#define __RABIN_WIN_H

// The sliding window.
struct win
{
	char *data;
	unsigned int pos;
	uint64_t total_bytes;
	uint64_t checksum;	// Rolling checksum.
	int finished;
};

extern struct win *win_alloc(struct rconf *rconf);
extern void win_free(struct win *win);

#endif
