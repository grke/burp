#ifndef __RABIN_WIN_H
#define __RABIN_WIN_H

#include "burp.h"
#include "protocol2/rabin/rconf.h"

// The sliding window.
struct win
{
	unsigned char *data;
	unsigned int pos;
	uint64_t checksum;	// Rolling checksum.
};

extern struct win *win_alloc(struct rconf *rconf);
extern void win_free(struct win **win);

#endif
