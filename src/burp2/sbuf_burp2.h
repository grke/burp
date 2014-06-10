#ifndef _SBUF_BURP2_H
#define _SBUF_BURP2_H

#include "include.h"

// Structure used only by burp2 style functionality.
struct burp2
{
	ssize_t bytes_read;

	uint64_t index;
	uint32_t encryption;

	struct BFILE bfd;

	struct blk *bstart;
	struct blk *bend;
	struct blk *bsighead;
};

extern struct burp2 *sbuf_burp2_alloc(void);
extern void sbuf_burp2_free_content(struct burp2 *burp2);

#endif
