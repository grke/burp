#ifndef _SBUF_PROTOCOL2_H
#define _SBUF_PROTOCOL2_H

#include "include.h"

// Structure used only by protocol2 style functionality.
struct protocol2
{
	ssize_t bytes_read;

	uint64_t index;
	uint32_t encryption;

	BFILE bfd;

	struct blk *bstart;
	struct blk *bend;
	struct blk *bsighead;
};

extern struct protocol2 *sbuf_protocol2_alloc(void);
extern void sbuf_protocol2_free_content(struct protocol2 *protocol2);

#endif
