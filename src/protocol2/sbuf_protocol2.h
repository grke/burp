#ifndef _SBUF_PROTOCOL2_H
#define _SBUF_PROTOCOL2_H

#include "../burp.h"
#include "../bfile.h"

// Structure used only by protocol2 style functionality.
struct protocol2
{
	ssize_t bytes_read;

	uint64_t index;

	struct BFILE bfd;

	struct blk *bstart;
	struct blk *bend;
	struct blk *bsighead;
};

extern struct protocol2 *sbuf_protocol2_alloc(void);
extern void sbuf_protocol2_free_content();

#endif
