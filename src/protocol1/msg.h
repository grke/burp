#ifndef _MSG_PROTOCOL1_H
#define _MSG_PROTOCOL1_H

#include <zlib.h>
#include "../bfile.h"

extern int transfer_gzfile_inl(struct asfd *asfd,
	struct sbuf *sb, const char *path, BFILE *bfd,
	uint64_t *rcvd, uint64_t *sent,
	const char *encpassword, int enccompressed,
	struct cntr *cntr, char **metadata);

#endif
