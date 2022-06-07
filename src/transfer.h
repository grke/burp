#ifndef _TRANSFER_H
#define _TRANSFER_H

#include <zlib.h>
#include "bfile.h"

extern int transfer_gzfile_inl(struct asfd *asfd,
#ifdef HAVE_WIN32
	struct sbuf *sb,
#endif
	struct BFILE *bfd,
	uint64_t *rcvd, uint64_t *sent,
	const char *encpassword, int enccompressed,
	struct cntr *cntr, char **metadata,
	int key_deriv, uint64_t salt);

#endif
