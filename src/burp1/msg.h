#ifndef _MSG_BURP1_H
#define _MSG_BURP1_H

#include <zlib.h>
#include "include.h"

extern int transfer_gzfile_inl(struct asfd *asfd,
	struct sbuf *sb, const char *path, struct BFILE *bfd,
	FILE *fp, unsigned long long *rcvd, unsigned long long *sent,
	const char *encpassword, int enccompressed, struct cntr *cntr,
	char **metadata);

#endif
