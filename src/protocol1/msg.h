#ifndef _MSG_PROTOCOL1_H
#define _MSG_PROTOCOL1_H

#include <zlib.h>
#include "../bfile.h"

extern int transfer_gzfile_inl(struct asfd *asfd,
	struct sbuf *sb, const char *path, BFILE *bfd,
	unsigned long long *rcvd, unsigned long long *sent,
	const char *encpassword, int enccompressed,
	struct conf **conf, char **metadata);

#endif
