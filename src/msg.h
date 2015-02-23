#ifndef _MSG_ROUTINES
#define _MSG_ROUTINES

#include <zlib.h>
#include "bfile.h"
#include "cmd.h"

extern int send_msg_fp(FILE *fp, enum cmd cmd, const char *buf, size_t s);
extern int send_msg_zp(gzFile zp, enum cmd cmd, const char *buf, size_t s);
extern int transfer_gzfile_in(struct asfd *asfd, const char *path, BFILE *bfd,
	unsigned long long *rcvd, unsigned long long *sent, struct cntr *cntr);
extern FILE *open_file(const char *fname, const char *mode);
extern gzFile gzopen_file(const char *fname, const char *mode);

#endif
