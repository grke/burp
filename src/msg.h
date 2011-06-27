#ifndef _MSG_ROUTINES
#define _MSG_ROUTINES

#include <zlib.h>
#include "find.h"

extern int send_msg_fp(FILE *fp, char cmd, const char *buf, size_t s);
extern int send_msg_zp(gzFile zp, char cmd, const char *buf, size_t s);
extern int transfer_gzfile_in(BFILE *bfd, FILE *fp, char **bytes, const char *encpassword, struct cntr *cntr, char **metadata);
extern FILE *open_file(const char *fname, const char *mode);
extern gzFile gzopen_file(const char *fname, const char *mode);

#endif
