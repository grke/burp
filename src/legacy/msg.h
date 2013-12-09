#ifndef _MSG_LEGACY_H
#define _MSG_LEGACY_H

#include <zlib.h>
#include "include.h"

extern int send_msg_fp(FILE *fp, char cmd, const char *buf, size_t s);
extern int send_msg_zp(gzFile zp, char cmd, const char *buf, size_t s);
extern int transfer_gzfile_in(struct sbufl *sb, const char *path, BFILE *bfd, FILE *fp, unsigned long long *rcvd, unsigned long long *sent, const char *encpassword, int enccompressed, struct cntr *cntr, char **metadata);
extern FILE *open_file(const char *fname, const char *mode);
extern gzFile gzopen_file(const char *fname, const char *mode);

#endif
