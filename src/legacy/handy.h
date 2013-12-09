#ifndef HANDY_LEGACY_H
#define HANDY_LEGACY_H

#include "prepend.h"

#include <openssl/md5.h>
#include <zlib.h>

#include "bfile.h"

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

extern int open_file_for_sendl(BFILE *bfd, FILE **fp, const char *fname, int64_t winattr, size_t *datalen, struct cntr *cntr);

extern int close_file_for_sendl(BFILE *bfd, FILE **fp);

extern int send_whole_file_gzl(const char *fname, const char *datapth, int quick_read, unsigned long long *bytes, const char *encpassword, struct cntr *cntr, int compression, BFILE *bfd, FILE *fp, const char *extrameta, size_t elen, size_t datalen);

extern int send_whole_filel(char cmd, const char *fname, const char *datapth, int quick_read, unsigned long long *bytes, struct cntr *cntr, BFILE *bfd, FILE *fp, const char *extrameta, size_t elen, size_t datalen);

extern EVP_CIPHER_CTX *enc_setup(int encrypt, const char *encryption_password);

extern char *get_endfile_str(unsigned long long bytes, unsigned char *checksum);
extern int write_endfile(unsigned long long bytes, unsigned char *checksum);

#endif
