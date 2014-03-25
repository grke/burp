#ifndef HANDY_BURP1_H
#define HANDY_BURP1_H

#include <openssl/md5.h>
#include <zlib.h>

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

extern int open_file_for_sendl(BFILE *bfd, FILE **fp, const char *fname,
	int64_t winattr, size_t *datalen, struct conf *conf);

extern int close_file_for_sendl(BFILE *bfd, FILE **fp);

extern int send_whole_file_gzl(const char *fname, const char *datapth,
	int quick_read, unsigned long long *bytes, const char *encpassword,
	struct conf *conf, int compression, BFILE *bfd, FILE *fp,
	const char *extrameta, size_t elen, size_t datalen);

extern int send_whole_filel(char cmd, const char *fname, const char *datapth,
	int quick_read, unsigned long long *bytes, struct conf *conf,
	BFILE *bfd, FILE *fp,
	const char *extrameta, size_t elen, size_t datalen);

extern EVP_CIPHER_CTX *enc_setup(int encrypt, const char *encryption_password);

extern char *get_endfile_str(unsigned long long bytes, unsigned char *checksum);
extern int write_endfile(unsigned long long bytes, unsigned char *checksum);

#endif
