#ifndef HANDY_BURP1_H
#define HANDY_BURP1_H

#include <openssl/md5.h>
#include <zlib.h>

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

extern int open_file_for_sendl(struct asfd *asfd,
	struct BFILE *bfd, FILE **fp, const char *fname,
	int64_t winattr, size_t *datalen, int atime, struct conf *conf);

extern int close_file_for_sendl(struct BFILE *bfd,
	FILE **fp, struct asfd *asfd);

extern int send_whole_file_gzl(struct asfd *asfd,
	const char *fname, const char *datapth,
	int quick_read, unsigned long long *bytes, const char *encpassword,
	struct conf *conf, int compression, struct BFILE *bfd, FILE *fp,
	const char *extrameta, size_t elen, size_t datalen);

extern int send_whole_filel(struct asfd *asfd,
	char cmd, const char *fname, const char *datapth,
	int quick_read, unsigned long long *bytes, struct conf *conf,
	struct BFILE *bfd, FILE *fp,
	const char *extrameta, size_t elen, size_t datalen);

extern EVP_CIPHER_CTX *enc_setup(int encrypt, const char *encryption_password);

extern int write_endfile_burp1(struct asfd *asfd,
	unsigned long long bytes, unsigned char *checksum);

#endif
