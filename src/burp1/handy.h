#ifndef HANDY_BURP1_H
#define HANDY_BURP1_H

#include <openssl/md5.h>
#include <zlib.h>

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

extern int open_file_for_sendl(struct asfd *asfd,
	BFILE *bfd, const char *fname,
	int64_t winattr, size_t *datalen, int atime, struct conf *conf);

extern int close_file_for_sendl(BFILE *bfd, struct asfd *asfd);

extern int send_whole_file_gzl(struct asfd *asfd,
	const char *fname, const char *datapth,
	int quick_read, unsigned long long *bytes, const char *encpassword,
	struct conf *conf, int compression, BFILE *bfd,
	const char *extrameta, size_t elen, size_t datalen);

extern int send_whole_filel(struct asfd *asfd,
	char cmd, const char *fname, const char *datapth,
	int quick_read, unsigned long long *bytes, struct conf *conf,
	BFILE *bfd,
	const char *extrameta, size_t elen, size_t datalen);

extern EVP_CIPHER_CTX *enc_setup(int encrypt, const char *encryption_password);

extern char *get_endfile_str(unsigned long long bytes, uint8_t *checksum);
extern int write_endfile(struct asfd *asfd,
	unsigned long long bytes, uint8_t *checksum);

#endif
