#ifndef HANDY_PROTOCOL1_H
#define HANDY_PROTOCOL1_H

#include <openssl/md5.h>
#include <zlib.h>
#include "../bfile.h"
#include "../cmd.h"

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

extern int send_whole_file_gzl(struct asfd *asfd,
	const char *fname, const char *datapth,
	int quick_read, uint64_t *bytes, const char *encpassword,
	struct cntr *cntr, int compression, BFILE *bfd,
	const char *extrameta, size_t elen);

extern int send_whole_filel(struct asfd *asfd,
	enum cmd cmd, const char *datapth,
	int quick_read, uint64_t *bytes, struct cntr *cntr,
	BFILE *bfd,
	const char *extrameta, size_t elen);

extern EVP_CIPHER_CTX *enc_setup(int encrypt, const char *encryption_password);

extern char *get_endfile_str(uint64_t bytes, uint8_t *checksum);
extern int write_endfile(struct asfd *asfd, uint64_t bytes, uint8_t *checksum);

#endif
