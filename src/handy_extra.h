#ifndef HANDY_EXTRA_H
#define HANDY_EXTRA_H

#include <openssl/md5.h>
#include <zlib.h>
#include "bfile.h"
#include "cmd.h"

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

enum send_e
{
	SEND_FATAL=-1,
	SEND_OK=0,
	SEND_ERROR=1
};

extern enum send_e send_whole_file_gzl(struct asfd *asfd, const char *datapth,
	int quick_read, uint64_t *bytes, const char *encpassword,
	struct cntr *cntr, int compression, struct BFILE *bfd,
	const char *extrameta, size_t elen,
	int key_deriv, uint64_t salt);

extern enum send_e send_whole_filel(struct asfd *asfd,
#ifdef HAVE_WIN32
	enum cmd cmd,
#endif
	const char *datapth,
	int quick_read, uint64_t *bytes, struct cntr *cntr,
	struct BFILE *bfd,
	const char *extrameta, size_t elen);

extern EVP_CIPHER_CTX *enc_setup(int encrypt, const char *encryption_password,
	int key_deriv, uint64_t salt);

extern char *get_endfile_str(uint64_t bytes, uint8_t *checksum);
extern int write_endfile(struct asfd *asfd, uint64_t bytes, uint8_t *checksum);

#endif
