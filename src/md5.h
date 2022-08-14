#ifndef _BURP_MD5_H
#define _BURP_MD5_H

#include <openssl/md5.h>

/* Not ready yet
#if OPENSSL_VERSION_NUMBER < 0x30000000L
*/
#if 1
struct md5 {
	MD5_CTX *ctx;
};
#else
#include <openssl/evp.h>
struct md5 {
	EVP_MD_CTX *ctx;
};
#endif

extern struct md5 *md5_alloc(
	const char *func
);
extern void md5_free(
	struct md5 **md5
);
extern int md5_init(
	struct md5 *md5
);
extern int md5_update(
	struct md5 *md5,
	const void *data,
	unsigned long len
);
extern int md5_final(
	struct md5 *md5,
	unsigned char *md
);

#endif
