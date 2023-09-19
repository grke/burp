#include "burp.h"
#include "alloc.h"
#include "conf.h"
#include "log.h"
#include "md5.h"

#if OPENSSL_VERSION_NUMBER < 0x30000000L

struct md5 *md5_alloc(
	const char *func
) {
	struct md5 *md5;
	if(!(md5=(struct md5 *)calloc_w(1, sizeof(struct md5), func)))
		return NULL;
	if(!(md5->ctx=(MD5_CTX *)calloc_w(1, sizeof(MD5_CTX), func)))
		md5_free(&md5);
	return md5;
}

void md5_free(
	struct md5 **md5
) {
	if(!md5 || !*md5)
		return;
	free_v((void **)&(*md5)->ctx);
	free_v((void **)md5);
}

int md5_init(
	struct md5 *md5
) {
	return MD5_Init(md5->ctx);
}

int md5_update(
	struct md5 *md5,
	const void *data,
	unsigned long len
) {
	return MD5_Update(md5->ctx, data, len);
}

int md5_final(
	struct md5 *md5,
	unsigned char *md
) {
	return MD5_Final(md, md5->ctx);
}

#else

struct md5 *md5_alloc(
        const char *func
) {
	struct md5 *md5;
	if(!(md5=(struct md5 *)calloc_w(1, sizeof(struct md5), func)))
		return NULL;
	if((md5->ctx=EVP_MD_CTX_create()))
	{
#ifdef UTEST
		alloc_count++;
#endif
		return md5;
	}
	log_oom_w(__func__, func);
	md5_free(&md5);
	return NULL;
}

void md5_free(
	struct md5 **md5
) {
	if(!md5 || !*md5)
		return;
	if ((*md5)->ctx)
	{
		EVP_MD_CTX_free((*md5)->ctx);
#ifdef UTEST
		free_count++;
#endif
	}
	free_v((void **)md5);
	*md5=NULL;
}

int md5_init(
	struct md5 *md5
) {
	return EVP_DigestInit_ex(md5->ctx, EVP_md5(), NULL);
}

int md5_update(
	struct md5 *md5,
	const void *data,
	unsigned long len
) {
	return EVP_DigestUpdate(md5->ctx, data, len);
}

int md5_final(
	struct md5 *md5,
	unsigned char *md
) {
	return EVP_DigestFinal_ex(md5->ctx, md, NULL);
}

#endif
