#include "../burp.h"
#include "blk.h"
#include "../alloc.h"
#include "../hexmap.h"
#include "../iobuf.h"
#include "../log.h"
#include "../protocol2/rabin/rabin.h"
#include "rabin/rconf.h"

struct blk *blk_alloc(void)
{
	return (struct blk *)calloc_w(1, sizeof(struct blk), __func__);
}

struct blk *blk_alloc_with_data(uint32_t max_data_length)
{
	struct blk *blk=NULL;
	if(!(blk=blk_alloc())
	  || !(blk->data=(char *)
		calloc_w(1, sizeof(char)*max_data_length, __func__)))
			goto end;
	return blk;
end:
	blk_free(&blk);
	return NULL;
}

void blk_free_content(struct blk *blk)
{
	if(!blk) return;
	free_w(&blk->data);
}

void blk_free(struct blk **blk)
{
	if(!blk || !*blk) return;
	blk_free_content(*blk);
	free_v((void **)blk);
}

static int md5_generation(uint8_t md5sum[], const char *data, uint32_t length)
{
	MD5_CTX md5;
	if(!MD5_Init(&md5)
	  || !MD5_Update(&md5, data, length)
	  || !MD5_Final(md5sum, &md5))
	{
		logp("MD5 generation failed.\n");
		return -1;
	}
	return 0;
}

int blk_md5_update(struct blk *blk)
{
	return md5_generation(blk->md5sum, blk->data, blk->length);
}

int blk_is_zero_length(struct blk *blk)
{
	return !blk->fingerprint // All zeroes.
	  && !memcmp(blk->md5sum, md5sum_of_empty_string, MD5_DIGEST_LENGTH);
}

int blk_verify(uint64_t fingerprint, uint8_t *md5sum,
	char *data, size_t length)
{
	uint8_t md5sum_new[MD5_DIGEST_LENGTH];

	switch(blk_verify_fingerprint(fingerprint, data, length))
	{
		case 1: break; // Match.
		case 0: return 0; // Did not match.
		default: return -1;
	}

	if(md5_generation(md5sum_new, data, length))
		return -1;
	if(!memcmp(md5sum_new, md5sum, MD5_DIGEST_LENGTH))
		return 1;

	return 0;
}

#define HOOK_MASK       0xF000000000000000ULL

int blk_fingerprint_is_hook(struct blk *blk)
{
	return (blk->fingerprint&HOOK_MASK)==HOOK_MASK;
}

#define ETOH	le64toh
#define HTOE	htole64
// Can set it the other way round to test that endian logic works, but for
// real use we will always be going host->little little->host.
//#define ETOH	be64toh
//#define HTOE	htobe64

static void set_fingerprint(struct blk *blk, struct iobuf *iobuf)
{
	blk->fingerprint=ETOH(*(uint64_t *)iobuf->buf);
}

static void set_sig(struct blk *blk, struct iobuf *iobuf)
{
	set_fingerprint(blk, iobuf);
	memcpy(blk->md5sum, iobuf->buf+8, 8);
	memcpy(blk->md5sum+8, iobuf->buf+16, 8);
}

static void set_savepath(struct blk *blk, struct iobuf *iobuf, size_t offset)
{
	blk->savepath=ETOH(*(uint64_t *)(iobuf->buf+offset));
}

int blk_set_from_iobuf_sig(struct blk *blk, struct iobuf *iobuf)
{
	if(iobuf->len!=24)
	{
		logp("Signature wrong length: %lu!=24\n",
			(unsigned long)iobuf->len);
		return -1;
	}
	set_sig(blk, iobuf);
	return 0;
}

int blk_set_from_iobuf_sig_and_savepath(struct blk *blk, struct iobuf *iobuf)
{
	if(iobuf->len!=32)
	{
		logp("Signature with save_path wrong length: %lu!=32\n",
			(unsigned long)iobuf->len);
		return -1;
	}
	set_sig(blk, iobuf);
	set_savepath(blk, iobuf, 24 /* offset */);
	return 0;
}

int blk_set_from_iobuf_fingerprint(struct blk *blk, struct iobuf *iobuf)
{
	if(iobuf->len!=sizeof(blk->fingerprint))
	{
		logp("Fingerprint wrong length: %lu!=%lu\n",
			(unsigned long)iobuf->len,
			(unsigned long)sizeof(blk->fingerprint));
		return -1;
	}
	set_fingerprint(blk, iobuf);
	return 0;
}

int blk_set_from_iobuf_savepath(struct blk *blk, struct iobuf *iobuf)
{
	if(iobuf->len!=sizeof(blk->savepath))
	{
		logp("Save path wrong length: %lu!=%lu\n",
			(unsigned long)iobuf->len,
			(unsigned long)sizeof(blk->savepath));
		return -1;
	}
	set_savepath(blk, iobuf, 0 /* offset */);
	return 0;
}

int blk_set_from_iobuf_index_and_savepath(struct blk *blk, struct iobuf *iobuf)
{
	if(iobuf->len!=16)
	{
		logp("File number and savepath with wrong length: %lu!=16\n",
			(unsigned long)iobuf->len);
		return -1;
	}
	blk->index=ETOH(*(uint64_t *)iobuf->buf);
	blk->savepath=ETOH(*(uint64_t *)(iobuf->buf+8));
	return 0;
}

int blk_set_from_iobuf_wrap_up(struct blk *blk, struct iobuf *iobuf)
{
	if(iobuf->len!=sizeof(blk->index))
	{
		logp("Wrap up with wrong length: %lu!=%lu\n",
			(unsigned long)iobuf->len,
			(unsigned long)sizeof(blk->index));
		return -1;
	}
	blk->index=ETOH(*(uint64_t *)iobuf->buf);
	return 0;
}

void blk_to_iobuf_sig(struct blk *blk, struct iobuf *iobuf)
{
	static union { char c[24]; uint64_t v[3]; } buf;
	buf.v[0]=HTOE(blk->fingerprint);
	memcpy(&buf.c[8], blk->md5sum, 8);
	memcpy(&buf.c[16], blk->md5sum+8, 8);
	iobuf_set(iobuf, CMD_SIG, buf.c, sizeof(buf));
}

void blk_to_iobuf_sig_and_savepath(struct blk *blk, struct iobuf *iobuf)
{
	static union { char c[32]; uint64_t v[4]; } buf;
	buf.v[0]=HTOE(blk->fingerprint);
	memcpy(&buf.c[8], blk->md5sum, 8);
	memcpy(&buf.c[16], blk->md5sum+8, 8);
	buf.v[3]=HTOE(blk->savepath);
	iobuf_set(iobuf, CMD_SIG, buf.c, sizeof(buf));
}

static void to_iobuf_uint64(struct iobuf *iobuf, enum cmd cmd, uint64_t val)
{
	static union { char c[8]; uint64_t v; } buf;
	buf.v=HTOE(val);
	iobuf_set(iobuf, cmd, buf.c, sizeof(buf));
}

void blk_to_iobuf_fingerprint(struct blk *blk, struct iobuf *iobuf)
{
	to_iobuf_uint64(iobuf, CMD_FINGERPRINT, blk->fingerprint);
}

void blk_to_iobuf_savepath(struct blk *blk, struct iobuf *iobuf)
{
	to_iobuf_uint64(iobuf, CMD_SAVE_PATH, blk->savepath);
}

void blk_to_iobuf_index_and_savepath(struct blk *blk, struct iobuf *iobuf)
{
	static union { char c[16]; uint64_t v[2]; } buf;
	buf.v[0]=HTOE(blk->index);
	buf.v[1]=HTOE(blk->savepath);
	iobuf_set(iobuf, CMD_SIG, buf.c, sizeof(buf));
}

void blk_to_iobuf_wrap_up(struct blk *blk, struct iobuf *iobuf)
{
	to_iobuf_uint64(iobuf, CMD_WRAP_UP, blk->index);
}

int to_fzp_fingerprint(struct fzp *fzp, uint64_t fingerprint)
{
	static struct iobuf wbuf;
	to_iobuf_uint64(&wbuf, CMD_FINGERPRINT, fingerprint);
	return iobuf_send_msg_fzp(&wbuf, fzp);
}
