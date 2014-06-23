#include "include.h"

struct hash_weak *hash_table=NULL;

struct hash_weak *hash_weak_find(uint64_t weak)
{
	struct hash_weak *hash_weak;
	HASH_FIND_INT(hash_table, &weak, hash_weak);
	return hash_weak;
}

struct hash_strong *hash_strong_find(struct hash_weak *hash_weak,
	uint8_t *md5sum)
{
	struct hash_strong *s;
	for(s=hash_weak->strong; s; s=s->next)
		if(!memcmp(s->md5sum, md5sum, MD5_DIGEST_LENGTH)) return s;
	return NULL;
}

struct hash_weak *hash_weak_add(uint64_t weakint)
{
	struct hash_weak *newweak;
	if(!(newweak=(struct hash_weak *)malloc(sizeof(struct hash_weak))))
	{
		log_out_of_memory(__func__);
		return NULL;
	}
	newweak->weak=weakint;
//logp("addweak: %016lX\n", weakint);
	newweak->strong=NULL;
	HASH_ADD_INT(hash_table, weak, newweak);
	return newweak;
}

static struct hash_strong *hash_strong_add(struct hash_weak *hash_weak,
	struct blk *blk)
{
	struct hash_strong *newstrong;
	if(!(newstrong=(struct hash_strong *)
		malloc_w(sizeof(struct hash_strong), __func__)))
			return NULL;
	memcpy(newstrong->savepath, blk->savepath, SAVE_PATH_LEN);
	memcpy(newstrong->md5sum, blk->md5sum, MD5_DIGEST_LENGTH);
	newstrong->next=hash_weak->strong;
	return newstrong;
}

static void hash_strongs_free(struct hash_strong *shead)
{
	static struct hash_strong *s;
	s=shead;
	while(shead)
	{
		s=shead;
		shead=shead->next;
		free(s);
	}
}

void hash_delete_all(void)
{
	struct hash_weak *tmp;
	struct hash_weak *hash_weak;

	HASH_ITER(hh, hash_table, hash_weak, tmp)
	{
		HASH_DEL(hash_table, hash_weak);
		hash_strongs_free(hash_weak->strong);
		free(hash_weak);
	}
}

static int process_sig(struct iobuf *rbuf)
{
	static struct hash_weak *hash_weak;
	static struct blk *blk=NULL;

	if(!blk && !(blk=blk_alloc())) return -1;

	if(split_sig_from_manifest(rbuf, blk))
		return -1;

	hash_weak=hash_weak_find(blk->fingerprint);

	// Add to hash table.
	if(!hash_weak && !(hash_weak=hash_weak_add(blk->fingerprint)))
		return -1;
	if(!hash_strong_find(hash_weak, blk->md5sum))
	{
		if(!(hash_weak->strong=hash_strong_add(hash_weak, blk)))
			return -1;
	}

	return 0;
}

int hash_load(const char *champ, struct conf *conf)
{
	int ret=-1;
	char *path=NULL;
	size_t bytes;
	gzFile zp=NULL;
	static struct iobuf *rbuf=NULL;
	static unsigned int buf_alloc=0;

	if(!(path=prepend_s(conf->directory, champ))
	  || !(zp=gzopen_file(path, "rb")))
		goto end;

	if(!rbuf && !(rbuf=iobuf_alloc()))
		goto end;

	if(!buf_alloc)
	{
		buf_alloc=8;
		if(!(rbuf->buf=(char *)malloc_w(buf_alloc, __func__)))
			goto end;
	}

	while((bytes=gzread(zp, rbuf->buf, 5)))
	{
		if(bytes!=5)
		{
			logp("Short read: %d wanted: %d\n", (int)bytes, 5);
			goto end;
		}
		rbuf->buf[6]=0;
		if((sscanf(rbuf->buf, "%c%04lX", &rbuf->cmd, &rbuf->len))!=2)
		{
			logp("sscanf failed in %s: %s\n", __func__, rbuf->buf);
			goto end;
		}
		if(rbuf->len+1>buf_alloc)
		{
			buf_alloc=rbuf->len+1;
			if(!(rbuf->buf=(char *)realloc_w(rbuf->buf,
				buf_alloc, __func__))) goto end;
		}

		if((bytes=gzread(zp, rbuf->buf, rbuf->len+1))!=rbuf->len+1)
		{
			logp("Short read: %d wanted: %d\n",
				(int)bytes, (int)(rbuf->len+1));
			goto end;
		}

		if(rbuf->cmd==CMD_SIG)
		{
			rbuf->buf[rbuf->len]=0;
			if(process_sig(rbuf)) goto end;
		}
	}

	ret=0;
end:
	if(path) free(path);
	gzclose_fp(&zp);
	return ret;
}
