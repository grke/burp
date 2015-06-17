#include "include.h"
#include "../../sbuf.h"

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
	if(!(newweak=(struct hash_weak *)
		malloc_w(sizeof(struct hash_weak), __func__)))
			return NULL;
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

static int process_sig(struct blk *blk)
{
	static struct hash_weak *hash_weak;

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

int hash_load(const char *champ, struct conf **confs)
{
	int ret=-1;
	char *path=NULL;
	struct fzp *fzp=NULL;
	struct sbuf *sb=NULL;
	static struct blk *blk=NULL;

	if(!(path=prepend_s(get_string(confs[OPT_DIRECTORY]), champ))
	  || !(fzp=fzp_gzopen(path, "rb")))
		goto end;

	if(!sb && !(sb=sbuf_alloc(confs))) goto end;
	if(!blk && !(blk=blk_alloc())) goto end;

	while(1)
	{
		sbuf_free_content(sb);
		switch(sbuf_fill_from_file(sb, fzp, blk, NULL, confs))
		{
			case 1: ret=0;
				goto end;
			case -1:
				goto end;
		}
		if(!blk->got_save_path) continue;
		if(process_sig(blk)) goto end;
		blk->got_save_path=0;
	}
end:
	if(path) free(path);
	fzp_close(&fzp);
	return ret;
}
