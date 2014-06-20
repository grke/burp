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

struct hash_strong *hash_strong_add(struct hash_weak *hash_weak,
	uint8_t *md5sum, uint8_t *savepath)
{
	struct hash_strong *newstrong;
	if(!(newstrong=(struct hash_strong *)
		malloc_w(sizeof(struct hash_strong), __func__)))
			return NULL;
	memcpy(newstrong->savepath, savepath, SAVE_PATH_LEN);
	memcpy(newstrong->md5sum, md5sum, MD5_DIGEST_LENGTH);
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

static int process_sig(char cmd, const char *buf, unsigned int s)
{
	static uint64_t fingerprint;
	static struct hash_weak *hash_weak;
	static uint8_t md5sum[MD5_DIGEST_LENGTH];
	static uint8_t savepath[SAVE_PATH_LEN];

	if(split_sig_with_save_path(buf, s, &fingerprint, md5sum, savepath))
		return -1;

	hash_weak=hash_weak_find(fingerprint);

	// Add to hash table.
	if(!hash_weak && !(hash_weak=hash_weak_add(fingerprint)))
		return -1;
	if(!hash_strong_find(hash_weak, md5sum))
	{
		if(!(hash_weak->strong=hash_strong_add(hash_weak,
			md5sum, savepath))) return -1;
	}

	return 0;
}

int hash_load(const char *champ, struct conf *conf)
{
	int ret=-1;
	char cmd='\0';
	char *path=NULL;
	size_t bytes;
// FIX THIS.
	char buf[1048576];
	unsigned int s;
	gzFile zp=NULL;

	if(!(path=prepend_s(conf->directory, champ))
	  || !(zp=gzopen_file(path, "rb")))
		goto end;
//printf("hash load %s\n", path);

	while((bytes=gzread(zp, buf, 5)))
	{
		if(bytes!=5)
		{
			logp("Short read: %d wanted: %d\n", (int)bytes, 5);
			goto end;
		}
		buf[6]=0;
		if((sscanf(buf, "%c%04X", &cmd, &s))!=2)
		{
			logp("sscanf failed in %s: %s\n", __func__, buf);
			goto end;
		}

		if((bytes=gzread(zp, buf, s+1))!=s+1)
		{
			logp("Short read: %d wanted: %d\n", (int)bytes, (int)s);
			goto end;
		}

		if(cmd==CMD_SIG)
		{
			buf[s]=0;
			if(process_sig(cmd, buf, s))
				goto end;
		}
	}

	ret=0;
end:
	if(path) free(path);
	gzclose_fp(&zp);
	return ret;
}
