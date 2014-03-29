#include "include.h"

struct weak_entry *hash_table=NULL;

struct weak_entry *find_weak_entry(uint64_t weak)
{
	struct weak_entry *weak_entry;
	HASH_FIND_INT(hash_table, &weak, weak_entry);
	return weak_entry;
}

struct strong_entry *find_strong_entry(struct weak_entry *weak_entry, const char *strong)
{
	struct strong_entry *s;
	for(s=weak_entry->strong; s; s=s->next)
		if(!strcmp(s->strong, strong)) return s;
	return NULL;
}

struct weak_entry *add_weak_entry(uint64_t weakint)
{
	struct weak_entry *newweak;
	if(!(newweak=(struct weak_entry *)malloc(sizeof(struct weak_entry))))
	{
		log_out_of_memory(__FUNCTION__);
		return NULL;
	}
	newweak->weak=weakint;
//logp("addweak: %016lX\n", weakint);
	newweak->strong=NULL;
	HASH_ADD_INT(hash_table, weak, newweak);
	return newweak;
}

struct strong_entry *add_strong_entry(struct weak_entry *weak_entry, const char *strong, const char *path)
{
	struct strong_entry *newstrong;
	if(!(newstrong=(struct strong_entry *)malloc(sizeof(struct strong_entry)))
	  || !(newstrong->path=strdup(path)))
	{
		log_out_of_memory(__FUNCTION__);
		return NULL;
	}
	snprintf(newstrong->strong, sizeof(newstrong->strong), "%s", strong);
	newstrong->next=weak_entry->strong;
	return newstrong;
}

static void strong_entries_free(struct strong_entry *shead)
{
	static struct strong_entry *s;
	s=shead;
	while(shead)
	{
		s=shead;
		shead=shead->next;
		free(s->path);
		free(s);
	}
}

void hash_delete_all(void)
{
	struct weak_entry *tmp;
	struct weak_entry *weak_entry;

	HASH_ITER(hh, hash_table, weak_entry, tmp)
	{
		HASH_DEL(hash_table, weak_entry);
		strong_entries_free(weak_entry->strong);
		free(weak_entry);
	}
}

static int process_sig(char cmd, const char *buf, unsigned int s)
{
	static uint64_t weakint;
	static struct weak_entry *weak_entry;
	static char weak[16+1];
	static char strong[32+1];
	static char save_path[128+1];

	if(split_sig_with_save_path(buf, s, weak, strong, save_path))
		return -1;

	weakint=strtoull(weak, 0, 16);

	weak_entry=find_weak_entry(weakint);

	// Add to hash table.
	if(!weak_entry && !(weak_entry=add_weak_entry(weakint)))
		return -1;
	if(!find_strong_entry(weak_entry, strong))
	{
		if(!(weak_entry->strong=add_strong_entry(weak_entry,
			strong, save_path))) return -1;
	}

	return 0;
}

int hash_load(const char *champ, struct conf *conf)
{
	int ret=-1;
	char cmd='\0';
	char *path=NULL;
	size_t bytes;
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
			logp("sscanf failed in %s: %s\n", __FUNCTION__, buf);
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
