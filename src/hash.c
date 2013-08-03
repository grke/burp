#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uthash.h>

#include "hash.h"
#include "log.h"

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

struct strong_entry *add_strong_entry(struct weak_entry *weak_entry, const char *strong, struct dpth *dpth)
{
	struct strong_entry *newstrong;
	if(!(newstrong=(struct strong_entry *)malloc(sizeof(struct strong_entry)))
	  || !(newstrong->path=strdup(dpth_mk(dpth))))
	{
		log_out_of_memory(__FUNCTION__);
		return NULL;
	}
	snprintf(newstrong->strong, sizeof(newstrong->strong), "%s", strong);
	newstrong->next=weak_entry->strong;
	return newstrong;
}
