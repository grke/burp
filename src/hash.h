#ifndef __HASH_H
#define __HASH_H

#include <stdint.h>
#include <uthash.h>

#include "dpth.h"

#define SIG_MAX	0xFFF

typedef struct strong_entry strong_entry_t;

struct strong_entry
{
	char strong[32+1];
	strong_entry_t *next;
	char *path;
};

struct weak_entry
{
	uint64_t weak;
	struct strong_entry *strong;
	UT_hash_handle hh;
};

extern struct weak_entry *hash_table;

extern struct weak_entry   *find_weak_entry(uint64_t weak);
extern struct strong_entry *find_strong_entry(struct weak_entry *weak_entry, const char *strong);
extern struct weak_entry   *add_weak_entry(uint64_t weakint);
extern struct strong_entry *add_strong_entry(struct weak_entry *weak_entry, const char *strong, const char *path);

extern void hash_delete_all(void);
extern int hash_load(const char *champ, struct config *conf);

#endif
