#ifndef _CHAMP_CHOOSER_SPARSE_H
#define _CHAMP_CHOOSER_SPARSE_H

#include <uthash.h>

struct sparse
{
	uint64_t fingerprint;
	size_t size;
	struct candidate **candidates;
	UT_hash_handle hh;
};

extern struct sparse *sparse_find(uint64_t *fingerprint);
extern void sparse_delete_all(void);
extern int sparse_add_candidate(uint64_t *fingerprint,
	struct candidate *candidate);
extern void sparse_delete_fresh_candidate(struct candidate *candidate);

#endif
