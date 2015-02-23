#include "include.h"

struct sparse
{
	uint64_t fingerprint;
	size_t size;
	struct candidate **candidates;
	UT_hash_handle hh;
};

extern struct sparse *sparse_find(uint64_t *fingerprint);
extern int sparse_add_candidate(uint64_t *fingerprint,
	struct candidate *candidate);
