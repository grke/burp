#include "include.h"

struct sparse
{
	uint64_t weak;
	size_t size;
	struct candidate **candidates;
	UT_hash_handle hh;
};

extern struct sparse *sparse_find(uint64_t weak);
extern int sparse_add_candidate(const char *weakstr,
	struct candidate *candidate);
