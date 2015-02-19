#include "include.h"

static struct sparse *sparse_table=NULL;

static struct sparse *sparse_add(uint64_t fingerprint)
{
        struct sparse *sparse;
        if(!(sparse=(struct sparse *)
		calloc_w(1, sizeof(struct sparse), __func__)))
			return NULL;
        sparse->fingerprint=fingerprint;
	HASH_ADD_INT(sparse_table, fingerprint, sparse);
        return sparse;
}

struct sparse *sparse_find(uint64_t *fingerprint)
{
	struct sparse *sparse=NULL;
	HASH_FIND_INT(sparse_table, fingerprint, sparse);
	return sparse;
}

int sparse_add_candidate(uint64_t *fingerprint, struct candidate *candidate)
{
	static size_t s;
	static struct sparse *sparse;

	if((sparse=sparse_find(fingerprint)))
	{
		// Do not add it to the list if it has already been added.
		for(s=0; s<sparse->size; s++)
			if((sparse->candidates[s]==candidate))
			{
//				printf("not adding %s\n", candidate->path);
				return 0;
			}
	}

	if(!sparse && !(sparse=sparse_add(*fingerprint)))
		return -1;
	if(!(sparse->candidates=(struct candidate **)
		realloc_w(sparse->candidates,
			(sparse->size+1)*sizeof(struct candidate *), __func__)))
				return -1;
	sparse->candidates[sparse->size++]=candidate;
	
	return 0;
}
