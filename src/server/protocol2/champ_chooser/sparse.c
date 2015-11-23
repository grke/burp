#include "../../../burp.h"
#include "../../../alloc.h"
#include "candidate.h"
#include "sparse.h"

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

void sparse_delete_all(void)
{
	struct sparse *tmp;
	struct sparse *sparse;

	HASH_ITER(hh, sparse_table, sparse, tmp)
	{
		HASH_DEL(sparse_table, sparse);
		free_v((void **)&sparse->candidates);
		free_v((void **)&sparse);
	}
	sparse_table=NULL;
}

int sparse_add_candidate(uint64_t *fingerprint, struct candidate *candidate)
{
	static size_t s;
	static struct sparse *sparse;

	if((sparse=sparse_find(fingerprint)))
	{
		// Do not add it to the list if it has already been added.
		for(s=0; s<sparse->size; s++)
			if(sparse->candidates[s]==candidate)
				return 0;
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

void sparse_delete_fresh_candidate(struct candidate *candidate)
{
	struct sparse *tmp;
	struct sparse *sparse;

	HASH_ITER(hh, sparse_table, sparse, tmp)
	{
		// Only works if the candidate being deleted is the most recent
		// one added. Which is fine for candidate_add_fresh().
		if(sparse->candidates[sparse->size-1]==candidate)
			sparse->size--;
	}
}
