#include "include.h"

static struct sparse *sparse_table=NULL;

static struct sparse *sparse_add(uint64_t weak)
{
        struct sparse *sparse;
        if(!(sparse=(struct sparse *)calloc(1, sizeof(struct sparse))))
        {
                log_out_of_memory(__func__);
                return NULL;
        }
        sparse->weak=weak;
	HASH_ADD_INT(sparse_table, weak, sparse);
        return sparse;
}

struct sparse *sparse_find(uint64_t weak)
{
	struct sparse *sparse=NULL;
	HASH_FIND_INT(sparse_table, &weak, sparse);
	return sparse;
}

int sparse_add_candidate(const char *weakstr, struct candidate *candidate)
{
	static size_t s;
	static uint64_t weak;
	static struct sparse *sparse;

	// Convert to uint64_t.
	weak=strtoull(weakstr, 0, 16);

	if((sparse=sparse_find(weak)))
	{
		// Do not add it to the list if it has already been added.
		for(s=0; s<sparse->size; s++)
			if((sparse->candidates[s]==candidate))
			{
//				printf("not adding %s\n", candidate->path);
				return 0;
			}
	}

	if(!sparse && !(sparse=sparse_add(weak)))
		return -1;
	if(!(sparse->candidates=(struct candidate **)
		realloc(sparse->candidates,
			(sparse->size+1)*sizeof(struct candidate *))))
	{
                log_out_of_memory(__func__);
		return -1;
	}
	sparse->candidates[sparse->size++]=candidate;
	
	return 0;
}
