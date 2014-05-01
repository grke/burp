#include <assert.h>

#include "include.h"

struct incoming *incoming_alloc(void)
{
	struct incoming *in;
	if((in=(struct incoming *)calloc(1, sizeof(struct incoming))))
		return in;
	log_out_of_memory(__func__);
	return NULL;
}

int incoming_grow_maybe(struct incoming *in)
{
	if(++in->size<in->allocated) return 0;
	// Make the incoming array bigger.
	in->allocated+=32;
//printf("grow incoming to %d\n", in->allocated);
	if((in->weak=(uint64_t *)
		realloc(in->weak, in->allocated*sizeof(uint64_t)))
	  && (in->found=(uint8_t *)
		realloc(in->found, in->allocated*sizeof(uint8_t))))
			return 0;
	log_out_of_memory(__func__);
	return -1;
}

void incoming_found_reset(struct incoming *in)
{
	if(!in->found || !in->size) return;
	memset(in->found, 0, sizeof(in->found[0])*in->size);
	in->got=0;
}
