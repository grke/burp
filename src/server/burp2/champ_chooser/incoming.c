#include <assert.h>

#include "include.h"

struct incoming *incoming_alloc(void)
{
	return (struct incoming *)calloc_w(1,
		sizeof(struct incoming), __func__);
}

int incoming_grow_maybe(struct incoming *in)
{
	if(++in->size<in->allocated) return 0;
	// Make the incoming array bigger.
	in->allocated+=32;
//printf("grow incoming to %d\n", in->allocated);
	if((in->fingerprints=(uint64_t *)
		realloc_w(in->fingerprints,
			in->allocated*sizeof(uint64_t), __func__))
	  && (in->found=(uint8_t *)
		realloc_w(in->found, in->allocated*sizeof(uint8_t), __func__)))
			return 0;
	return -1;
}

void incoming_found_reset(struct incoming *in)
{
	if(!in->found || !in->size) return;
	memset(in->found, 0, sizeof(in->found[0])*in->size);
	in->got=0;
}
