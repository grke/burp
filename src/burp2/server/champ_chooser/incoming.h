#include <assert.h>

#include "include.h"

struct incoming
{
	uint64_t *weak;
	uint8_t *found;
	uint16_t size;
	uint16_t allocated;

	uint16_t got;
};

extern struct incoming *in;

extern struct incoming *incoming_alloc(void);
extern int incoming_grow_maybe(struct incoming *in);
extern void incoming_found_reset(struct incoming *in);
