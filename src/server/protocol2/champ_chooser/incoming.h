#ifndef _CHAMP_CHOOSER_INCOMING_H
#define _CHAMP_CHOOSER_INCOMING_H

struct incoming
{
	uint64_t *fingerprints;
	uint8_t *found;
	uint16_t size;
	uint16_t allocated;

	uint16_t got;
};

extern struct incoming *incoming_alloc(void);
extern void incoming_free(struct incoming **in);
extern int incoming_grow_maybe(struct incoming *in);
extern void incoming_found_reset(struct incoming *in);

#endif
