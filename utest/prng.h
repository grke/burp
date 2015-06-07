#ifndef __PRNG_H
#define __PRNG_H

#include <stdint.h>

extern void prng_init(uint32_t val);
extern uint32_t prng_next(void);
extern uint64_t prng_next64(void);

#endif
