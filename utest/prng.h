#ifndef __PRNG_H
#define __PRNG_H

#include "../src/burp.h"
#include <openssl/md5.h>

extern void prng_init(uint32_t val);
extern uint32_t prng_next(void);
extern uint64_t prng_next64(void);
extern uint8_t *prng_md5sum(uint8_t checksum[]);

#endif
