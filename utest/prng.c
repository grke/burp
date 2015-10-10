#include <stdio.h>

#include "prng.h"

static uint32_t current=0;
static uint32_t seed=0;

static uint32_t permute(uint32_t x)
{
	static uint32_t prime = 4294967291U;
	if(x>=prime) return x;
	uint32_t residue = ((uint64_t)x*x)%prime;
	if(x<=prime/2) return residue;
	else return prime - residue;
}

void prng_init(uint32_t val)
{
	current=0;
	seed=val;
}

uint32_t prng_next(void)
{
	current=permute((permute(current) + seed) ^ 0x5bf03635);
	return current;
}

uint64_t prng_next64(void)
{
	return (uint64_t)(prng_next())<<32|prng_next();
}

uint8_t *prng_md5sum(uint8_t checksum[])
{
	uint8_t i=0;
	uint8_t j=0;
	uint32_t r;
	while(i<MD5_DIGEST_LENGTH)
	{
		r=prng_next();
		for(j=0; j<sizeof(r)*4; j+=8)
			checksum[i++]=(uint8_t)(r>>j);
	}
	return checksum;
}
