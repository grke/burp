#include "include.h"

#define HEXMAP_SIZE	256

static uint8_t hexmap1[HEXMAP_SIZE];
static uint8_t hexmap2[HEXMAP_SIZE];

uint8_t md5sum_of_empty_string[MD5_DIGEST_LENGTH];

static void do_hexmap_init(uint8_t *hexmap, uint8_t shift)
{
	uint8_t i;
	uint8_t h;
	memset(hexmap, 0, HEXMAP_SIZE);
	for(i='0', h=0x00; i<='9'; i++, h++) hexmap[i]=h<<shift;
	for(i='a', h=0x0A; i<='f'; i++, h++) hexmap[i]=h<<shift;
	for(i='A', h=0x0A; i<='F'; i++, h++) hexmap[i]=h<<shift;
}

void hexmap_init(void)
{
	do_hexmap_init(hexmap1, 4);
	do_hexmap_init(hexmap2, 0);
	md5str_to_bytes("D41D8CD98F00B204E9800998ECF8427E",
		md5sum_of_empty_string);
}

void md5str_to_bytes(const char *md5str, uint8_t *bytes)
{
	static uint8_t bpos;
	static uint8_t spos;

	for(bpos=0, spos=0; bpos<MD5_DIGEST_LENGTH; bpos++, spos+=2)
		bytes[bpos] = hexmap1[(uint8_t)md5str[spos]]
			| hexmap2[(uint8_t)md5str[spos+1]];
}

char *bytes_to_md5str(uint8_t *bytes)
{
        static char str[64]="";
        snprintf(str, sizeof(str),
          "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7],
                bytes[8], bytes[9], bytes[10], bytes[11],
                bytes[12], bytes[13], bytes[14], bytes[15]);
        return str;
}

