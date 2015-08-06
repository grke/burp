#include "burp.h"
#include "hexmap.h"
#include "protocol2/blk.h"

// FIX THIS: Should be set in configure somewhere.
#include <openssl/md5.h>

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

static void str_to_bytes(const char *str, uint8_t *bytes, size_t len)
{
	static uint8_t bpos;
	static uint8_t spos;

	for(bpos=0, spos=0; bpos<len && str[spos]; )
	{
		if(str[spos]=='/')
		{
			spos++;
			continue;
		}
		bytes[bpos++] = hexmap1[(uint8_t)str[spos]]
			| hexmap2[(uint8_t)str[spos+1]];
		spos+=2;
	}
}

void md5str_to_bytes(const char *md5str, uint8_t *bytes)
{
	str_to_bytes(md5str, bytes, MD5_DIGEST_LENGTH);
}

char *bytes_to_md5str(uint8_t *bytes)
{
        static char str[64]="";
        snprintf(str, sizeof(str), "%016"PRIx64"%016"PRIx64,
		htobe64(*(uint64_t *)bytes), htobe64(*(uint64_t *)(bytes+8)));
        return str;
}

uint64_t savepathstr_to_uint64(const char *savepathstr)
{
	uint8_t b[sizeof(uint64_t)];
	str_to_bytes(savepathstr, b, sizeof(b));
	return htobe64(*(uint64_t *)&b);
}

char *uint64_to_savepathstr(uint64_t bytes)
{
        static char str[15]="";
	uint64_t tmp=htobe64(bytes);
	uint8_t *b=(uint8_t *)&tmp;
        snprintf(str, sizeof(str), "%02X%02X/%02X%02X/%02X%02X",
                b[0], b[1], b[2], b[3], b[4], b[5]);
        return str;
}

char *uint64_to_savepathstr_with_sig(uint64_t bytes)
{
        static char str[20]="";
	uint64_t tmp=htobe64(bytes);
	uint8_t *b=(uint8_t *)&tmp;
        snprintf(str, sizeof(str), "%02X%02X/%02X%02X/%02X%02X/%02X%02X",
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
        return str;
}
