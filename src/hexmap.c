#include "burp.h"
#include "hexmap.h"

char *bytes_to_md5str(uint8_t *bytes)
{
        static char str[64];
        snprintf(str, sizeof(str), "%016" PRIx64 "%016" PRIx64,
		htobe64(*(uint64_t *)bytes), htobe64(*(uint64_t *)(bytes+8)));
        return str;
}
