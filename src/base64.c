#include "burp.h"

static uint8_t const base64_digits[64] =
{
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
  'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

static int base64_inited = 0;
static uint8_t base64_map[128];


/* Initialize the Base 64 conversion routines */
void
base64_init(void)
{
   int i;
   memset(base64_map, 0, sizeof(base64_map));
   for (i=0; i<64; i++)
      base64_map[(uint8_t)base64_digits[i]] = i;
   base64_inited = 1;
}

/* Convert a value to base64 characters.
 * The result is stored in where, which
 * must be at least 8 characters long.
 *
 * Returns the number of characters
 * stored (not including the EOS).
 */
int
to_base64(int64_t value, char *where)
{
   uint64_t val;
   int i = 0;
   int n;

   /* Handle negative values */
   if (value < 0) {
      where[i++] = '-';
      value = -value;
   }

   /* Determine output size */
   val = value;
   do {
      val >>= 6;
      i++;
   } while (val);
   n = i;

   /* Output characters */
   val = value;
   where[i] = 0;
   do {
      where[--i] = base64_digits[val & (uint64_t)0x3F];
      val >>= 6;
   } while (val);
   return n;
}

/*
 * Convert the Base 64 characters in where to
 * a value. No checking is done on the validity
 * of the characters!!
 *
 * Returns the value.
 */
int
from_base64(int64_t *value, const char *where)
{
   uint64_t val = 0;
   int i, neg;

   if (!base64_inited)
      base64_init();
   /* Check if it is negative */
   i = neg = 0;
   if (where[i] == '-') {
      i++;
      neg = 1;
   }
   /* Construct value */
   while (where[i] != 0 && where[i] != ' ') {
      val <<= 6;
      val += base64_map[(uint8_t)where[i++]];
   }

   *value = neg ? -(int64_t)val : (int64_t)val;
   return i;
}
