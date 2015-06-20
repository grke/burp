#ifndef _HEXMAP_H
#define _HEXMAP_H

#include "burp.h"

extern uint8_t md5sum_of_empty_string[];

extern void hexmap_init(void);

extern void md5str_to_bytes(const char *md5str, uint8_t *bytes);
extern char *bytes_to_md5str(uint8_t *bytes);

extern void savepathstr_to_bytes(const char *savepathstr, uint8_t *bytes);
extern char *bytes_to_savepathstr(uint8_t *bytes);
extern char *bytes_to_savepathstr_with_sig(uint8_t *bytes);

#endif
