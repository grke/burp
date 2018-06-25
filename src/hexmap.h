#ifndef _HEXMAP_H
#define _HEXMAP_H

#include "burp.h"

extern uint8_t md5sum_of_empty_string[];

extern void hexmap_init(void);

extern void md5str_to_bytes(const char *md5str, uint8_t *bytes);
extern char *bytes_to_md5str(uint8_t *bytes);

extern uint64_t savepathstr_with_sig_to_uint64(const char *savepathstr);
extern char *uint64_to_savepathstr(uint64_t bytes);
extern char *uint64_to_savepathstr_with_sig(uint64_t bytes);
extern char *uint64_to_savepathstr_with_sig_uint(uint64_t bytes, uint16_t *sig);
extern uint64_t uint64_to_savepath_hash_key(uint64_t bytes);

#endif
