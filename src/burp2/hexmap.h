#ifndef _HEXMAP_H
#define _HEXMAP_H

extern uint8_t md5sum_of_empty_string[];

extern void hexmap_init(void);
extern void md5str_to_bytes(const char *md5str, uint8_t *bytes);

#endif
