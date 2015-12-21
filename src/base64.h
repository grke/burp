#ifndef BASE_64_H
#define BASE_64_H

#include "burp.h"

extern void base64_init(void);
extern int to_base64(int64_t value, char *where);
extern int from_base64(int64_t *value, const char *where);

extern uint64_t base64_to_uint64(const char *buf);
extern void base64_from_uint64(uint64_t src, char *buf);

#endif
