#ifndef _ALLOC_H
#define _ALLOC_H

#include "burp.h"

#ifdef UTEST
extern int alloc_errors;
extern uint64_t alloc_count;
extern uint64_t free_count;
extern void alloc_counters_reset(void);
#endif

extern char *strdup_w(const char *s, const char *func);
extern void *realloc_w(void *ptr, size_t size, const char *func);
extern void *malloc_w(size_t size, const char *func);
extern void *calloc_w(size_t nmem, size_t size, const char *func);
extern void free_v(void **ptr);
extern void free_w(char **str);

#endif
