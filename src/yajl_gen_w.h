#ifndef _YAJL_GEN_W_H
#define _YAJL_GEN_W_H

#ifdef HAVE_WIN32
#include <yajl/yajl_gen.h>
#else
#include "yajl/yajl/yajl_gen.h"
#endif

// Functions for making working with yajl_gen a little easier.

extern yajl_gen yajl;
extern int yajl_map_open_w(void);
extern int yajl_map_close_w(void);
extern int yajl_array_open_w(void);
extern int yajl_array_close_w(void);
extern int yajl_gen_str_w(const char *str);
extern int yajl_gen_int_w(long long num);
extern int yajl_gen_str_pair_w(const char *field, const char *value);
extern int yajl_gen_int_pair_w(const char *field, long long value);

#endif
