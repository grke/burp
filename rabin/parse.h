#ifndef __PARSE_H
#define __PARSE_H

#include <stdio.h>

#include "dpth.h"

extern int collisions;

extern int split_sig(const char *buf, unsigned int s, char *weak, char *strong);

extern int split_stream(FILE *ifp, struct dpth *dpth, void *flag,
  int (*process_dat)(char, const char *, unsigned int, struct dpth *, void *),
  int (*process_man)(char, const char *, unsigned int, struct dpth *, void *),
  int (*process_sig)(char, const char *, unsigned int, struct dpth *, void *));

extern int fwrite_dat(char cmd, const char *buf, unsigned int s, struct dpth *dpth, void *);
extern int fwrite_man(char cmd, const char *buf, unsigned int s, struct dpth *dpth, void *);
extern int fwrite_sig(char cmd, const char *buf, unsigned int s, struct dpth *dpth, void *);

extern int fwrite_buf(char cmd, const char *buf, unsigned int s, FILE *fp, int *flag);

#endif
