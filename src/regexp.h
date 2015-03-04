#ifndef _REGEXP_H
#define _REGEXP_H

#if defined(HAVE_PCREPOSIX)
#include <pcreposix.h>
#else
#include <regex.h>
#endif

extern int compile_regex(regex_t **regex, const char *str);
extern int check_regex(regex_t *regex, const char *buf);

#endif
