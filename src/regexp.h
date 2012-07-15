#ifndef _REGEXP_H
#define _REGEXP_H

extern int compile_regex(regex_t **regex, const char *str);
extern int check_regex(regex_t *regex, const char *buf);

#endif // _REGEXP_H
