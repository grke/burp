#ifndef _PREPEND_H
#define _PREPEND_H

extern char *prepend_len(const char *prep, size_t plen, const char *fname, size_t flen, const char *sep, size_t slen, size_t *newlen);
extern char *prepend_n(const char *prep, const char *fname,
        size_t len, const char *sep);
extern char *prepend(const char *prep, const char *fname);
extern char *prepend_slash(const char *prep, const char *fname, size_t len);
extern char *prepend_s(const char *prep, const char *fname);
extern int astrcat(char **buf, const char *append, const char *func);

#endif
