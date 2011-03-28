#ifndef BASE_64_H
#define BASE_64_H

/* Maximum size of len bytes after base64 encoding */
#define BASE64_SIZE(len) ((4 * len + 2) / 3 + 1)

void      base64_init            (void);
int       to_base64              (intmax_t value, char *where);
int       from_base64            (intmax_t *value, const char *where);

#endif
