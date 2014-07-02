#ifndef BASE_64_H
#define BASE_64_H

extern void base64_init(void);
extern int to_base64(int64_t value, char *where);
extern int from_base64(int64_t *value, const char *where);

#endif
