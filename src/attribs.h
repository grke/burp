#ifndef __ATTRIBS_H
#define __ATTRIBS_H

extern void encode_stat(char *buf, struct stat *statp, int64_t winattr, int compression);
extern void decode_stat(const char *buf, struct stat *statp, int64_t *winattr, int *compression);
extern bool set_attributes(const char *path, char cmd, struct stat *statp, int64_t winattr, struct cntr *cntr);

#endif /* __ATTRIBS_H */
