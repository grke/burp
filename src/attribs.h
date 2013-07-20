#ifndef __ATTRIBS_H
#define __ATTRIBS_H

extern void encode_stat(struct sbuf *sb, int compression);
extern void decode_stat(struct sbuf *sb, int *compression);
extern bool set_attributes(const char *path, char cmd, struct stat *statp, int64_t winattr, struct cntr *cntr);

#endif /* __ATTRIBS_H */
