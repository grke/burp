#ifndef __ATTRIBS_H
#define __ATTRIBS_H

extern int encode_stat(struct sbuf *sb, int compression);
extern void decode_stat(struct sbuf *sb, uint64_t *file_no, int *compression);
extern bool set_attributes(const char *path, char cmd, struct stat *statp, int64_t winattr, struct cntr *cntr);
extern uint64_t decode_file_no(struct sbuf *sb);

#endif /* __ATTRIBS_H */
