#ifndef __ATTRIBS_H
#define __ATTRIBS_H

extern int attribs_encode(struct sbuf *sb, int compression);
extern void attribs_decode(struct sbuf *sb, int *compression);
extern int attribs_set(const char *path, struct stat *statp, int64_t winattr, struct config *conf);
extern uint64_t decode_file_no(struct sbuf *sb);

// FIX THIS - want to only use sbuf stuff.
extern void attribs_decode_low_level(struct stat *statp, const char *attribs, uint64_t *index, uint64_t *winattr, int *compression);

#endif
