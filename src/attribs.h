#ifndef __ATTRIBS_H
#define __ATTRIBS_H

extern int attribs_encode(struct sbuf *sb);
extern void attribs_decode(struct sbuf *sb);
extern int attribs_set(const char *path, struct stat *statp, int64_t winattr, struct config *conf);
extern uint64_t decode_file_no(struct sbuf *sb);

extern void attribs_decode_low_level(struct sbuf *sb);

#endif
