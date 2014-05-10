#ifndef __ATTRIBS_H
#define __ATTRIBS_H

extern int attribs_encode(struct sbuf *sb);

extern void attribs_decode(struct sbuf *sb);

extern int attribs_set(struct asfd *asfd, const char *path, struct stat *statp,
	uint64_t winattr, struct conf *conf);

extern uint64_t decode_file_no(struct sbuf *sb);

#endif
