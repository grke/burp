#ifndef __ATTRIBS_H
#define __ATTRIBS_H

#include "sbuf.h"

extern int attribs_encode(struct sbuf *sb);

extern void attribs_decode(struct sbuf *sb);

extern int attribs_set(struct asfd *asfd, const char *path, struct stat *statp,
	uint64_t winattr, struct conf **confs);

extern uint64_t decode_file_no(struct iobuf *iobuf);
extern uint64_t decode_file_no_and_save_path(struct iobuf *iobuf,
	char **save_path);

#endif
