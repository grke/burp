#ifndef __ATTRIBS_H
#define __ATTRIBS_H

extern int attribs_encode(struct stat *statp, struct iobuf *attr,
	uint64_t winattr, int compression, uint64_t *index);

extern void attribs_decode(struct stat *statp, struct iobuf *attr,
	uint64_t *winattr, int *compression, uint64_t *index);

extern int attribs_set(const char *path, struct stat *statp,
	uint64_t winattr, struct config *conf);

extern uint64_t decode_file_no(struct sbuf *sb);

#endif
