#ifndef _ATTRIBS_LEGACY_H
#define _ATTRIBS_LEGACY_H

extern void encode_stat(char *buf, struct stat *statp, int64_t winattr,
	int compression);
extern void decode_stat(const char *buf, struct stat *statp, int64_t *winattr,
	int *compression);

#endif
