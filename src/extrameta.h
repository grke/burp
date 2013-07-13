#ifndef _EXTRAMETA_H
#define _EXTRAMETA_H

#include "bfile.h"

#define META_ACCESS_ACL		'A'
#define META_DEFAULT_ACL	'D'
#define META_XATTR		'X'
#define META_XATTR_BSD		'B'
#define META_VSS		'V'

extern int has_extrameta(const char *path, char cmd);
extern int get_extrameta(BFILE *bfd, const char *path, struct stat *statp, char **extrameta, size_t *elen, int64_t winattr, struct cntr *cntr, size_t *datalen);
extern int set_extrameta(BFILE *bfd, const char *path, char cmd, struct stat *statp, const char *extrameta, size_t metalen, struct cntr *cntr);

#endif // _EXTRAMETA_H
