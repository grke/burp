#ifndef _EXTRAMETA_H
#define _EXTRAMETA_H

#include "../bfile.h"
#include "../sbuf.h"

#define META_ACCESS_ACL		'A'
#define META_DEFAULT_ACL	'D'

#define META_XATTR		'X'
#define META_XATTR_BSD		'B'

#define META_VSS		'V'

extern int has_extrameta(const char *path, enum cmd cmd,
	int enable_acl, int enable_xattr);

extern int get_extrameta(struct asfd *asfd,
#ifdef HAVE_WIN32
	struct BFILE *bfd,
#endif
	const char *path,
	int isdir,
	char **extrameta,
	size_t *elen,
	struct cntr *cntr);

extern int set_extrameta(struct asfd *asfd,
#ifdef HAVE_WIN32
	struct BFILE *bfd,
#endif
	const char *path,
	const char *extrameta,
	size_t metalen,
	struct cntr *cntr);

#endif
