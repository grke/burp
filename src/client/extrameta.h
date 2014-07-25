#ifndef _EXTRAMETA_H
#define _EXTRAMETA_H

#define META_ACCESS_ACL		'A'
#define META_DEFAULT_ACL	'D'
#define META_XATTR		'X'
#define META_XATTR_BSD		'B'
#define META_VSS		'V'

extern int has_extrameta(const char *path, char cmd);

extern int get_extrameta(struct asfd *asfd,
#ifdef HAVE_WIN32
	BFILE *bfd,
#endif
	struct sbuf *sb,
	char **extrameta,
	size_t *elen,
	struct conf *conf,
	size_t *datalen);

extern int set_extrameta(struct asfd *asfd,
#ifdef HAVE_WIN32
	BFILE *bfd,
#endif
	const char *path,
	struct sbuf *sb,
	const char *extrameta,
	size_t metalen,
	struct conf *conf);

#endif
