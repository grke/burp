#ifndef _BURP_XATTR_H
#define _BURP_XATTR_H

#ifdef HAVE_XATTR
#if defined(HAVE_LINUX_OS) \
 || defined(HAVE_FREEBSD_OS) \
 || defined(HAVE_OPENBSD_OS) \
 || defined(HAVE_NETBSD_OS) \
 || defined(HAVE_DARWIN_OS)
extern int has_xattr(const char *path, enum cmd cmd);
extern int get_xattr(struct asfd *asfd, struct sbuf *sb,
	char **xattrtext, size_t *xlen, struct conf **confs);
extern int set_xattr(struct asfd *asfd, const char *path, struct sbuf *sb,
	const char *xattrtext, size_t xlen, char metacmd, struct conf **confs);
#endif
#endif

#endif
