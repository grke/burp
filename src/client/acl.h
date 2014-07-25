#ifndef _BURP_ACL_H
#define _BURP_ACL_H

#ifdef HAVE_ACL
#if defined(HAVE_LINUX_OS) || \
    defined(HAVE_FREEBSD_OS) || \
    defined(HAVE_OPENBSD_OS) || \
    defined(HAVE_NETBSD_OS)
extern int has_acl(const char *path, char cmd);
extern int get_acl(struct asfd *asfd, struct sbuf *sb,
	char **acltext, size_t *alen, struct conf *conf);
extern int set_acl(struct asfd *asfd, const char *path, struct sbuf *sb,
	const char *acltext, size_t alen, char metacmd, struct conf *conf);
#endif
#endif

#endif
