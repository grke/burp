#ifndef _BURP_ACL_H
#define _BURP_ACL_H

#ifdef HAVE_ACL
#if defined(HAVE_LINUX_OS) || \
    defined(HAVE_FREEBSD_OS) || \
    defined(HAVE_NETBSD_OS)
extern int has_acl(const char *path, enum cmd cmd);
extern int get_acl(struct asfd *asfd, const char *path, int isdir,
	char **acltext, size_t *alen, struct cntr *cntr);
extern int set_acl(struct asfd *asfd, const char *path,
	const char *acltext, char metacmd, struct cntr *cntr);
#endif
#endif

#endif
