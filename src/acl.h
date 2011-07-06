#ifndef _BURP_ACL_H
#define _BURP_ACL_H

#ifdef HAVE_ACL
#if defined(HAVE_LINUX_OS) || \
    defined(HAVE_FREEBSD_OS)
extern int has_acl(const char *path, char cmd);
extern int get_acl(const char *path, struct stat *statp, char **acltext, struct cntr *cntr);
extern int set_acl(const char *path, struct stat *statp, const char *acltext, char cmd, struct cntr *cntr);
#endif
#endif

#endif // _BURP_ACL_H
