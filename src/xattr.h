#ifndef _BURP_XATTR_H
#define _BURP_XATTR_H

#ifdef HAVE_XATTR
#if defined(HAVE_LINUX_OS)
extern int has_xattr(const char *path, char cmd);
extern int get_xattr(const char *path, struct stat *statp, char **xattrtext, struct cntr *cntr);
extern int set_xattr(const char *path, struct stat *statp, const char *xattrtext, char cmd, struct cntr *cntr);
#endif
#endif

#endif // _BURP_XATTR_H
