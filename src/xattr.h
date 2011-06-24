#ifndef _BURP_XATTR_H
#define _BURP_XATTR_H

#ifdef HAVE_XATTR
extern int has_xattr(const char *path, char cmd);
extern int get_xattr(const char *path, char cmd, char **xattrtext);
#endif

#endif // _BURP_XATTR_H
