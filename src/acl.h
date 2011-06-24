#ifndef _BURP_ACL_H
#define _BURP_ACL_H

#ifdef HAVE_ACL
extern int has_acl(const char *path, char cmd);
extern int get_acl(const char *path, char cmd, char **acltext, struct cntr *cntr);
#endif

#endif // _BURP_ACL_H
