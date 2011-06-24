#include "burp.h"
#include "prog.h"
#include "acl.h"
#include "cmd.h"

#ifdef HAVE_XATTR

int has_xattr(const char *path, char cmd)
{
	//if(llistxattr(path, NULL, 0)>0) return 1;
	return 0;
}

int get_xattr(const char *path, char cmd, char **xattrtext)
{
	return 0;
}

#endif // HAVE_XATTR
