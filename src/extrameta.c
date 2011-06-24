#include "burp.h"
#include "prog.h"
#include "acl.h"
#include "cmd.h"
#include "asyncio.h"
#include "extrameta.h"

int has_extrameta(const char *path, int cmd)
{
#ifdef HAVE_ACL
	if(has_acl(path, cmd)) return 1;
#endif
#ifdef HAVE_XATTR
	//if(has_xattr(path, cmd)) return 1;
#endif
        return 0;
}

int get_extrameta(const char *path, int cmd, char **extrameta, struct cntr *cntr)
{
#ifdef HAVE_ACL
	if(get_acl(path, cmd, extrameta, cntr)) return -1;
#endif
#ifdef HAVE_XATTR
	//if(get_xattr(path, cmd, extrameta, cntr)) return -1;
#endif
        return 0;
}
