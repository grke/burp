#include "burp.h"
#include "prog.h"
#include "acl.h"
#include "cmd.h"
#include "sbuf.h"
#include "asyncio.h"
#include "extrameta.h"
#include "xattr.h"

int has_extrameta(const char *path, char cmd)
{
#if defined(HAVE_LINUX_OS) || \
    defined(HAVE_FREEBSD_OS) || \
    defined(HAVE_OPENBSD_OS) || \
    defined(HAVE_NETBSD_OS)
#ifdef HAVE_ACL
	if(has_acl(path, cmd)) return 1;
#endif
#endif
#if defined(HAVE_LINUX_OS) || \
    defined(HAVE_FREEBSD_OS) || \
    defined(HAVE_OPENBSD_OS) || \
    defined(HAVE_NETBSD_OS)
#ifdef HAVE_XATTR
	if(has_xattr(path, cmd)) return 1;
#endif
#endif
        return 0;
}

int get_extrameta(const char *path, struct stat *statp, char **extrameta, size_t *elen, struct cntr *cntr)
{
	// Important to do xattr directly after acl, because xattr is excluding
	// some entries if acls were set.
#if defined(HAVE_LINUX_OS) || \
    defined(HAVE_FREEBSD_OS) || \
    defined(HAVE_OPENBSD_OS) || \
    defined(HAVE_NETBSD_OS)
#ifdef HAVE_ACL
	if(get_acl(path, statp, extrameta, elen, cntr)) return -1;
#endif
#endif
#if defined(HAVE_LINUX_OS) || \
    defined(HAVE_FREEBSD_OS) || \
    defined(HAVE_OPENBSD_OS) || \
    defined(HAVE_NETBSD_OS)
#ifdef HAVE_XATTR
	if(get_xattr(path, statp, extrameta, elen, cntr)) return -1;
#endif
#endif
        return 0;
}

int set_extrameta(const char *path, char cmd, struct stat *statp, const char *extrameta, size_t metalen, struct cntr *cntr)
{
	size_t l=0;
	char cmdtmp='\0';
	unsigned int s=0;
	const char *metadata=NULL;
	int errors=0;

	metadata=extrameta;
	l=metalen;
	while(l>0)
	{
		char *m=NULL;
		if((sscanf(metadata, "%c%08X", &cmdtmp, &s))!=2)
		{
			logw(cntr, "sscanf of metadata failed for %s: %s\n",
				path, metadata);
			return -1;
		}
		metadata+=9;
		l-=9;
		if(!(m=(char *)malloc(s+1)))
		{
			logp("out of memory\n");
			return -1;
		}
		memcpy(m, metadata, s);
		m[s]='\0';

		metadata+=s;
		l-=s;

		switch(cmdtmp)
		{
#if defined(HAVE_LINUX_OS) || \
    defined(HAVE_FREEBSD_OS) || \
    defined(HAVE_OPENBSD_OS) || \
    defined(HAVE_NETBSD_OS)
#ifdef HAVE_ACL
			case META_ACCESS_ACL:
				if(set_acl(path, statp, m, s, cmdtmp, cntr))
					errors++;
				break;
			case META_DEFAULT_ACL:
				if(set_acl(path, statp, m, s, cmdtmp, cntr))
					errors++;
				break;
#endif
#endif
#if defined(HAVE_LINUX_OS)
#ifdef HAVE_XATTR
			case META_XATTR:
				if(set_xattr(path, statp, m, s, cmdtmp, cntr))
					errors++;
				break;
#endif
#endif
#if defined(HAVE_FREEBSD_OS) || \
    defined(HAVE_OPENBSD_OS) || \
    defined(HAVE_NETBSD_OS)
#ifdef HAVE_XATTR
			case META_XATTR_BSD:
				if(set_xattr(path, statp, m, s, cmdtmp, cntr))
					errors++;
				break;
#endif
#endif
			default:
				logp("unknown metadata: %c\n", cmdtmp);
				logw(cntr, "unknown metadata: %c\n", cmdtmp);
				errors++;
				break;
				
		}
		free(m);
	}

	return errors;
}
