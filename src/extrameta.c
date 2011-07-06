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
	// Assume that links do not have their own metadata.
	if(cmd_is_link(cmd)) return 0;

#if defined(HAVE_LINUX_OS) || \
    defined(HAVE_FREEBSD_OS)
#ifdef HAVE_ACL
	if(has_acl(path, cmd)) return 1;
#endif
#endif
#if defined(HAVE_LINUX_OS)
#ifdef HAVE_XATTR
	if(has_xattr(path, cmd)) return 1;
#endif
#endif
        return 0;
}

int get_extrameta(const char *path, struct stat *statp, char **extrameta, struct cntr *cntr)
{
	// Important to do xattr directly after acl, because xattr is excluding
	// some entries if acls were set.
#if defined(HAVE_LINUX_OS) || \
    defined(HAVE_FREEBSD_OS)
#ifdef HAVE_ACL
	if(get_acl(path, statp, extrameta, cntr)) return -1;
#endif
#endif
#if defined(HAVE_LINUX_OS)
#ifdef HAVE_XATTR
	if(get_xattr(path, statp, extrameta, cntr)) return -1;
#endif
#endif
        return 0;
}

int set_extrameta(const char *path, char cmd, struct stat *statp, const char *extrameta, struct cntr *cntr)
{
	ssize_t l=NULL;
	char cmdtmp='\0';
	unsigned int s=0;
	const char *metadata=NULL;
	int errors=0;

	metadata=extrameta;
	l=strlen(metadata);
	while(l>0)
	{
		char *m=NULL;
		if((sscanf(metadata, "%c%08X", &cmdtmp, &s))!=2)
		{
			logp("sscanf of metadata failed\n");
			logw(cntr, "sscanf of metadata failed\n");
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
    defined(HAVE_FREEBSD_OS)
#ifdef HAVE_ACL
			case META_ACCESS_ACL:
				if(set_acl(path, statp, m, cmdtmp, cntr))
					errors++;
				break;
			case META_DEFAULT_ACL:
				if(set_acl(path, statp, m, cmdtmp, cntr))
					errors++;
				break;
#endif
#endif
#if defined(HAVE_LINUX_OS)
#ifdef HAVE_XATTR
			case META_XATTR:
				if(set_xattr(path, statp, m, cmdtmp, cntr))
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
