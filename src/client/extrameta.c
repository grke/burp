#include "../burp.h"
#include "../alloc.h"
#include "../bfile.h"
#include "../cmd.h"
#include "../conf.h"
#include "../log.h"
#include "acl.h"
#include "cvss.h"
#include "extrameta.h"
#include "xattr.h"

int has_extrameta(const char *path, enum cmd cmd, enum protocol protocol,
	int enable_acl, int enable_xattr)
{
#if defined(WIN32_VSS)
	return 1;
#endif
	// FIX THIS: extra meta not supported in protocol2.
	if(protocol==PROTO_2) return 0;
#if defined(HAVE_LINUX_OS) || \
    defined(HAVE_FREEBSD_OS) || \
    defined(HAVE_OPENBSD_OS) || \
    defined(HAVE_NETBSD_OS)

#ifdef HAVE_ACL
	if(enable_acl && has_acl(path, cmd)) return 1;
#endif
#endif
#if defined(HAVE_LINUX_OS) || \
    defined(HAVE_FREEBSD_OS) || \
    defined(HAVE_OPENBSD_OS) || \
    defined(HAVE_NETBSD_OS) || \
    defined(HAVE_DARWIN_OS)
#ifdef HAVE_XATTR
	if(enable_xattr && has_xattr(path)) return 1;
#endif
#endif
        return 0;
}

int get_extrameta(struct asfd *asfd,
	BFILE *bfd,
	struct sbuf *sb,
	char **extrameta,
	size_t *elen,
	struct cntr *cntr)
{
#if defined (WIN32_VSS)
	if(get_vss(bfd, sb, extrameta, elen)) return -1;
#endif
	// Important to do xattr directly after acl, because xattr is excluding
	// some entries if acls were set.
#if defined(HAVE_LINUX_OS) || \
    defined(HAVE_FREEBSD_OS) || \
    defined(HAVE_OPENBSD_OS) || \
    defined(HAVE_NETBSD_OS)
#ifdef HAVE_ACL
	if(get_acl(asfd, sb, extrameta, elen, cntr)) return -1;
#endif
#endif
#if defined(HAVE_LINUX_OS) || \
    defined(HAVE_FREEBSD_OS) || \
    defined(HAVE_OPENBSD_OS) || \
    defined(HAVE_NETBSD_OS) || \
    defined(HAVE_DARWIN_OS)
#ifdef HAVE_XATTR
	if(get_xattr(asfd, sb->path.buf, extrameta, elen, cntr)) return -1;
#endif
#endif
        return 0;
}

int set_extrameta(struct asfd *asfd,
	BFILE *bfd,
	const char *path,
	struct sbuf *sb,
	const char *extrameta,
	size_t metalen,
	struct cntr *cntr)
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
			logw(asfd, cntr,
				"sscanf of metadata failed for %s: %s\n",
				path, metadata);
			return -1;
		}
		metadata+=9;
		l-=9;
		if(!(m=(char *)malloc_w(s+1, __func__)))
			return -1;
		memcpy(m, metadata, s);
		m[s]='\0';

		metadata+=s;
		l-=s;

		switch(cmdtmp)
		{
#if defined(HAVE_WIN32)
			case META_VSS:
				if(set_vss(bfd, m, s)) errors++;
				break;
#endif
#if defined(HAVE_LINUX_OS) || \
    defined(HAVE_FREEBSD_OS) || \
    defined(HAVE_OPENBSD_OS) || \
    defined(HAVE_NETBSD_OS)
#ifdef HAVE_ACL
			case META_ACCESS_ACL:
				if(set_acl(asfd, path, sb, m, s, cmdtmp, cntr))
					errors++;
				break;
			case META_DEFAULT_ACL:
				if(set_acl(asfd, path, sb, m, s, cmdtmp, cntr))
					errors++;
				break;
#endif
#endif
#if defined(HAVE_LINUX_OS)
#ifdef HAVE_XATTR
			case META_XATTR:
				if(set_xattr(asfd,
					path, m, s, cmdtmp, cntr))
						errors++;
				break;
#endif
#endif
#if defined(HAVE_FREEBSD_OS) || \
    defined(HAVE_OPENBSD_OS) || \
    defined(HAVE_NETBSD_OS)
#ifdef HAVE_XATTR
			case META_XATTR_BSD:
				if(set_xattr(asfd,
					path, m, s, cmdtmp, cntr))
						errors++;
				break;
#endif
#endif
#if defined(HAVE_DARWIN_OS)
#ifdef HAVE_XATTR
			case META_XATTR_OSX:
				if(set_xattr(asfd,
					path, m, s, cmdtmp, cntr))
						errors++;
				break;
#endif
#endif
			default:
				logp("unknown metadata: %c\n", cmdtmp);
				logw(asfd, cntr,
					"unknown metadata: %c\n", cmdtmp);
				errors++;
				break;
				
		}
		free(m);
	}

	return errors;
}
