#include "burp.h"
#include "prog.h"
#include "acl.h"
#include "cmd.h"
#include "sbuf.h"
#include "asyncio.h"
#include "extrameta.h"
#include "xattr.h"
#include "client_vss.h"

int has_extrameta(const char *path, char cmd)
{
#if defined(WIN32_VSS)
	return 1;
#endif
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

int get_extrameta(BFILE *bfd, const char *path, struct stat *statp, char **extrameta, size_t *elen, int64_t winattr, struct config *conf, size_t *datalen)
{
#if defined (WIN32_VSS)
	if(get_vss(bfd, path, statp, extrameta, elen, winattr, conf,
		datalen)) return -1;
#endif
	// Important to do xattr directly after acl, because xattr is excluding
	// some entries if acls were set.
#if defined(HAVE_LINUX_OS) || \
    defined(HAVE_FREEBSD_OS) || \
    defined(HAVE_OPENBSD_OS) || \
    defined(HAVE_NETBSD_OS)
#ifdef HAVE_ACL
	if(get_acl(path, statp, extrameta, elen, conf->cntr)) return -1;
#endif
#endif
#if defined(HAVE_LINUX_OS) || \
    defined(HAVE_FREEBSD_OS) || \
    defined(HAVE_OPENBSD_OS) || \
    defined(HAVE_NETBSD_OS)
#ifdef HAVE_XATTR
	if(get_xattr(path, statp, extrameta, elen, conf->cntr)) return -1;
#endif
#endif
        return 0;
}

int set_extrameta(
#ifdef HAVE_WIN32
	BFILE *bfd,
#endif
	const char *path,
	char cmd,
	struct stat *statp,
	const char *extrameta,
	size_t metalen,
	struct config *conf)
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
			logw(conf->cntr, "sscanf of metadata failed for %s: %s\n",
				path, metadata);
			return -1;
		}
		metadata+=9;
		l-=9;
		if(!(m=(char *)malloc(s+1)))
		{
			log_out_of_memory(__FUNCTION__);
			return -1;
		}
		memcpy(m, metadata, s);
		m[s]='\0';

		metadata+=s;
		l-=s;

		switch(cmdtmp)
		{
#if defined(HAVE_WIN32)
			case META_VSS:
				if(set_vss(bfd, m, s, conf)) errors++;
				break;
#endif
#if defined(HAVE_LINUX_OS) || \
    defined(HAVE_FREEBSD_OS) || \
    defined(HAVE_OPENBSD_OS) || \
    defined(HAVE_NETBSD_OS)
#ifdef HAVE_ACL
			case META_ACCESS_ACL:
				if(set_acl(path, statp, m, s, cmdtmp, conf->cntr))
					errors++;
				break;
			case META_DEFAULT_ACL:
				if(set_acl(path, statp, m, s, cmdtmp, conf->cntr))
					errors++;
				break;
#endif
#endif
#if defined(HAVE_LINUX_OS)
#ifdef HAVE_XATTR
			case META_XATTR:
				if(set_xattr(path, statp, m, s, cmdtmp, conf->cntr))
					errors++;
				break;
#endif
#endif
#if defined(HAVE_FREEBSD_OS) || \
    defined(HAVE_OPENBSD_OS) || \
    defined(HAVE_NETBSD_OS)
#ifdef HAVE_XATTR
			case META_XATTR_BSD:
				if(set_xattr(path, statp, m, s, cmdtmp, conf->cntr))
					errors++;
				break;
#endif
#endif
			default:
				logp("unknown metadata: %c\n", cmdtmp);
				logw(conf->cntr, "unknown metadata: %c\n", cmdtmp);
				errors++;
				break;
				
		}
		free(m);
	}

	return errors;
}
