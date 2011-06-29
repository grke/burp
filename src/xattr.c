#include "burp.h"
#include "prog.h"
#include "xattr.h"
#include "cmd.h"
#include "log.h"
#include "asyncio.h"
#include "handy.h"
#include "extrameta.h"

#ifdef HAVE_XATTR
#if defined(HAVE_LINUX_OS)
#include <sys/xattr.h>

static const char *xattr_acl_skiplist[3] = { "system.posix_acl_access", "system.posix_acl_default", NULL };
//static const char *xattr_skiplist[1] = { NULL };

int has_xattr(const char *path, char cmd)
{
	if(llistxattr(path, NULL, 0)>0) return 1;
	return 0;
}

int get_xattr(const char *path, struct stat *statp, char **xattrtext, struct cntr *cntr)
{
	char *x=NULL;
	ssize_t len=0;
	int have_acl=0;
	char *toappend=NULL;
	char *xattrlist=NULL;
	ssize_t totallen=0;
	ssize_t maxlen=0xFFFFFFFF/2;

	if((len=llistxattr(path, NULL, 0))<=0)
	{
		logw(cntr, "could not llistxattr of '%s': %d\n", path, len);
		return 0; // carry on
	}
	if(!(xattrlist=(char *)malloc(len+1)))
	{
		logp("out of memory\n");
		return -1;
	}
	memset(xattrlist, 0, len+1);
	if((len=llistxattr(path, xattrlist, len))<=0)
	{
		logw(cntr, "could not llistxattr '%s': %d\n", path, len);
		free(xattrlist);
		return 0; // carry on
	}
	xattrlist[len]='\0';

	if(xattrtext && *xattrtext)
	{
		// Already have some meta text, which means that some
		// ACLs were set.
		have_acl++;
	}

	x=xattrlist;
	for(x=xattrlist; (x-xattrlist)+1 < len; x=strchr(x, '\0')+1)
	{
		char tmp1[9];
		char tmp2[9];
		char *val=NULL;
		ssize_t vlen=0;
		ssize_t xlen=0;

		if((xlen=strlen(x))>maxlen)
		{
                	logw(cntr, "xattr element of '%s' too long: %d\n",
				path, xlen);
			if(toappend) { free(toappend); toappend=NULL; }
			break;
		}

		if(have_acl)
		{
			int c=0;
			int skip=0;
			// skip xattr entries that were already saved as ACLs.
			for(c=0; xattr_acl_skiplist[c]; c++)
			{
				if(!strcmp(x, xattr_acl_skiplist[c]))
				{
					skip++;
					break;
				}
			}
			if(skip) continue;
		}

		if((vlen=lgetxattr(path, x, NULL, 0))<=0)
		{
			logw(cntr, "could not lgetxattr on %s for %s: %d\n",
				path, x, vlen);
			continue;
		}
		if(!(val=(char *)malloc(vlen+1)))
		{
			logp("out of memory\n");
			free(xattrlist);
			if(toappend) free(toappend);
			return -1;
		}
		if((vlen=lgetxattr(path, x, val, vlen))<=0)
		{
			logw(cntr, "could not lgetxattr %s for %s: %d\n",
				path, x, vlen);
			free(val);
			continue;
		}
		val[vlen]='\0';

		if(vlen>maxlen)
		{
                	logw(cntr, "xattr value of '%s' too long: %d\n",
				path, vlen);
			if(toappend) { free(toappend); toappend=NULL; }
			free(val);
			break;
		}

		snprintf(tmp1, sizeof(tmp1), "%08X", xlen);
		snprintf(tmp2, sizeof(tmp2), "%08X", vlen);
		if(!(toappend=prepend(toappend, tmp1, 8, ""))
		  || !(toappend=prepend(toappend, x, xlen, ""))
		  || !(toappend=prepend(toappend, tmp2, 8, ""))
		  || !(toappend=prepend(toappend, val, vlen, "")))
		{
			logp("out of memory\n");
			free(val);
			free(xattrlist);
			return -1;
		}
		free(val);

		totallen+=8+xlen+8+vlen;

		if(totallen>maxlen)
		{
                	logw(cntr, "xattr length of '%s' grew too long: %d\n",
				path, totallen);
			free(val);
			free(toappend);
			free(xattrlist);
			return 0; // carry on
		}
	}

	if(toappend)
	{
		char tmp3[10];
		snprintf(tmp3, sizeof(tmp3), "%c%08X", META_XATTR, totallen);
		if(!(*xattrtext=prepend(*xattrtext,
			tmp3, 9, ""))
		  || !(*xattrtext=prepend(*xattrtext,
			toappend, totallen, "")))
		{
			logp("out of memory\n");
			free(toappend);
			free(xattrlist);
			return -1;
		}
		free(toappend);
	}
	free(xattrlist);
	return 0;
}

static char *get_next_str(char **data, ssize_t *l, struct cntr *cntr)
{
	char *ret=NULL;
	unsigned int s=0;

	if((sscanf(*data, "%08X", &s))!=1)
	{
		logp("sscanf of xattr failed\n");
		logw(cntr, "sscanf of xattr failed\n");
		return NULL;
	}
	*data+=8;
	*l-=8;
	if(!(ret=(char *)malloc(s+1)))
	{
		logp("out of memory\n");
		return NULL;
	}
	memcpy(ret, *data, s);
	ret[s]='\0';

	*data+=s;
	*l-=s;

	return ret;
}

static int do_set_xattr(const char *path, struct stat *statp, const char *xattrtext, struct cntr *cntr)
{
	ssize_t l=0;
	char *data=NULL;

	data=(char *)xattrtext;
	l=strlen(data);
	while(l>0)
	{
		char *name=NULL;
		char *value=NULL;

		if(!(name=get_next_str(&data, &l, cntr)))
			return -1;
		if(!(value=get_next_str(&data, &l, cntr)))
		{
			free(name);
			return -1;
		}

		if(lsetxattr(path, name, value, strlen(value), 0))
		{
			logw(cntr, "lsetxattr error on %s: %s\n",
				path, strerror(errno));
			free(name);
			free(value);
			return -1;
		}

		free(name);
		free(value);
	}

	return 0;
}

int set_xattr(const char *path, struct stat *statp, const char *xattrtext, char cmd, struct cntr *cntr)
{
	switch(cmd)
	{
		case META_XATTR:
			return do_set_xattr(path, statp, xattrtext, cntr);
		default:
			logp("unknown xattr type: %c\n", cmd);
			logw(cntr, "unknown xattr type: %c\n", cmd);
			break;
	}
	return -1;
}

#endif // HAVE_LINUX_OS
#endif // HAVE_XATTR
