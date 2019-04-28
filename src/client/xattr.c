#include "../burp.h"
#include "../alloc.h"
#include "../asfd.h"
#include "../async.h"
#include "../cntr.h"
#include "../log.h"
#include "../prepend.h"
#include "extrameta.h"
#include "xattr.h"

#ifdef HAVE_XATTR

#ifdef HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif
#ifdef HAVE_SYS_EXTATTR_H
#include <sys/extattr.h>
#endif
#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif

#ifdef HAVE_DARWIN_OS
/*
 * OSX doesn't have llistxattr, lgetxattr and lsetxattr but has
 * listxattr, getxattr and setxattr with an extra options argument
 * which mimics the l variants of the functions when we specify
 * XATTR_NOFOLLOW as the options value.
 */
#define llistxattr(path, list, size) \
listxattr((path), (list), (size), XATTR_NOFOLLOW)
#define lgetxattr(path, name, value, size) \
getxattr((path), (name), (value), (size), 0, XATTR_NOFOLLOW)
#define lsetxattr(path, name, value, size, flags) \
setxattr((path), (name), (value), (size), (flags), XATTR_NOFOLLOW)
static const char *acl_skiplist[2] = {
    "com.apple.system.Security",
    NULL
};
#elif HAVE_LINUX_OS
static const char *acl_skiplist[3] = {
    "system.posix_acl_access",
    "system.posix_acl_default",
    NULL
};
#elif HAVE_FREEBSD_OS
static const char *acl_skiplist[2] = {
    "system.posix1e.acl_access", NULL
};
#else
static const char *acl_skiplist[1] = {
	NULL
};
#endif

// Skip xattr entries that were already saved as ACLs.
static int in_skiplist(const char *xattr)
{
	for(int c=0; acl_skiplist[c]; c++)
		if(!strcmp(xattr, acl_skiplist[c]))
			return 1;
	return 0;
}

static int append_to_extrameta(const char *toappend, char metasymbol,
	char **xattrtext, size_t *xlen, uint32_t totallen)
{
	char tmp3[10];
	size_t newlen=0;
	snprintf(tmp3, sizeof(tmp3), "%c%08X", metasymbol, totallen);
	newlen=(*xlen)+9+totallen+1;
	if(!(*xattrtext=(char *)
		realloc_w(*xattrtext, newlen, __func__)))
			return -1;
	memcpy((*xattrtext)+(*xlen), tmp3, 9);
	(*xlen)+=9;
	memcpy((*xattrtext)+(*xlen), toappend, totallen);
	(*xlen)+=totallen;
	(*xattrtext)[*xlen]='\0';
	return 0;
}

#ifndef UTEST
static
#endif
char *get_next_xattr_str(struct asfd *asfd, char **data, size_t *l,
	struct cntr *cntr, uint32_t *s, const char *path)
{
	char *ret=NULL;

	if(*l<8)
	{
		logw(asfd, cntr, "length of xattr '%s' %zd is too short for %s\n",
			*data, *l, path);
		return NULL;
	}

	if((sscanf(*data, "%08X", s))!=1)
	{
		logw(asfd, cntr, "sscanf of xattr '%s' %zd failed for %s\n",
			*data, *l, path);
		return NULL;
	}
	*data+=8;
	*l-=8;
	if(*s>*l)
	{
		logw(asfd, cntr, "requested length %d of xattr '%s' %zd is too long for %s\n",
			*s, *data, *l, path);
		return NULL;
	}
	if(!(ret=(char *)malloc_w((*s)+1, __func__)))
		return NULL;
	memcpy(ret, *data, *s);
	ret[*s]='\0';

	*data+=*s;
	*l-=*s;

	return ret;
}

#ifdef HAVE_SYS_EXTATTR_H
static int namespaces[2] = {
	EXTATTR_NAMESPACE_USER,
	EXTATTR_NAMESPACE_SYSTEM
};

int has_xattr(const char *path)
{
	int i=0;
	for(i=0; i<(int)(sizeof(namespaces)/sizeof(int)); i++)
	{
		if(extattr_list_link(path, namespaces[i], NULL, 0)>0)
			return 1;
	}
	return 0;
}

#define BSD_BUF_SIZE	1024
int get_xattr(struct asfd *asfd, const char *path,
	char **xattrtext, size_t *xlen, struct cntr *cntr)
{
	int i=0;
	uint32_t maxlen=0xFFFFFFFF/2;

	for(i=0; i<(int)(sizeof(namespaces)/sizeof(int)); i++)
	{
		int j=0;
		ssize_t len=0;
		int have_acl=0;
		char *xattrlist=NULL;
		char *cnamespace=NULL;
		uint32_t totallen=0;
		char *toappend=NULL;
		static char z[BSD_BUF_SIZE*2]="";
		char cattrname[BSD_BUF_SIZE]="";
		if((len=extattr_list_link(path, namespaces[i], NULL, 0))<0)
		{
			logw(asfd, cntr, "could not extattr_list_link of '%s': %zd\n",
				path, len);
			return 0; // carry on
		}
		if(!len) continue;
		if(xattrtext && *xattrtext)
		{
			// Already have some meta text, which means that some
			// ACLs were set.
			have_acl++;
		}
		if(!(xattrlist=(char *)calloc_w(1, len+1, __func__)))
			return -1;
		if((len=extattr_list_link(path, namespaces[i], xattrlist, len))<=0)
		{
			logw(asfd, cntr, "could not extattr_list_link '%s': %zd\n",
				path, len);
			free_w(&xattrlist);
			return 0; // carry on
		}
		xattrlist[len]='\0';

		if(extattr_namespace_to_string(namespaces[i], &cnamespace))
		{
			logp("Failed to convert %d into namespace on '%s'\n",
				 namespaces[i], path);
			free_w(&xattrlist);
			return 0; // carry on
		}


		for(j=0; j<(int)len; j+=xattrlist[j]+1)
		{
			int cnt=0;
			char tmp1[9];
			char tmp2[9];
			size_t newlen=0;
			uint32_t zlen=0;
			ssize_t vlen=0;
			char *val=NULL;
			cnt=xattrlist[j];
			if(cnt>((int)sizeof(cattrname)-1))
				cnt=((int)sizeof(cattrname)-1);
			strncpy(cattrname, xattrlist+(j+1), cnt);
			cattrname[cnt]='\0';
			snprintf(z, sizeof(z), "%s.%s",
				cnamespace, cattrname);

			if(have_acl && in_skiplist(z))
				continue;
			zlen=(uint32_t)strlen(z);
			//printf("\ngot: %s (%s)\n", z, path);

			if((vlen=extattr_list_link(path, namespaces[i],
				xattrlist, len))<0)
			{
				logw(asfd, cntr, "could not extattr_list_link on %s for %s: %zd\n", path, cnamespace, vlen);
				continue;
			}
			if(vlen)
			{
				if(!(val=(char *)malloc_w(vlen+1, __func__)))
				{
					free_w(&xattrlist);
					free_w(&toappend);
					return -1;
				}
				if((vlen=extattr_get_link(path, namespaces[i],
					cattrname, val, vlen))<0)
				{
					logw(asfd, cntr, "could not extattr_list_link %s for %s: %zd\n", path, cnamespace, vlen);
					free_w(&val);
					continue;
				}
				val[vlen]='\0';

				if(vlen>maxlen)
				{
					logw(asfd, cntr, "xattr value of '%s' too long: %zd\n",
						path, vlen);
					free_w(&toappend);
					free_w(&val);
					break;
				}
			}

			snprintf(tmp1, sizeof(tmp1), "%08X", zlen);
			snprintf(tmp2, sizeof(tmp2), "%08X", (uint32_t)vlen);
			newlen=totallen+8+zlen+8+vlen;
			if(!(toappend=(char *)realloc_w(toappend, newlen, __func__)))
			{
				free_w(&val);
				free_w(&xattrlist);
				return -1;
			}
			memcpy(toappend+totallen, tmp1, 8);
			totallen+=8;
			memcpy(toappend+totallen, z, zlen);
			totallen+=zlen;
			memcpy(toappend+totallen, tmp2, 8);
			totallen+=8;
			memcpy(toappend+totallen, val, vlen);
			totallen+=vlen;
			free_w(&val);

			if(totallen>maxlen)
			{
				logw(asfd, cntr,
				  "xattr length of '%s' grew too long: %d\n",
				  path, totallen);
				free_w(&val);
				free_w(&toappend);
				free_w(&xattrlist);
				return 0; // carry on
			}
		}

		if(toappend)
		{
			if(append_to_extrameta(toappend, META_XATTR_BSD,
				xattrtext, xlen, totallen))
			{
				free_w(&toappend);
				free_w(&xattrlist);
				return -1;
			}
		}
		free_w(&toappend);
		free_w(&xattrlist);
	}

	return 0;
}

static int do_set_xattr_bsd(struct asfd *asfd,
	const char *path,
	const char *xattrtext, size_t xlen, struct cntr *cntr)
{
	int ret=-1;
	size_t l=0;
	char *data=NULL;
	char *value=NULL;
	char *nspace=NULL;

	data=(char *)xattrtext;
	l=xlen;
	while(l>0)
	{
		ssize_t cnt;
		uint32_t vlen=0;
		int cnspace=0;
		char *name=NULL;

		if(!(nspace=get_next_xattr_str(asfd, &data, &l,
			cntr, &vlen, path))
		  || !(value=get_next_xattr_str(asfd, &data, &l,
			cntr, &vlen, path)))
				goto end;

		// Need to split the name into two parts.
		if(!(name=strchr(nspace, '.')))
		{
			logw(asfd, cntr,
			  "could not split %s into namespace and name on %s\n",
				nspace, path);
			goto end;
		}
		*name='\0';
		name++;

		if(extattr_string_to_namespace(nspace, &cnspace))
		{
			logw(asfd, cntr,
				"could not convert %s into namespace on %s\n",
				nspace, path);
			goto end;
		}

		//printf("set_link: %d %s %s %s\n", cnspace, nspace, name, value);
		if((cnt=extattr_set_link(path,
			cnspace, name, value, vlen))!=vlen)
		{
			logw(asfd, cntr,
				"extattr_set_link error on %s %zd!=%d: %s\n",
				path, cnt, vlen, strerror(errno));
			goto end;
		}

		free_w(&nspace);
		free_w(&value);
	}
	ret=0;
end:
	free_w(&nspace);
	free_w(&value);
	return ret;
}

int set_xattr(struct asfd *asfd, const char *path,
	const char *xattrtext,
	size_t xlen, char metacmd, struct cntr *cntr)
{
	switch(metacmd)
	{
		case META_XATTR_BSD:
			return do_set_xattr_bsd(asfd, path,
				xattrtext, xlen, cntr);
		default:
			logp("unknown xattr type: %c\n", metacmd);
			logw(asfd, cntr, "unknown xattr type: %c\n", metacmd);
			break;
	}
	return -1;
}

#elif HAVE_SYS_XATTR_H

int has_xattr(const char *path)
{
	if(llistxattr(path, NULL, 0)>0) return 1;
	return 0;
}

static int get_toappend(struct asfd *asfd, const char *path,
	char **toappend, const char *xattrlist,
	ssize_t len, uint32_t *totallen,
	int have_acl,
	struct cntr *cntr)
{
	char *val=NULL;
	const char *z=NULL;
	uint32_t maxlen=0xFFFFFFFF/2;

	for(z=xattrlist; z-xattrlist < len; z=strchr(z, '\0')+1)
	{
		char tmp1[9];
		char tmp2[9];
		ssize_t vlen;
		uint32_t zlen=0;
		uint32_t newlen=0;

		free_w(&val);

		if((zlen=(uint32_t)strlen(z))>maxlen)
		{
			logw(asfd, cntr,
				"xattr element of '%s' too long: %d\n",
				path, zlen);
			goto carryon;
		}

		if(have_acl && in_skiplist(z))
			continue;

		if((vlen=lgetxattr(path, z, NULL, 0))<0)
		{
			logw(asfd, cntr,
				"could not lgetxattr on %s for %s: %zd %s\n",
				path, z, vlen, strerror(errno));
			continue;
		}
		if(vlen)
		{
			if(!(val=(char *)malloc_w(vlen+1, __func__)))
				goto error;
			if((vlen=lgetxattr(path, z, val, vlen))<0)
			{
				logw(asfd, cntr,
				  "could not lgetxattr %s for %s: %zd %s\n",
					path, z, vlen, strerror(errno));
				continue;
			}
			val[vlen]='\0';

			if(vlen>maxlen)
			{
				logw(asfd, cntr,
					"xattr value of '%s' too long: %zd\n",
					path, vlen);
				goto carryon;
			}
		}

		snprintf(tmp1, sizeof(tmp1), "%08X", zlen);
		snprintf(tmp2, sizeof(tmp2), "%08X", (uint32_t)vlen);
		newlen=(*totallen)+8+zlen+8+vlen;
		if(!(*toappend=(char *)realloc_w(*toappend, newlen, __func__)))
			goto error;
		memcpy((*toappend)+(*totallen), tmp1, 8);
		*totallen+=8;
		memcpy((*toappend)+(*totallen), z, zlen);
		*totallen+=zlen;
		memcpy((*toappend)+(*totallen), tmp2, 8);
		*totallen+=8;
		memcpy((*toappend)+(*totallen), val, vlen);
		*totallen+=vlen;

		if(*totallen>maxlen)
		{
			logw(asfd, cntr,
				"xattr length of '%s' grew too long: %d\n",
				path, *totallen);
			goto carryon;
		}
	}

	free_w(&val);
	return 0;
error:
	free_w(&val);
	free_w(toappend);
	return -1;
carryon:
	free_w(&val);
	free_w(toappend);
	return 0;
}

int get_xattr(struct asfd *asfd, const char *path,
	char **xattrtext, size_t *xlen, struct cntr *cntr)
{
	int ret=0;
	ssize_t len;
	int have_acl=0;
	char *toappend=NULL;
	char *xattrlist=NULL;
	uint32_t totallen=0;

	if((len=llistxattr(path, NULL, 0))<0)
	{
		logw(asfd, cntr, "could not llistxattr '%s': %zd %s\n",
			path, len, strerror(errno));
		goto end; // Carry on.
	}
	if(!(xattrlist=(char *)calloc_w(1, len, __func__)))
	{
		ret=-1;
		goto end;
	}
	if((len=llistxattr(path, xattrlist, len))<0)
	{
		logw(asfd, cntr, "could not llistxattr '%s': %zd %s\n",
			path, len, strerror(errno));
		goto end; // Carry on.
	}

	if(xattrtext && *xattrtext)
	{
		// Already have some meta text, which means that some
		// ACLs were set.
		have_acl++;
	}

	if(get_toappend(asfd, path, &toappend, xattrlist, len, &totallen,
		have_acl, cntr))
	{
		ret=-1;
		goto end;
	}

	if(toappend)
		ret=append_to_extrameta(toappend, META_XATTR,
			xattrtext, xlen, totallen);
end:
	free_w(&toappend);
	free_w(&xattrlist);
	return ret;
}

static int do_set_xattr(struct asfd *asfd,
	const char *path,
	const char *xattrtext, size_t xlen, struct cntr *cntr)
{
	size_t l=0;
	int ret=-1;
	char *data=NULL;
	char *name=NULL;
	char *value=NULL;

	data=(char *)xattrtext;
	l=xlen;
	while(l>0)
	{
		uint32_t s=0;
		free_w(&name);
		free_w(&value);

		if(!(name=get_next_xattr_str(asfd, &data, &l,
			cntr, &s, path))
		  || !(value=get_next_xattr_str(asfd, &data, &l,
			cntr, &s, path)))
				goto end;
		if(lsetxattr(path, name, value, s, 0))
		{
			logw(asfd, cntr, "lsetxattr error on %s: %s\n",
				path, strerror(errno));
			goto end;
		}
	}

	ret=0;
end:
	free_w(&name);
	free_w(&value);
	return ret;
}

int set_xattr(struct asfd *asfd, const char *path,
	const char *xattrtext, size_t xlen, char metacmd, struct cntr *cntr)
{
	switch(metacmd)
	{
		case META_XATTR:
			return do_set_xattr(asfd,
				path, xattrtext, xlen, cntr);
		default:
			logp("unknown xattr type: %c\n", metacmd);
			logw(asfd, cntr, "unknown xattr type: %c\n", metacmd);
			break;
	}
	return -1;
}
#endif

#ifdef UTEST
int fs_supports_xattr(void)
{
	FILE *fp;
	int ret=-1;
	const char *fname="xattr_test_file";
	if(!(fp=fopen(fname, "w")))
	{
		printf("Could not open %s!\n", fname);
		return 0;
	}
	fclose(fp);
#ifdef HAVE_SYS_EXTATTR_H
	ret=extattr_set_link(fname, EXTATTR_NAMESPACE_USER, "comment", "a", strlen("a"));
#elif HAVE_SYS_XATTR_H
	ret=lsetxattr(fname, "user.comment", "a", strlen("a"), /*flags*/0);
#else
	errno=ENOTSUP;
#endif
	if(ret<0 && errno==ENOTSUP)
	{
		printf("File system does not support xattrs!\n");
		unlink(fname);
		return 0;
	}
	unlink(fname);
	return 1;
}
#endif

#endif
