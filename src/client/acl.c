#include "../burp.h"
#include "../alloc.h"
#include "../cmd.h"
#include "../log.h"
#include "../prepend.h"
#include "../sbuf.h"
#include "acl.h"
#include "extrameta.h"

#ifdef HAVE_ACL
#if defined(HAVE_LINUX_OS) || \
    defined(HAVE_FREEBSD_OS) || \
    defined(HAVE_NETBSD_OS)
#include "sys/acl.h"

/* Linux can do shorter ACLs */
#if defined(HAVE_LINUX_OS)
#include <acl/libacl.h>
#define acl_to_text(acl,len)	    (acl_to_any_text((acl), NULL, ',', TEXT_ABBREVIATE|TEXT_NUMERIC_IDS))
#endif

// section of acl_is_trivial copied from bacula 
static int acl_is_trivial(acl_t acl)
{
#if defined(HAVE_LINUX_OS) \
 || defined(HAVE_FREEBSD_OS) \
 || defined(HAVE_NETBSD_OS)
	/*
	 * acl is trivial if it has only the following entries:
	 * "user::",
	 * "group::",
	 * "other::"
	 */
	acl_entry_t ace;
	acl_tag_t tag;
	int entry_available;

	entry_available = acl_get_entry(acl, ACL_FIRST_ENTRY, &ace);
	while(entry_available==1)
	{
		/*
		 * Get the tag type of this acl entry.
		 * If we fail to get the tagtype we call the acl non-trivial.
		 */
		if (acl_get_tag_type(ace, &tag) < 0)
			return 0;
		/*
		 * Anything other the ACL_USER_OBJ, ACL_GROUP_OBJ
		 * or ACL_OTHER breaks the spell.
		 */
		if(tag!=ACL_USER_OBJ
		  && tag!=ACL_GROUP_OBJ
		  && tag!=ACL_OTHER)
			return 0;
		entry_available=acl_get_entry(acl, ACL_NEXT_ENTRY, &ace);
	}
#endif
	return 1;
}

static int default_acl_contains_something(acl_t acl)
{
	acl_entry_t ace;
	return acl_get_entry(acl, ACL_FIRST_ENTRY, &ace)==1;
}

static acl_t acl_contains_something(const char *path, int acl_type)
{
	acl_t acl=NULL;
	if(!(acl=acl_get_file(path, acl_type)))
		return NULL;
	switch(acl_type)
	{
		case ACL_TYPE_ACCESS:
			if(acl_is_trivial(acl))
				goto nothing;
			break;
		case ACL_TYPE_DEFAULT:
			if(!default_acl_contains_something(acl))
				goto nothing;
			break;
	}
	return acl;
nothing:
	acl_free(acl);
	return NULL;
}

int has_acl(const char *path, enum cmd cmd)
{
	acl_t acl=NULL;
	if((acl=acl_contains_something(path, ACL_TYPE_ACCESS)))
	{
		acl_free(acl);
		return 1;
	}
	if(cmd==CMD_DIRECTORY
	    && (acl=acl_contains_something(path, ACL_TYPE_DEFAULT)))
	{
		acl_free(acl);
		return 1;
	}
	return 0;
}

static int get_acl_string(struct asfd *asfd, acl_t acl, char **acltext,
	size_t *alen, const char *path, char type, struct cntr *cntr)
{
	int ret=0;
	char pre[10]="";
	char *tmp=NULL;
	uint32_t tlen=0;
	char *ourtext=NULL;
	char *oldtext=*acltext;
	uint32_t maxlen=0xFFFFFFFF/2;

	if(!(tmp=acl_to_text(acl, NULL)))
	{
		logw(asfd, cntr, "could not get ACL text of '%s'\n", path);
		goto end; // carry on
	}

	tlen=(uint32_t)strlen(tmp);

	if(tlen>maxlen)
	{
		logw(asfd, cntr, "ACL of '%s' too long: %d\n", path, tlen);
		goto end; // carry on
	}

	snprintf(pre, sizeof(pre), "%c%08X", type, tlen);
	if(!(ourtext=prepend(pre, tmp))
	  || !(*acltext=prepend_len(oldtext,
		*alen, ourtext, tlen+9, "", 0, alen)))
			ret=-1;
	free_w(&oldtext);
end:
	if(tmp) acl_free(tmp);
	free_w(&ourtext);
	return ret;
}

int get_acl(struct asfd *asfd, const char *path, int isdir,
	char **acltext, size_t *alen, struct cntr *cntr)
{
	int ret=-1;
	acl_t acl=NULL;

	if((acl=acl_contains_something(path, ACL_TYPE_ACCESS)))
	{
		if(get_acl_string(asfd, acl,
			acltext, alen, path, META_ACCESS_ACL, cntr))
				goto end;
	}

	if(isdir)
	{
		if(acl) acl_free(acl);
		if((acl=acl_contains_something(path, ACL_TYPE_DEFAULT)))
		{
			if(get_acl_string(asfd, acl,
				acltext, alen, path, META_DEFAULT_ACL, cntr))
					goto end;
		}
	}
	ret=0;
end:
	if(acl) acl_free(acl);
	return ret;
}

static int do_set_acl(struct asfd *asfd, const char *path,
	const char *acltext, int acltype, struct cntr *cntr)
{
	acl_t acl;
	int ret=-1;
	if(!(acl=acl_from_text(acltext)))
	{
		logp("acl_from_text error on %s (%s): %s\n",
			path, acltext, strerror(errno));
		logw(asfd, cntr, "acl_from_text error on %s (%s): %s\n",
			path, acltext, strerror(errno));
		goto end;
	}
	if(acl_valid(acl))
	{
		logp("acl_valid error on %s: %s", path, strerror(errno));
		logw(asfd, cntr, "acl_valid error on %s: %s\n",
			path, strerror(errno));
		goto end;
	}
	if(acl_set_file(path, acltype, acl))
	{
		logp("acl set error on %s: %s", path, strerror(errno));
		logw(asfd, cntr, "acl set error on %s: %s\n",
			path, strerror(errno));
		goto end;
	}
	ret=0;
end:
	if(acl) acl_free(acl);
	return ret;
}

int set_acl(struct asfd *asfd, const char *path,
	const char *acltext, char metacmd, struct cntr *cntr)
{
	switch(metacmd)
	{
		case META_ACCESS_ACL:
			return do_set_acl(asfd, path,
				acltext, ACL_TYPE_ACCESS, cntr);
		case META_DEFAULT_ACL:
			return do_set_acl(asfd, path,
				acltext, ACL_TYPE_DEFAULT, cntr);
		default:
			logp("unknown acl type: %c\n", metacmd);
			logw(asfd, cntr, "unknown acl type: %c\n", metacmd);
			return -1;
	}
}

#endif
#endif
