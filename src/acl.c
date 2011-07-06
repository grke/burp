#include "burp.h"
#include "prog.h"
#include "acl.h"
#include "cmd.h"
#include "log.h"
#include "asyncio.h"
#include "handy.h"
#include "extrameta.h"

#ifdef HAVE_ACL
#if defined(HAVE_LINUX_OS) || \
    defined(HAVE_FREEBSD_OS)
#include "sys/acl.h"

/* Linux can do shorter ACLs */
#if defined(HAVE_LINUX_OS)
#include <acl/libacl.h>
#define acl_to_text(acl,len)	    (acl_to_any_text((acl), NULL, ',', TEXT_ABBREVIATE|TEXT_NUMERIC_IDS))
#endif

// section of acl_is_trivial copied from bacula 
static int acl_is_trivial(acl_t acl)
{
  /*
   * acl is trivial if it has only the following entries:
   * "user::",
   * "group::",
   * "other::"
   */
   acl_entry_t ace;
   acl_tag_t tag;
#if defined(HAVE_FREEBSD_OS) || \
    defined(HAVE_LINUX_OS)
   int entry_available;

   entry_available = acl_get_entry(acl, ACL_FIRST_ENTRY, &ace);
   while (entry_available == 1) {
      /*
       * Get the tag type of this acl entry.
       * If we fail to get the tagtype we call the acl non-trivial.
       */
      if (acl_get_tag_type(ace, &tag) < 0)
         return true;
      /*
       * Anything other the ACL_USER_OBJ, ACL_GROUP_OBJ or ACL_OTHER breaks the 
spell.
       */
      if (tag != ACL_USER_OBJ &&
          tag != ACL_GROUP_OBJ &&
          tag != ACL_OTHER)
         return 0;
      entry_available = acl_get_entry(acl, ACL_NEXT_ENTRY, &ace);
   }
#endif
   return 1;
}

static acl_t acl_contains_something(const char *path, int acl_type)
{
	acl_t acl=NULL;
	if((acl=acl_get_file(path, acl_type)))
	{
		if(acl_is_trivial(acl))
		{
			acl_free(acl);
			return NULL;
		}
		return acl;
	}
	return NULL;
}

int has_acl(const char *path, char cmd)
{
	acl_t acl=NULL;
	if((acl=acl_contains_something(path, ACL_TYPE_ACCESS)))
	{
		acl_free(acl);
		return 1;
	}

	if(cmd==CMD_DIRECTORY)
	{
		if((acl=acl_contains_something(path, ACL_TYPE_DEFAULT)))
		{
			acl_free(acl);
			return 1;
		}
	}

	return 0;
}

static int get_acl_string(acl_t acl, char **acltext, const char *path, char type, struct cntr *cntr)
{
	ssize_t s=0;
	char pre[10]="";
	char *tmp=NULL;
	char *ourtext=NULL;
	ssize_t maxlen=0xFFFFFFFF/2;

	if(!(tmp=acl_to_text(acl, NULL)))
	{
		logw(cntr, "could not get ACL text of '%s'\n", path);
		return 0; // carry on
	}

	s=strlen(tmp);

	if(s>maxlen)
	{
		logw(cntr, "ACL of '%s' too long: %d\n", path, s);
		if(tmp) acl_free(tmp);
		return 0; // carry on
	}

	snprintf(pre, sizeof(pre), "%c%08X", type, (unsigned int)s);
	if(!(ourtext=prepend(pre, tmp, s, "")))
	{
		if(tmp) acl_free(tmp);
		return -1;
	}
	if(tmp) acl_free(tmp);
	if(!*acltext)
	{
		*acltext=ourtext;
		return 0;
	}
	if(!(*acltext=prepend(*acltext, ourtext, s+9, "")))
	{
		if(ourtext) free(ourtext);
		return -1;
	}
	if(ourtext) free(ourtext);
	return 0;
}

int get_acl(const char *path, struct stat *statp, char **acltext, struct cntr *cntr)
{
	acl_t acl=NULL;

	if((acl=acl_contains_something(path, ACL_TYPE_ACCESS)))
	{
		if(get_acl_string(acl,
			acltext, path, META_ACCESS_ACL, cntr))
		{
			acl_free(acl);
			return -1;
		}
		acl_free(acl);
	}

	if(S_ISDIR(statp->st_mode))
	{
		if((acl=acl_contains_something(path, ACL_TYPE_DEFAULT)))
		{
			if(get_acl_string(acl,
				acltext, path, META_DEFAULT_ACL, cntr))
			{
				acl_free(acl);
				return -1;
			}
			acl_free(acl);
		}
	}
	return 0;
}

static int do_set_acl(const char *path, struct stat *statp, const char *acltext, int acltype, struct cntr *cntr)
{
	acl_t acl;
	if(!(acl=acl_from_text(acltext)))
	{
		logp("acl_from_text error on %s (%s): %s\n",
			path, acltext, strerror(errno));
		logw(cntr, "acl_from_text error on %s (%s): %s\n",
			path, acltext, strerror(errno));
		return -1;
	}
//#ifndef HAVE_FREEBSD_OS // Bacula says that acl_valid fails on valid input
			// on freebsd. It works OK for me on FreeBSD 8.2.
	if(acl_valid(acl))
	{
		logp("acl_valid error on %s: %s", path, strerror(errno));
		logw(cntr, "acl_valid error on %s: %s", path, strerror(errno));
		acl_free(acl);
		return -1;
	}
//#endif
	if(acl_set_file(path, acltype, acl))
	{
		logp("acl set error on %s: %s", path, strerror(errno));
		logw(cntr, "acl set error on %s: %s", path, strerror(errno));
		acl_free(acl);
		return -1;
	}
	acl_free(acl);
	return 0; 
}

int set_acl(const char *path, struct stat *statp, const char *acltext, char cmd, struct cntr *cntr)
{
	switch(cmd)
	{
		case META_ACCESS_ACL:
			return do_set_acl(path,
				statp, acltext, ACL_TYPE_ACCESS, cntr);
		case META_DEFAULT_ACL:
			return do_set_acl(path,
				statp, acltext, ACL_TYPE_DEFAULT, cntr);
		default:
			logp("unknown acl type: %c\n", cmd);
			logw(cntr, "unknown acl type: %c\n", cmd);
			break;
	}
	return -1;
}

#endif // HAVE_LINUX_OS
#endif // HAVE_ACL
