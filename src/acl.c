#include "burp.h"
#include "prog.h"
#include "acl.h"
#include "cmd.h"
#include "log.h"
#include "asyncio.h"
#include "handy.h"

#ifdef HAVE_ACL
#include "sys/acl.h"
#include "acl/libacl.h"

// acl_is_trivial copied from bacula 
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
	char pre[8]="";
	char *tmp=NULL;
	char *ourtext=NULL;
	if(!(tmp=acl_to_any_text(acl, NULL, ':',
		TEXT_NUMERIC_IDS|TEXT_ABBREVIATE)))
	{
		logp("could not get ACL text of '%s'\n", path);
		return -1;
	}
	s=strlen(tmp);

	if(s>0xFFFF)
	{
		logw(cntr, "ACL of '%s' too long: %d\n", path, s);
		if(tmp) acl_free(tmp);
		return 0;
	}

	snprintf(pre, sizeof(pre), "%c%04X", type, (unsigned int)s);
	if(!(ourtext=prepend(pre, tmp, s, "")))
	{
		if(tmp) acl_free(tmp);
		return -1;
	}
	if(tmp) acl_free(tmp);
	if(!*acltext)
	{
		*acltext=ourtext;
		return  0;
	}
	if(!(*acltext=prepend(*acltext, ourtext, s+5, "")))
	{
		if(ourtext) free(ourtext);
		return -1;
	}
	if(ourtext) free(ourtext);
	return 0;
}

int get_acl(const char *path, char cmd, char **acltext, struct cntr *cntr)
{
	acl_t acl=NULL;
	if((acl=acl_contains_something(path, ACL_TYPE_ACCESS)))
	{
		if(get_acl_string(acl, acltext, path, 'A', cntr))
		{
			acl_free(acl);
			return -1;
		}
		acl_free(acl);
	}

	if(cmd==CMD_DIRECTORY)
	{
		if((acl=acl_contains_something(path, ACL_TYPE_DEFAULT)))
		{
			if(get_acl_string(acl, acltext, path, 'D', cntr))
			{
				acl_free(acl);
				return -1;
			}
			acl_free(acl);
		}
	}
	return 0;
}

#endif // HAVE_ACL
