#include "burp.h"
#include "alloc.h"
#include "log.h"
#include "prepend.h"

/* This may be given binary data, of which we need to already know the length */
char *prepend_len(const char *prep, size_t plen, const char *fname,
	size_t flen, const char *sep, size_t slen, size_t *newlen)
{
	size_t l=0;
	char *rpath=NULL;

	l+=plen;
	l+=flen;
	l+=slen;
	l+=1;

	if(!(rpath=(char *)malloc_w(l, __func__)))
		return NULL;
	if(plen) memcpy(rpath,           prep,  plen);
	if(slen) memcpy(rpath+plen,      sep,   slen);
	if(flen) memcpy(rpath+plen+slen, fname, flen);
	rpath[plen+slen+flen]='\0';

	if(newlen) (*newlen)+=slen+flen;
	return rpath;
}

char *prepend_n(const char *prep, const char *fname,
	size_t len, const char *sep)
{
	return prepend_len(prep, prep?strlen(prep):0,
		fname, len,
		sep, (sep && *fname)?strlen(sep):0, NULL);
}

char *prepend(const char *prep, const char *fname)
{
	return prepend_n(prep, fname, strlen(fname), "");
}

char *prepend_slash(const char *prep, const char *fname, size_t len)
{
	if(!prep || !*prep)
		return strdup_w(fname, __func__);
	// Try to avoid getting a double slash in the path.
	if(fname && fname[0]=='/')
	{
		fname++;
		len--;
	}
	return prepend_n(prep, fname, len, "/");
}

char *prepend_s(const char *prep, const char *fname)
{
	return prepend_slash(prep, fname, strlen(fname));
}

int astrcat(char **buf, const char *append, const char *func)
{
	int l=0;
	char *copy=NULL;
	if(append) l+=strlen(append);
	if(*buf) l+=strlen(*buf);
	l++;
	if((*buf && !(copy=strdup_w(*buf, __func__)))
	  || !(*buf=(char *)realloc_w(*buf, l, __func__)))
	{
		log_oom_w(__func__, func);
		return -1;
	}
	snprintf(*buf, l, "%s%s", copy?copy:"", append?append:"");
	free_w(&copy);
	return 0;
}
