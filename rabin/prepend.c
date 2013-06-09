#include <stdio.h>
#include <string.h>
#include <malloc.h>

#include "prepend.h"

/* This may be given binary data, of which we need to already know the length */
char *prepend_len(const char *prep, size_t plen, const char *fname, size_t flen, const char *sep, size_t slen, size_t *newlen)
{
	size_t l=0;
	char *rpath=NULL;

	l+=plen;
	l+=flen;
	l+=slen;
	l+=1;

	if(!(rpath=(char *)malloc(l)))
	{
		fprintf(stderr, "could not malloc for prepend to %s\n", fname);
		return NULL;
	}
	if(plen) memcpy(rpath,           prep,  plen);
	if(slen) memcpy(rpath+plen,      sep,   slen);
	if(flen) memcpy(rpath+plen+slen, fname, flen);
	rpath[plen+slen+flen]='\0';

	if(newlen) (*newlen)+=slen+flen;
	return rpath;
}

char *prepend(const char *prep, const char *fname, size_t len, const char *sep)
{
	return prepend_len(prep, prep?strlen(prep):0,
		fname, len,
		sep, (sep && *fname)?strlen(sep):0, NULL);
}

char *prepend_s(const char *prep, const char *fname, size_t len)
{
	if(!prep || !*prep)
	{
		char *ret=NULL;
		if(!(ret=strdup(fname)))
			fprintf(stderr, "Out of memory in %s\n", __FUNCTION__);
		return ret;
	}
	// Try to avoid getting a double slash in the path.
	if(fname && fname[0]=='/')
	{
		fname++;
		len--;
	}
	return prepend(prep, fname, len, "/");
}
