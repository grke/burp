#include "burp.h"
#include "pathcmp.h"

// Return a number indicating the number of directories matched.
// 0 if it is not a sub-directory.
// Two paths the same counts as a subdirectory.
int is_subdir(const char *dir, const char *sub)
{
	int count=1;
	const char *d=NULL;
	const char *s=NULL;
	const char *dl=NULL;
	const char *sl=NULL;
	if(!sub || !dir) return 0;
	for(s=sl=sub, dl=d=dir; *s && *d; s++, d++)
	{
		if(*s!=*d) break;
		sl=s;
		dl=d;
		if(*s=='/') count++;
	}
	if(!*d && !*s) return count; // Paths were exactly the same.
	if(!*d && *s=='/')
		return count; // 'dir' ended without a slash, for example:
	// dir=/bin sub=/bin/bash
	if(*dl=='/' && *sl=='/' && *(sl+1) && !*(dl+1)) return count;
	return 0;
}

int pathcmp(const char *a, const char *b)
{
	// This should have used 'unsigned chars', but now its too late and
	// everybody has backups with odd sorting. Will have to live with it.
	const char *x=NULL;
	const char *y=NULL;
	if(!a && !b)
		return 0; // equal
	if( a && !b)
		return 1; // a is longer
	if(!a &&  b)
		return -1; // b is longer
	for(x=a, y=b; *x && *y ; x++, y++)
	{
		if(*x==*y)
			continue;
		if(*x=='/' && *y!='/')
			return -1;
		if(*x!='/' && *y=='/')
			return 1;
		// Need to make sure the comparisons are signed.
		// Not doing this caused problems on raspberry pis.
		if((int8_t)*x<(int8_t)*y)
			return -1;
		if((int8_t)*x>(int8_t)*y)
			return 1;
	}
	if(!*x && !*y)
		return 0; // equal
	if( *x && !*y)
		return 1; // x is longer
	return -1; // y is longer
}

// Not really pathcmp functions, but there is nowhere better to put them.
int has_dot_component(const char *path)
{
	const char *p=NULL;
	for(p=path; *p; p++)
	{
		if(*p!='.')
			continue;
		// Check for single dot.
		if((p==path || *(p-1)=='/') && (*(p+1)=='/' || !*(p+1)))
			return 1;
		// Check for double dot.
		if(*(p+1)=='.'
		  && (p==path || *(p-1)=='/') && (*(p+2)=='/' || !*(p+2)))
			return 1;
	}
	return 0;
}

int is_absolute(const char *path)
{
	if(has_dot_component(path))
		return 0;
// This is being run on the server too, where you can enter paths for the
// clients, so need to allow windows style paths for windows and unix.
	return (isalpha(*path) && *(path+1)==':')
#ifndef HAVE_WIN32
	// Windows does not need to check for unix style paths.
	  || *path=='/'
#endif
	;
}
