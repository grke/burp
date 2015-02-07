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
	const char *x=NULL;
	const char *y=NULL;
	if(!a && !b) return 0; // equal
	if( a && !b) return 1; // a is longer
	if(!a &&  b) return -1; // b is longer
	for(x=a, y=b; *x && *y ; x++, y++)
	{
		if(*x==*y) continue;
		if(*x=='/' && *y!='/') return -1;
		if(*x!='/' && *y=='/') return 1;
		if(*x<*y) return -1;
		if(*x>*y) return 1;
	}
	if(!*x && !*y) return 0; // equal
	if( *x && !*y) return 1; // x is longer
	return -1; // y is longer
}
