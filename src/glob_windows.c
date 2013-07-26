// Windows glob stuff by ziirish
// Most of the x...() functions are probably not really necessary and can be
// cleaned up. They are also not really doing things the 'burp way' - ie,
// things running out of memory should return an error, not just exit.

#include "burp.h"
#include "prog.h"
#include "glob_windows.h"

static void xfree(void *ptr)
{
	if(ptr) free(ptr);
}

static void xfree_list(char **list, int size)
{
	if(!list) return;
	if(size<0)
		for(; *list; list++) xfree(*list);
	else
	{
		int i;
		for (i=0; i<size; i++) xfree(list[i]);
	}
	xfree(list);
}

static size_t xstrlen(const char *in)
{
	size_t cpt;
	const char *s;
	if(!in) return 0;
	/* we want to avoid an overflow in case the input string isn't null
	   terminated */
	for(s=in, cpt=0; *s && cpt<UINT_MAX; ++s, cpt++);
	return (s-in);
}

static void *xmalloc(size_t size)
{
	void *ret=malloc(size);
	if(!ret) return ret;
	logp("xmalloc can not allocate %lu bytes", (u_long)size);
	exit(2);
}

static void *xcalloc(size_t nmem, size_t size)
{
	void *ret=calloc(nmem, size);
	if(ret) return ret;
	logp("xcalloc can not allocate %lu bytes", (u_long)(size*nmem));
	exit(2);
}

static void *xrealloc(void *src, size_t new_size)
{
	void *ret;
	if(src) ret=realloc(src, new_size);
	else ret=xmalloc(new_size);
	if(ret) return ret;
	logp("xrealloc can not reallocate %lu bytes", (u_long)new_size);
	exit(2);
}

static char *xstrdup(const char *dup)
{
	size_t len;
	char *copy;

	len=xstrlen(dup);
	if(!len) return NULL;
	copy = (char *)xmalloc(len+1);
	if(copy) strncpy(copy, dup, len+1);
	return copy;
}

static char *xstrcat(char *dest, const char *src)
{
	char *save=xstrdup(dest);
	size_t len=xstrlen(save)+xstrlen(src)+1;
	xfree(dest);
	dest=(char *)xmalloc(len);
	if(!dest)
	{
		xfree(save);
		return NULL;
	}
	snprintf(dest, len, "%s%s", save?save:"", src);
	xfree(save);
	return dest;
}

static char **xstrsplit(const char *src, const char *token, size_t *size)
{
	char **ret;
	int n=1;
	char *tmp;
	char *init;
	init=xstrdup(src);
	tmp=strtok(init, token);
	*size = 0;
	if(!tmp)
	{
		xfree(init);
		return NULL;
	}
	ret=(char **)xcalloc(10, sizeof(char *));
	while(tmp)
	{
		if((int)*size>n*10)
		{
			char **newstr=(char **)xrealloc(ret, n++*10*sizeof(char *));
			if(!newstr)
			{
				for(; *size>0; (*size)--) xfree(ret[*size-1]);
				xfree(ret);
				xfree(init);
				return NULL;
			}
			ret=newstr;
		}
		ret[*size]=xstrdup(tmp);
		tmp=strtok(NULL, token);
		(*size)++;
	}
	if((int)*size+1>n*10)
		ret=(char **)xrealloc(ret, (n*10+1)*sizeof(char *));
	ret[*size+1]=NULL;

	xfree(init);
	return ret;
}

static inline int xmin(int a, int b)
{
	return a<b?a:b;
}

static inline int xmax(int a, int b)
{
	return a>b?a:b;
}

static char *xstrsub(const char *src, int begin, int len)
{
	int l;
	int ind;
	char *ret;
	size_t s_full;
	if(!src) return NULL;

	s_full=xstrlen(src);
	if(len==-1) l=(int)s_full;
	else l=len;

	ret=(char *)xmalloc((xmin(s_full, l)+1)*sizeof(char));
	ind=begin<0?xmax((int) s_full+begin, 0):xmin(s_full, begin);

	strncpy(ret, src+ind, xmin(s_full, l));
	ret[xmin(s_full, l)] = '\0';

	return ret;
}

int windows_glob(struct config *conf, struct strlist ***ielist)
{
	int i;
        WIN32_FIND_DATA ffd;
        HANDLE hFind = INVALID_HANDLE_VALUE;

	for(i=0; i<conf->igcount; i++)
	{
		char *sav=NULL;
		char *tmppath = NULL;
		char **splitstr1 = NULL;
		size_t len1 = 0;
		convert_backslashes(&(conf->incglob[i]->path));
		if(conf->incglob[i]->path[strlen(conf->incglob[i]->path)-1]!='*')
			splitstr1=xstrsplit(conf->incglob[i]->path, "*", &len1);
		if(len1>2)
		{
			logp("include_glob error: '%s' contains at list two '*' which is not currently supported\n", conf->incglob[i]->path);
			xfree_list(splitstr1, len1);
			continue;
		}
		if(len1>1)
		{
			tmppath = xstrcat(tmppath, splitstr1[0]);
			sav = xstrdup(tmppath);
			tmppath = xstrcat(tmppath, "*");
			hFind = FindFirstFileA(tmppath, &ffd);
			xfree(tmppath);
			tmppath = NULL;
		}
		else
			hFind = FindFirstFileA(conf->incglob[i]->path, &ffd);
		if(INVALID_HANDLE_VALUE==hFind)
		{
			LPVOID lpMsgBuf;
			DWORD dw=GetLastError(); 
			FormatMessage(
				FORMAT_MESSAGE_ALLOCATE_BUFFER | 
				FORMAT_MESSAGE_FROM_SYSTEM |
				FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL,
				dw,
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				(LPTSTR) &lpMsgBuf,
				0, NULL );
			logp("Error: %s\n", lpMsgBuf);
			LocalFree(lpMsgBuf);
			if(splitstr1)
			{
				xfree(sav);
				xfree_list(splitstr1, len1);
			}
			continue;
		}
		do
		{
			if(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY
			   && strcmp(ffd.cFileName, ".") != 0
			   && strcmp(ffd.cFileName, "..") != 0)
			{
				if(len1<2)
				{
					if(conf->incglob[i]->path[xstrlen(conf->incglob[i]->path)-1] == '*')
					{
						tmppath=xstrsub(conf->incglob[i]->path, 0, xstrlen(conf->incglob[i]->path)-1);
						tmppath=xstrcat(tmppath, ffd.cFileName);
					}
					else
						tmppath=xstrdup(conf->incglob[i]->path);
				}
				else
				{
					tmppath=xstrcat(tmppath, sav);
					tmppath=xstrcat(tmppath, ffd.cFileName);
					tmppath=xstrcat(tmppath, splitstr1[1]);
				}
				strlist_add(ielist, &(conf->iecount), tmppath, 1);
				xfree(tmppath);
				tmppath = NULL;
			}
		}
		while(FindNextFileA(hFind, &ffd)!=0);
		FindClose(hFind);
		if(splitstr1)
		{
			xfree(sav);
			xfree_list(splitstr1, len1);
		}
	}
	return 0;
}
