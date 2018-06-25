#ifdef HAVE_WIN32

// Windows glob stuff originally by ziirish.

#include "../burp.h"
#include "../alloc.h"
#include "../handy.h"
#include "../log.h"
#include "../strlist.h"

static void xfree_list(char **list, int size)
{
	if(!list) return;
	if(size<0)
	{
		for(; *list; list++)
			if(*list) free_w(list);
	}
	else
	{
		int i;
		for(i=0; i<size; i++)
			if(list[i]) free_w(&list[i]);
	}
	free_w(list);
}

/*
 * Returns NULL-terminated list of tokens found in string src,
 * also sets *size to number of tokens found (list length without final NULL).
 * On failure returns NULL. List itself and tokens are dynamically allocated.
 * Calls to strtok with delimiters in second argument are used (see its docs),
 * but neither src nor delimiters arguments are altered.
 */
static char **xstrsplit(const char *src, const char *delimiters, size_t *size)
{
	size_t allocated;
	char *init=NULL;
	char **ret=NULL;

	*size=0;
	if(!(init=strdup_w(src, __func__))) goto end;
	if(!(ret=(char **)malloc_w((allocated=10)*sizeof(char *), __func__)))
		goto end;
	for(char *tmp=strtok(init, delimiters); tmp; tmp=strtok(NULL, delimiters))
	{
		// Check if space is present for another token and terminating NULL.
		if(allocated<*size+2)
		{
			if(!(ret=(char **)realloc_w(ret,
				(allocated=*size+11)*sizeof(char *), __func__)))
					return NULL;
		}
		if(!(ret[(*size)++]=strdup_w(tmp, __func__)))
		{
			ret=NULL;
			goto end;
		}
	}
	ret[*size]=NULL;

end:
	free_w(&init);
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

	s_full=strlen(src);
	if(len==-1) l=(int)s_full;
	else l=len;

	if(!(ret=(char *)malloc_w((xmin(s_full, l)+1)*sizeof(char), __func__)))
		return NULL;
	ind=begin<0?xmax((int) s_full+begin, 0):xmin(s_full, begin);

	strncpy(ret, src+ind, xmin(s_full, l));
	ret[xmin(s_full, l)] = '\0';

	return ret;
}

static int process_entry(struct strlist *ig, struct conf **confs)
{
	int ret=-1;
	size_t len1=0;
	char *sav=NULL;
	char **splitstr1=NULL;
        WIN32_FIND_DATA ffd;
        HANDLE hFind=INVALID_HANDLE_VALUE;

	convert_backslashes(&ig->path);
	if(ig->path[strlen(ig->path)-1]!='*')
	{
		if(!(splitstr1=xstrsplit(ig->path, "*", &len1)))
			goto end;
	}
	if(len1>2)
	{
		logp("include_glob error: '%s' contains at least"
			" two '*' which is not currently supported\n",
				ig->path);
		goto end;
	}
	if(len1>1)
	{
		char *tmppath=NULL;
		if(astrcat(&tmppath, splitstr1[0], __func__)
		  || !(sav=strdup_w(tmppath, __func__))
		  || astrcat(&tmppath, "*", __func__))
			goto end;
		hFind=FindFirstFileA(tmppath, &ffd);
		free_w(&tmppath);
	}
	else
		hFind=FindFirstFileA(ig->path, &ffd);

	if(hFind==INVALID_HANDLE_VALUE)
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
			(LPTSTR)&lpMsgBuf,
			0, NULL );
		logp("Error: %s\n", (char *)lpMsgBuf);
		LocalFree(lpMsgBuf);
		goto end;
	}

	do
	{
		if(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY
		   && strcmp(ffd.cFileName, ".")
		   && strcmp(ffd.cFileName, ".."))
		{
			char *tmppath=NULL;
			if(len1<2)
			{
				if(ig->path[strlen(ig->path)-1]=='*')
				{
					if(!(tmppath=xstrsub(ig->path, 0,
						strlen(ig->path)-1))
					  || astrcat(&tmppath,
						ffd.cFileName, __func__))
							goto end;
				}
				else
					if(!(tmppath=strdup_w(ig->path,
						__func__))) goto end;
			}
			else
			{
				if(astrcat(&tmppath, sav, __func__)
				  || astrcat(&tmppath, ffd.cFileName, __func__)
				  || astrcat(&tmppath, splitstr1[1], __func__))
					goto end;
			}
			if(add_to_strlist(confs[OPT_INCLUDE], tmppath, 1))
				goto end;
			free_w(&tmppath);
		}
	}
	while(FindNextFileA(hFind, &ffd)!=0);

	FindClose(hFind);
	ret=0;
end:
	if(splitstr1)
	{
		free_w(&sav);
		xfree_list(splitstr1, len1);
	}
	return ret;
}

int glob_windows(struct conf **confs)
{
	struct strlist *ig;

	for(ig=get_strlist(confs[OPT_INCGLOB]); ig; ig=ig->next)
		if(process_entry(ig, confs)) return -1;
	return 0;
}

#endif
