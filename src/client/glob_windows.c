#ifdef HAVE_WIN32

// Windows glob stuff originally by ziirish.

#include "../burp.h"
#include "../alloc.h"
#include "../handy.h"
#include "../log.h"
#include "../strlist.h"

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
	char *tmppath=NULL;

	convert_backslashes(&ig->path);
	if(ig->path[strlen(ig->path)-1]!='*')
	{
		if(!(splitstr1=strsplit_w(ig->path, "*", &len1, __func__)))
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
		if(astrcat(&tmppath, splitstr1[0], __func__)
		  || !(sav=strdup_w(tmppath, __func__))
		  || astrcat(&tmppath, "*", __func__))
			goto end;
	}
	else
	{
		if(astrcat(&tmppath, ig->path, __func__))
			goto end;
	}

	hFind=FindFirstFileA(tmppath, &ffd);

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
		logp("include_glob error (%s): %s\n",
			tmppath, (char *)lpMsgBuf);
		LocalFree(lpMsgBuf);
		goto end;
	}

	do
	{
		if(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY
		   && strcmp(ffd.cFileName, ".")
		   && strcmp(ffd.cFileName, ".."))
		{
			free_w(&tmppath);
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
			if(add_to_strlist(confs[OPT_INCLUDE],
				tmppath, 1))
					goto end;
		}
	}
	while(FindNextFileA(hFind, &ffd)!=0);

	FindClose(hFind);
	ret=0;
end:
	free_w(&tmppath);
	if(splitstr1)
	{
		free_w(&sav);
		free_list_w(&splitstr1, len1);
	}
	return ret;
}

static int expand_windows_drives(struct conf **confs)
{
	struct strlist *ig_o=NULL;
	struct strlist *ig_n=NULL;
	char *drives_detected=NULL;

	if(!(drives_detected=get_fixed_drives()) || !*drives_detected)
	{
		logp("Could not detect windows drives.\n");
		return -1;
	}
	logp("windows drives detected: %s\n", drives_detected);

	for(ig_o=get_strlist(confs[OPT_INCGLOB]); ig_o; ig_o=ig_o->next)
	{
		if(!strncmp(ig_o->path, "*:", strlen("*:")))
		{
			size_t d;
			for(d=0; d<strlen(drives_detected); d++)
			{
				ig_o->path[0]=drives_detected[d];
				if(strchr(ig_o->path, '*'))
				{
					// More to expand later.
					if(strlist_add(&ig_n,
						ig_o->path, 1))
							return -1;
				}
				else
				{
					// Nothing else to expand, just add it
					// straight onto the includes - but
					// only if the expanded path actually
					// exists.
					char *rp;
					if(!(rp=realpath(ig_o->path, NULL)))
					{
						switch(errno)
						{
							case ENOENT:
								continue;
							case ENOMEM:
								return -1;
							case EACCES:
							default:
								// Add anyway,
								// for warnings
								// later.
								break;
						}
					}
					free_w(&rp);

					if(add_to_strlist(confs[OPT_INCLUDE],
						ig_o->path, 1))
							return -1;
				}
			}
			continue;
		}

		if(strlist_add(&ig_n, ig_o->path, 1))
			return -1;
	}

	set_strlist(confs[OPT_INCGLOB], ig_n);

	return 0;
}

int glob_windows(struct conf **confs)
{
	struct strlist *ig=NULL;

	if(expand_windows_drives(confs))
		return -1;

	for(ig=get_strlist(confs[OPT_INCGLOB]); ig; ig=ig->next)
		if(process_entry(ig, confs))
			return -1;

	return 0;
}

#endif
