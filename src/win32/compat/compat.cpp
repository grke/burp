#include "burp.h"
#include "compat.h"
#include "prog.h"
#include "time.h"
#include "mem_pool.h"

#define b_errno_win32 (1<<29)

#define MAX_PATHLENGTH  1024

/* UTF-8 to UCS2 path conversion is expensive,
   so we cache the conversion. During backup the
   conversion is called 3 times (lstat, attribs, open),
   by using the cache this is reduced to 1 time */

static char *g_pWin32ConvUTF8Cache = NULL;
static char *g_pWin32ConvUCS2Cache = NULL;
static DWORD g_dwWin32ConvUTF8strlen = 0;

static t_pVSSPathConvert   g_pVSSPathConvert;
static t_pVSSPathConvertW  g_pVSSPathConvertW;

/* Forward referenced functions */
static const char *errorString(void);


void SetVSSPathConvert(t_pVSSPathConvert pPathConvert, t_pVSSPathConvertW pPathConvertW)
{
   g_pVSSPathConvert = pPathConvert;
   g_pVSSPathConvertW = pPathConvertW;
}

static void Win32ConvInitCache()
{
   if (g_pWin32ConvUTF8Cache) {
      return;
   }
   g_pWin32ConvUTF8Cache = sm_get_pool_memory(PM_FNAME);
   g_pWin32ConvUCS2Cache = sm_get_pool_memory(PM_FNAME);
}

void Win32ConvCleanupCache()
{
   if (g_pWin32ConvUTF8Cache) {
      sm_free_pool_memory(g_pWin32ConvUTF8Cache);
      g_pWin32ConvUTF8Cache = NULL;
   }

   if (g_pWin32ConvUCS2Cache) {
      sm_free_pool_memory(g_pWin32ConvUCS2Cache);   
      g_pWin32ConvUCS2Cache = NULL;
   }

   g_dwWin32ConvUTF8strlen = 0;
}


/* to allow the usage of the original version in this file here */
#undef fputs


//#define USE_WIN32_COMPAT_IO 1
#define USE_WIN32_32KPATHCONVERSION 1

extern DWORD   g_platform_id;
extern DWORD   g_MinorVersion;

// from MicroSoft SDK (KES) is the diff between Jan 1 1601 and Jan 1 1970
#define WIN32_FILETIME_ADJUST 0x19DB1DED53E8000ULL 

#define WIN32_FILETIME_SCALE  10000000             // 100ns/second

void conv_unix_to_win32_path(const char *name, char *win32_name, DWORD dwSize)
{
    const char *fname = name;
    char *tname = win32_name;

    if (IsPathSeparator(name[0]) &&
        IsPathSeparator(name[1]) &&
        name[2] == '.' &&
        IsPathSeparator(name[3])) {

        *win32_name++ = '\\';
        *win32_name++ = '\\';
        *win32_name++ = '.';
        *win32_name++ = '\\';

        name += 4;
    } else if (g_platform_id != VER_PLATFORM_WIN32_WINDOWS &&
               g_pVSSPathConvert == NULL) {
        /* allow path to be 32767 bytes */
        *win32_name++ = '\\';
        *win32_name++ = '\\';
        *win32_name++ = '?';
        *win32_name++ = '\\';
    }

    while (*name) {
        /* Check for Unix separator and convert to Win32 */
        if (name[0] == '/' && name[1] == '/') {  /* double slash? */
           name++;                               /* yes, skip first one */
        }
        if (*name == '/') {
            *win32_name++ = '\\';     /* convert char */
        /* If Win32 separator that is "quoted", remove quote */
        } else if (*name == '\\' && name[1] == '\\') {
            *win32_name++ = '\\';
            name++;                   /* skip first \ */
        } else {
            *win32_name++ = *name;    /* copy character */
        }
        name++;
    }
    /* Strip any trailing slash, if we stored something */
    /* but leave "c:\" with backslash (root directory case */
    if (*fname != 0 && win32_name[-1] == '\\' && strlen (fname) != 3) {
        win32_name[-1] = 0;
    } else {
        *win32_name = 0;
    }

    /* here we convert to VSS specific file name which
       can get longer because VSS will make something like
       \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\burp\\uninstall.exe
       from c:\burp\uninstall.exe
    */
    if (g_pVSSPathConvert != NULL) {
       char *pszBuf = sm_get_pool_memory (PM_FNAME);
       pszBuf = sm_check_pool_memory_size(pszBuf, dwSize);
       snprintf(pszBuf, strlen(tname)+1, "%s", tname);
       g_pVSSPathConvert(pszBuf, tname, dwSize);
       sm_free_pool_memory(pszBuf);
    }

}

/* Conversion of a Unix filename to a Win32 filename */
char *
unix_name_to_win32(char *name)
{
   char *ret=NULL;
   char *tmp=NULL;
   
   /* One extra byte should suffice, but we double it */
   /* add MAX_PATH bytes for VSS shadow copy name */
   DWORD dwSize = 2*strlen(name)+MAX_PATH;
   tmp=sm_get_pool_memory(PM_FNAME);
   tmp=sm_check_pool_memory_size(tmp, dwSize);
   conv_unix_to_win32_path(name, tmp, dwSize);
   if(tmp) ret=strdup(tmp);
   sm_free_pool_memory(tmp);
   return ret;
}

char* 
make_wchar_win32_path(char *pszUCSPath, BOOL *pBIsRawPath /*= NULL*/)
{
   /* created 02/27/2006 Thorsten Engel
    * 
    * This function expects an UCS-encoded standard wchar_t in pszUCSPath and
    * will complete the input path to an absolue path of the form \\?\c:\path\file
    * 
    * With this trick, it is possible to have 32K characters long paths.
    *
    * Optionally one can use pBIsRawPath to determine id pszUCSPath contains a path
    * to a raw windows partition.  
    */

   if (pBIsRawPath) {
      *pBIsRawPath = FALSE;              /* Initialize, set later */
   }

   if (!p_GetCurrentDirectoryW) {
      return pszUCSPath;
   }
   
   wchar_t *name = (wchar_t *)pszUCSPath;

   /* if it has already the desired form, exit without changes */
   if (wcslen(name) > 3 && wcsncmp(name, L"\\\\?\\", 4) == 0) {
      return pszUCSPath;
   }

   wchar_t *pwszBuf = (wchar_t *)sm_get_pool_memory(PM_FNAME);
   wchar_t *pwszCurDirBuf = (wchar_t *)sm_get_pool_memory(PM_FNAME);
   DWORD dwCurDirPathSize = 0;

   /* get buffer with enough size (name+max 6. wchars+1 null terminator */
   DWORD dwBufCharsNeeded = (wcslen(name)+7);
   pwszBuf = (wchar_t *)sm_check_pool_memory_size((char *)pwszBuf, dwBufCharsNeeded*sizeof(wchar_t));
      
   /* add \\?\ to support 32K long filepaths 
      it is important to make absolute paths, so we add drive and
      current path if necessary */

   BOOL bAddDrive = TRUE;
   BOOL bAddCurrentPath = TRUE;
   BOOL bAddPrefix = TRUE;

   /* does path begin with drive? if yes, it is absolute */
   if (iswalpha(name[0]) && name[1] == ':' && IsPathSeparator(name[2])) {
      bAddDrive = FALSE;
      bAddCurrentPath = FALSE;
   }

   /* is path absolute? */
   if (IsPathSeparator(name[0]))
      bAddCurrentPath = FALSE; 

   /* is path relative to itself?, if yes, skip ./ */
   if (name[0] == '.' && IsPathSeparator(name[1])) {
      name += 2;
   }

   /* is path of form '//./'? */
   if (IsPathSeparator(name[0]) && 
       IsPathSeparator(name[1]) && 
       name[2] == '.' && 
       IsPathSeparator(name[3])) {
      bAddDrive = FALSE;
      bAddCurrentPath = FALSE;
      bAddPrefix = FALSE;
      if (pBIsRawPath) {
         *pBIsRawPath = TRUE;
      }
   }

   int nParseOffset = 0;
   
   /* add 4 bytes header */
   if (bAddPrefix) {
      nParseOffset = 4;
      wcscpy(pwszBuf, L"\\\\?\\");
   }

   /* get current path if needed */
   if (bAddDrive || bAddCurrentPath) {
      dwCurDirPathSize = p_GetCurrentDirectoryW(0, NULL);
      if (dwCurDirPathSize > 0) {
         /* get directory into own buffer as it may either return c:\... or \\?\C:\.... */         
         pwszCurDirBuf = (wchar_t *)sm_check_pool_memory_size((char *)pwszCurDirBuf, (dwCurDirPathSize+1)*sizeof(wchar_t));
         p_GetCurrentDirectoryW(dwCurDirPathSize, pwszCurDirBuf);
      } else {
         /* we have no info for doing so */
         bAddDrive = FALSE;
         bAddCurrentPath = FALSE;
      }
   }
      

   /* add drive if needed */
   if (bAddDrive && !bAddCurrentPath) {
      wchar_t szDrive[3];

      if (IsPathSeparator(pwszCurDirBuf[0]) && 
          IsPathSeparator(pwszCurDirBuf[1]) && 
          pwszCurDirBuf[2] == '?' && 
          IsPathSeparator(pwszCurDirBuf[3])) {
         /* copy drive character */
         szDrive[0] = pwszCurDirBuf[4];
      } else {
         /* copy drive character */
         szDrive[0] = pwszCurDirBuf[0];
      }

      szDrive[1] = ':';
      szDrive[2] = 0;

      wcscat(pwszBuf, szDrive);
      nParseOffset +=2;
   }

   /* add path if needed */
   if (bAddCurrentPath) {
      /* the 1 add. character is for the eventually added backslash */
      dwBufCharsNeeded += dwCurDirPathSize+1; 
      pwszBuf = (wchar_t *)sm_check_pool_memory_size((char *)pwszBuf, dwBufCharsNeeded*sizeof(wchar_t));
      /* get directory into own buffer as it may either return c:\... or \\?\C:\.... */
      
      if (IsPathSeparator(pwszCurDirBuf[0]) && 
          IsPathSeparator(pwszCurDirBuf[1]) && 
          pwszCurDirBuf[2] == '?' && 
          IsPathSeparator(pwszCurDirBuf[3])) {
         /* copy complete string */
         wcscpy(pwszBuf, pwszCurDirBuf);
      } else {
         /* append path  */
         wcscat(pwszBuf, pwszCurDirBuf);
      }

      nParseOffset = wcslen((LPCWSTR) pwszBuf);

      /* check if path ends with backslash, if not, add one */
      if (!IsPathSeparator(pwszBuf[nParseOffset-1])) {
         wcscat(pwszBuf, L"\\");
         nParseOffset++;
      }
   }

   wchar_t *win32_name = &pwszBuf[nParseOffset];
   wchar_t *name_start = name;

   while (*name) {
      /* Check for Unix separator and convert to Win32, eliminating 
       * duplicate separators.
       */
      if (IsPathSeparator(*name)) {
         *win32_name++ = '\\';     /* convert char */

         /* Eliminate consecutive slashes, but not at the start so that 
          * \\.\ still works.
          */
         if (name_start != name && IsPathSeparator(name[1])) {
            name++;
         }
      } else {
         *win32_name++ = *name;    /* copy character */
      }
      name++;
   }

   /* null terminate string */
   *win32_name = 0;

   /* here we convert to VSS specific file name which
    * can get longer because VSS will make something like
    * \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\burp\\uninstall.exe
    * from c:\burp\uninstall.exe
   */ 
   if (g_pVSSPathConvertW != NULL) {
      /* is output buffer large enough? */
      pwszBuf = (wchar_t *)sm_check_pool_memory_size((char *)pwszBuf, 
                                                  (dwBufCharsNeeded+MAX_PATH)*sizeof(wchar_t));
      /* create temp. buffer */
      wchar_t *pszBuf = (wchar_t *)sm_get_pool_memory(PM_FNAME);
      pszBuf = (wchar_t *)sm_check_pool_memory_size((char *)pszBuf, 
                                                 (dwBufCharsNeeded+MAX_PATH)*sizeof(wchar_t));
      if (bAddPrefix)
         nParseOffset = 4;
      else
         nParseOffset = 0; 
      wcsncpy(pszBuf, &pwszBuf[nParseOffset], wcslen(pwszBuf)+1-nParseOffset);
      g_pVSSPathConvertW(pszBuf, pwszBuf, dwBufCharsNeeded+MAX_PATH);
      sm_free_pool_memory((char *)pszBuf);
   }   

   sm_free_pool_memory(pszUCSPath);
   sm_free_pool_memory((char *)pwszCurDirBuf);

   return (char *)pwszBuf;
}

int
wchar_2_UTF8(char *pszUTF, const wchar_t *pszUCS, int cchChar)
{
   /* the return value is the number of bytes written to the buffer.
      The number includes the byte for the null terminator. */

   if (p_WideCharToMultiByte) {
         int nRet = p_WideCharToMultiByte(CP_UTF8,0,pszUCS,-1,pszUTF,cchChar,NULL,NULL);
         ASSERT (nRet > 0);
         return nRet;
      }
   else
      return 0;
}

int
UTF8_2_wchar(char **ppszUCS, const char *pszUTF)
{
   /* the return value is the number of wide characters written to the buffer. */
   /* convert null terminated string from utf-8 to ucs2, enlarge buffer if necessary */

   if (p_MultiByteToWideChar) {
      /* strlen of UTF8 +1 is enough */
      DWORD cchSize = (strlen(pszUTF)+1);
      *ppszUCS = sm_check_pool_memory_size(*ppszUCS, cchSize*sizeof (wchar_t));

      int nRet = p_MultiByteToWideChar(CP_UTF8, 0, pszUTF, -1, (LPWSTR) *ppszUCS,cchSize);
      ASSERT (nRet > 0);
      return nRet;
   }
   else
      return 0;
}


void
wchar_win32_path(const char *name, wchar_t *win32_name)
{
    const char *fname = name;
    while (*name) {
        /* Check for Unix separator and convert to Win32 */
        if (*name == '/') {
            *win32_name++ = '\\';     /* convert char */
        /* If Win32 separated that is "quoted", remove quote */
        } else if (*name == '\\' && name[1] == '\\') {
            *win32_name++ = '\\';
            name++;                   /* skip first \ */
        } else {
            *win32_name++ = *name;    /* copy character */
        }
        name++;
    }
    /* Strip any trailing slash, if we stored something */
    if (*fname != 0 && win32_name[-1] == '\\') {
        win32_name[-1] = 0;
    } else {
        *win32_name = 0;
    }
}

/*
 * Allows one or both pointers to be NULL
 */
static bool bstrcmp(const char *s1, const char *s2)
{
   if (s1 == s2) return true;
   if (s1 == NULL || s2 == NULL) return false;
   return strcmp(s1, s2) == 0;
}

int 
make_win32_path_UTF8_2_wchar(char **pszUCS, const char *pszUTF, BOOL* pBIsRawPath /*= NULL*/)
{
   /* if we find the utf8 string in cache, we use the cached ucs2 version.
      we compare the stringlength first (quick check) and then compare the content.            
   */
   if (!g_pWin32ConvUTF8Cache) {
      Win32ConvInitCache();
   } else if (g_dwWin32ConvUTF8strlen == strlen(pszUTF)) {
      if (bstrcmp(pszUTF, g_pWin32ConvUTF8Cache)) {
         /* Return cached value */
         int32_t nBufSize = sm_sizeof_pool_memory(g_pWin32ConvUCS2Cache);
         *pszUCS = sm_check_pool_memory_size(*pszUCS, nBufSize);      
         wcscpy((LPWSTR) *pszUCS, (LPWSTR)g_pWin32ConvUCS2Cache);
         return nBufSize / sizeof (WCHAR);
      }
   }

   /* helper to convert from utf-8 to UCS-2 and to complete a path for 32K path syntax */
   int nRet = UTF8_2_wchar(pszUCS, pszUTF);

#ifdef USE_WIN32_32KPATHCONVERSION
   /* add \\?\ to support 32K long filepaths */
   *pszUCS = make_wchar_win32_path(*pszUCS, pBIsRawPath);
#else
   if (pBIsRawPath)
      *pBIsRawPath = FALSE;
#endif

   /* populate cache */      
   g_pWin32ConvUCS2Cache = sm_check_pool_memory_size(g_pWin32ConvUCS2Cache, sm_sizeof_pool_memory(*pszUCS));
   wcscpy((LPWSTR) g_pWin32ConvUCS2Cache, (LPWSTR) *pszUCS);
   
   g_dwWin32ConvUTF8strlen = strlen(pszUTF);
   g_pWin32ConvUTF8Cache = sm_check_pool_memory_size(g_pWin32ConvUTF8Cache, g_dwWin32ConvUTF8strlen+2);
   snprintf(g_pWin32ConvUTF8Cache, g_dwWin32ConvUTF8strlen+1, "%s", pszUTF);

   return nRet;
}

char *make_win32_path_UTF8_2_wchar_w(const char *pszUTF)
{
	int size=0;
	char *ret=NULL;
	char *tmp=sm_get_pool_memory(PM_FNAME);

	size=make_win32_path_UTF8_2_wchar(&tmp, pszUTF);
	if(size>0)
	{
		ret=(char *)malloc(2*strlen(pszUTF)+MAX_PATH);
		//ret=(char *)malloc((size+1)*sizeof(WCHAR));
        	wcscpy((LPWSTR)ret, (LPWSTR)tmp);
	}
	sm_free_pool_memory(tmp);
	return ret;
}

#if !defined(_MSC_VER) || (_MSC_VER < 1400) // VC8+
int umask(int)
{
   return 0;
}
#endif

#ifndef LOAD_WITH_ALTERED_SEARCH_PATH
#define LOAD_WITH_ALTERED_SEARCH_PATH 0x00000008
#endif

void *dlopen(const char *file, int mode)
{
   void *handle;

   handle = LoadLibraryEx(file, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
   return handle;
}

void *dlsym(void *handle, const char *name)
{
   void *symaddr;
   symaddr = (void *)GetProcAddress((HMODULE)handle, name);
   return symaddr;
}

int dlclose(void *handle) 
{
   if (handle && !FreeLibrary((HMODULE)handle)) {
      errno = b_errno_win32;
      return 1;        /* failed */
   }
   return 0;           /* OK */
}

char *dlerror(void) 
{
   static char buf[200];
   const char *err = errorString();
   snprintf(buf, sizeof(buf), "%s", (char *)err);
   LocalFree((void *)err);
   return buf;
}

int fcntl(int fd, int cmd)
{
   return 0;
}

int chown(const char *k, uid_t, gid_t)
{
   return 0;
}

int lchown(const char *k, uid_t, gid_t)
{
   return 0;
}

long int
random(void)
{
    return rand();
}

void
srandom(unsigned int seed)
{
   srand(seed);
}
// /////////////////////////////////////////////////////////////////
// convert from Windows concept of time to Unix concept of time
// /////////////////////////////////////////////////////////////////
void
cvt_utime_to_ftime(const time_t  &time, FILETIME &wintime)
{
   uint64_t mstime = time;
   mstime *= WIN32_FILETIME_SCALE;
   mstime += WIN32_FILETIME_ADJUST;

#if defined(_MSC_VER)
   wintime.dwLowDateTime = (DWORD)(mstime & 0xffffffffI64);
#else
   wintime.dwLowDateTime = (DWORD)(mstime & 0xffffffffUL);
#endif
   wintime.dwHighDateTime = (DWORD) ((mstime>>32)& 0xffffffffUL);
}

time_t
cvt_ftime_to_utime(const FILETIME &time)
{
    uint64_t mstime = time.dwHighDateTime;
    mstime <<= 32;
    mstime |= time.dwLowDateTime;

    mstime -= WIN32_FILETIME_ADJUST;
    mstime /= WIN32_FILETIME_SCALE; // convert to seconds.

    return (time_t) (mstime & 0xffffffff);
}

static const char *errorString(void)
{
   LPVOID lpMsgBuf;

   FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                 FORMAT_MESSAGE_FROM_SYSTEM |
                 FORMAT_MESSAGE_IGNORE_INSERTS,
                 NULL,
                 GetLastError(),
                 MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default lang
                 (LPTSTR) &lpMsgBuf,
                 0,
                 NULL);

   /* Strip any \r or \n */
   char *rval = (char *) lpMsgBuf;
   char *cp = strchr(rval, '\r');
   if (cp != NULL) {
      *cp = 0;
   } else {
      cp = strchr(rval, '\n');
      if (cp != NULL)
         *cp = 0;
   }
   return rval;
}


static int
statDir(const char *file, struct stat *sb, uint64_t *winattr)
{
   WIN32_FIND_DATAW info_w;       // window's file info
   WIN32_FIND_DATAA info_a;       // window's file info

   // cache some common vars to make code more transparent
   DWORD *pdwFileAttributes;
   DWORD *pnFileSizeHigh;
   DWORD *pnFileSizeLow;
   DWORD *pdwReserved0;
   FILETIME *pftLastAccessTime;
   FILETIME *pftLastWriteTime;
   FILETIME *pftCreationTime;

   /* 
    * Oh, cool, another exception: Microsoft doesn't let us do 
    *  FindFile operations on a Drive, so simply fake root attibutes.
    */
   if (file[1] == ':' && file[2] == 0) {
      time_t now = time(NULL);
      sb->st_mode = S_IFDIR;
      sb->st_mode |= S_IREAD|S_IEXEC|S_IWRITE;
      sb->st_ctime = now;
      sb->st_mtime = now;
      sb->st_atime = now;
      sb->st_rdev = 0;
      return 0;
    }

   HANDLE h = INVALID_HANDLE_VALUE;

   // use unicode
   if (p_FindFirstFileW) {
      char* pwszBuf = sm_get_pool_memory (PM_FNAME);
      make_win32_path_UTF8_2_wchar(&pwszBuf, file);

      h = p_FindFirstFileW((LPCWSTR)pwszBuf, &info_w);
      sm_free_pool_memory(pwszBuf);

      pdwFileAttributes = &info_w.dwFileAttributes;
      pdwReserved0      = &info_w.dwReserved0;
      pnFileSizeHigh    = &info_w.nFileSizeHigh;
      pnFileSizeLow     = &info_w.nFileSizeLow;
      pftLastAccessTime = &info_w.ftLastAccessTime;
      pftLastWriteTime  = &info_w.ftLastWriteTime;
      pftCreationTime   = &info_w.ftCreationTime;
   // use ASCII
   } else if (p_FindFirstFileA) {
      h = p_FindFirstFileA(file, &info_a);

      pdwFileAttributes = &info_a.dwFileAttributes;
      pdwReserved0      = &info_a.dwReserved0;
      pnFileSizeHigh    = &info_a.nFileSizeHigh;
      pnFileSizeLow     = &info_a.nFileSizeLow;
      pftLastAccessTime = &info_a.ftLastAccessTime;
      pftLastWriteTime  = &info_a.ftLastWriteTime;
      pftCreationTime   = &info_a.ftCreationTime;
   } else {
   }

   if (h == INVALID_HANDLE_VALUE) {
      const char *err = errorString();
      /*
       * Note, in creating leading paths, it is normal that
       * the file does not exist.
       */
      LocalFree((void *)err);
      errno = b_errno_win32;
      return -1;
   } else {
      FindClose(h);
   }

   *winattr = (int64_t)*pdwFileAttributes;

   /* Graham says: all the following stuff seems rather complicated.
      It is probably not all needed anymore, since I have added *winattr
      above, which bacula did not do.
      One reason for keeping it is that some of the values get converted to
      unix-style permissions that show up in the long list functionality.
      I think I would prefer to remove it all at some point.
   */
   sb->st_mode = 0777;               /* start with everything */
   if (*pdwFileAttributes & FILE_ATTRIBUTE_READONLY)
       sb->st_mode &= ~(S_IRUSR|S_IRGRP|S_IROTH);
   if (*pdwFileAttributes & FILE_ATTRIBUTE_SYSTEM)
       sb->st_mode &= ~S_IRWXO; /* remove everything for other */
   if (*pdwFileAttributes & FILE_ATTRIBUTE_HIDDEN)
       sb->st_mode |= S_ISVTX; /* use sticky bit -> hidden */
   sb->st_mode |= S_IFDIR;

   /* 
    * Store reparse/mount point info in st_rdev.  Note a
    *  Win32 reparse point (junction point) is like a link
    *  though it can have many properties (directory link,
    *  soft link, hard link, HSM, ...
    *  A mount point is a reparse point where another volume
    *  is mounted, so it is like a Unix mount point (change of
    *  filesystem).
    */
   if (*pdwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
      sb->st_rdev = WIN32_MOUNT_POINT;           /* mount point */
   } else {
      sb->st_rdev = 0;
   }
   if ((*pdwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
        (*pdwReserved0 & IO_REPARSE_TAG_MOUNT_POINT)) {
      sb->st_rdev = WIN32_MOUNT_POINT;           /* mount point */
      /*
       * Now to find out if the directory is a mount point or
       * a reparse point, we must do a song and a dance.
       * Explicitly open the file to read the reparse point, then
       * call DeviceIoControl to find out if it points to a Volume
       * or to a directory.
       */
      h = INVALID_HANDLE_VALUE;
      if (p_GetFileAttributesW) {
         char* pwszBuf = sm_get_pool_memory(PM_FNAME);
         make_win32_path_UTF8_2_wchar(&pwszBuf, file);
         if (p_CreateFileW) {
            h = CreateFileW((LPCWSTR)pwszBuf, GENERIC_READ,
                   FILE_SHARE_READ, NULL, OPEN_EXISTING,
                   FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                   NULL);
         }
         sm_free_pool_memory(pwszBuf);
      } else if (p_GetFileAttributesA) {
         h = CreateFileA(file, GENERIC_READ,
                FILE_SHARE_READ, NULL, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                NULL);
      }
      if (h != INVALID_HANDLE_VALUE) {
         char dummy[1000];
         REPARSE_DATA_BUFFER *rdb = (REPARSE_DATA_BUFFER *)dummy;
         rdb->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
         DWORD bytes;
         bool ok;
         ok = DeviceIoControl(h, FSCTL_GET_REPARSE_POINT,
                 NULL, 0,                           /* in buffer, bytes */
                 (LPVOID)rdb, (DWORD)sizeof(dummy), /* out buffer, btyes */
                 (LPDWORD)&bytes, (LPOVERLAPPED)0);
         if (ok) {
            char *utf8 = sm_get_pool_memory(PM_NAME);
            wchar_2_UTF8(utf8, (wchar_t *)rdb->SymbolicLinkReparseBuffer.PathBuffer);
            if (strncasecmp(utf8, "\\??\\volume{", 11) == 0) {
               sb->st_rdev = WIN32_MOUNT_POINT;
            } else {
               /* It points to a directory so we ignore it. */
               sb->st_rdev = WIN32_JUNCTION_POINT;
            }
            sm_free_pool_memory(utf8);
         }
         CloseHandle(h);
      } else {
         //Dmsg1(dbglvl, "Invalid handle from CreateFile(%s)\n", file);
      }
   }
   sb->st_size = *pnFileSizeHigh;
   sb->st_size <<= 32;
   sb->st_size |= *pnFileSizeLow;
   sb->st_blksize = 4096;
   sb->st_blocks = (uint32_t)(sb->st_size + 4095)/4096;

   sb->st_atime = cvt_ftime_to_utime(*pftLastAccessTime);
   sb->st_mtime = cvt_ftime_to_utime(*pftLastWriteTime);
   sb->st_ctime = cvt_ftime_to_utime(*pftCreationTime);

   return 0;
}

static int
do_fstat(intptr_t fd, struct stat *sb, uint64_t *winattr)
{
   BY_HANDLE_FILE_INFORMATION info;

   if (!GetFileInformationByHandle((HANDLE)_get_osfhandle(fd), &info)) {
       const char *err = errorString();
       LocalFree((void *)err);
       errno = b_errno_win32;
       return -1;
   }

   sb->st_dev = info.dwVolumeSerialNumber;
   sb->st_ino = info.nFileIndexHigh;
   sb->st_ino <<= 32;
   sb->st_ino |= info.nFileIndexLow;
   sb->st_nlink = (short)info.nNumberOfLinks;
   if (sb->st_nlink > 1) {
   }
   *winattr = (int64_t)info.dwFileAttributes;

   /* Graham says: all the following stuff seems rather complicated.
      It is probably not all needed anymore, since I have added *winattr
      above, which bacula did not do.
      One reason for keeping it is that some of the values get converted to
      unix-style permissions that show up in the long list functionality.
      I think I would prefer to remove it all though.
   */
   sb->st_mode = 0777;               /* start with everything */
   if (info.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
       sb->st_mode &= ~(S_IRUSR|S_IRGRP|S_IROTH);
   if (info.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)
       sb->st_mode &= ~S_IRWXO; /* remove everything for other */
   if (info.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)
       sb->st_mode |= S_ISVTX; /* use sticky bit -> hidden */
   sb->st_mode |= S_IFREG;

   /* Use st_rdev to store reparse attribute */
   if  (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
      sb->st_rdev = WIN32_REPARSE_POINT;
   }

   sb->st_size = info.nFileSizeHigh;
   sb->st_size <<= 32;
   sb->st_size |= info.nFileSizeLow;
   sb->st_blksize = 4096;
   sb->st_blocks = (uint32_t)(sb->st_size + 4095)/4096;
   sb->st_atime = cvt_ftime_to_utime(info.ftLastAccessTime);
   sb->st_mtime = cvt_ftime_to_utime(info.ftLastWriteTime);
   sb->st_ctime = cvt_ftime_to_utime(info.ftCreationTime);

   return 0;
}

int
fstat(intptr_t fd, struct stat *sb)
{
	uint64_t winattr=0;
	return do_fstat(fd, sb, &winattr);
}

static int
stat2(const char *file, struct stat *sb, uint64_t *winattr)
{
   HANDLE h = INVALID_HANDLE_VALUE;
   int rval = 0;
   char tmpbuf[5000];
   conv_unix_to_win32_path(file, tmpbuf, 5000);

   DWORD attr = (DWORD)-1;

   if (p_GetFileAttributesW) {
      char* pwszBuf = sm_get_pool_memory(PM_FNAME);
      make_win32_path_UTF8_2_wchar(&pwszBuf, tmpbuf);

      attr = p_GetFileAttributesW((LPCWSTR) pwszBuf);
      if (p_CreateFileW) {
         h = CreateFileW((LPCWSTR)pwszBuf, GENERIC_READ,
                FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
      }
      sm_free_pool_memory(pwszBuf);
   } else if (p_GetFileAttributesA) {
      attr = p_GetFileAttributesA(tmpbuf);
      h = CreateFileA(tmpbuf, GENERIC_READ,
               FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
   }

   if (attr == (DWORD)-1) {
      const char *err = errorString();
      LocalFree((void *)err);
      if (h != INVALID_HANDLE_VALUE) {
         CloseHandle(h);
      }
      errno = b_errno_win32;
      return -1;
   }

   if (h == INVALID_HANDLE_VALUE) {
      const char *err = errorString();
      LocalFree((void *)err);
      errno = b_errno_win32;
      return -1;
   }

   rval = do_fstat((intptr_t)h, sb, winattr);
   CloseHandle(h);

   if (attr & FILE_ATTRIBUTE_DIRECTORY &&
        file[1] == ':' && file[2] != 0) {
      rval = statDir(file, sb, winattr);
   }
   return rval;
}

static int
do_stat(const char *file, struct stat *sb, uint64_t *winattr)
{
   WIN32_FILE_ATTRIBUTE_DATA data;
   errno = 0;

   memset(sb, 0, sizeof(*sb));
   memset(winattr, 0, sizeof(*winattr));

   if (p_GetFileAttributesExW) {
      /* dynamically allocate enough space for UCS2 filename */
      char *pwszBuf = sm_get_pool_memory(PM_FNAME);
      make_win32_path_UTF8_2_wchar(&pwszBuf, file);

      BOOL b = p_GetFileAttributesExW((LPCWSTR)pwszBuf, GetFileExInfoStandard, &data);
      sm_free_pool_memory(pwszBuf);

      if (!b) {
         return stat2(file, sb, winattr);
      }

   } else if (p_GetFileAttributesExA) {
      if (!p_GetFileAttributesExA(file, GetFileExInfoStandard, &data)) {
         return stat2(file, sb, winattr);
       }
   } else {
      return stat2(file, sb, winattr);
   }

   *winattr = (int64_t)data.dwFileAttributes;

   /* Graham says: all the following stuff seems rather complicated.
      It is probably not all needed anymore, since I have added *winattr
      above, which bacula did not do.
      One reason for keeping it is that some of the values get converted to
      unix-style permissions that show up in the long list functionality.
      I think I would prefer to remove it all though.
   */
   sb->st_mode = 0777;               /* start with everything */
   if (data.dwFileAttributes & FILE_ATTRIBUTE_READONLY) {
      sb->st_mode &= ~(S_IRUSR|S_IRGRP|S_IROTH);
   }
   if (data.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) {
      sb->st_mode &= ~S_IRWXO; /* remove everything for other */
   }
   if (data.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) {
      sb->st_mode |= S_ISVTX; /* use sticky bit -> hidden */
   }
   if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      sb->st_mode |= S_IFDIR;
   } else {
      sb->st_mode |= S_IFREG;
   }

   /* Use st_rdev to store reparse attribute */
   sb->st_rdev = (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ? 1 : 0; 

   sb->st_nlink = 1;
   sb->st_size = data.nFileSizeHigh;
   sb->st_size <<= 32;
   sb->st_size |= data.nFileSizeLow;
   sb->st_blksize = 4096;
   sb->st_blocks = (uint32_t)(sb->st_size + 4095)/4096;
   sb->st_atime = cvt_ftime_to_utime(data.ftLastAccessTime);
   sb->st_mtime = cvt_ftime_to_utime(data.ftLastWriteTime);
   sb->st_ctime = cvt_ftime_to_utime(data.ftCreationTime);

   /*
    * If we are not at the root, then to distinguish a reparse 
    *  point from a mount point, we must call FindFirstFile() to
    *  get the WIN32_FIND_DATA, which has the bit that indicates
    *  that this directory is a mount point -- aren't Win32 APIs
    *  wonderful? (sarcasm).  The code exists in the statDir
    *  subroutine.
    */
   if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY && 
        file[1] == ':' && file[2] != 0) {
      statDir(file, sb, winattr);
   }
   return 0;
}

/*
 * We write our own ftruncate because the one in the
 *  Microsoft library mrcrt.dll does not truncate
 *  files greater than 2GB.
 *  KES - May 2007
 */
int win32_ftruncate(int fd, int64_t length) 
{
   /* Set point we want to truncate file */
   __int64 pos = _lseeki64(fd, (__int64)length, SEEK_SET);

   if (pos != (__int64)length) {
      errno = EACCES;         /* truncation failed, get out */
      return -1;
   }

   /* Truncate file */
   if (SetEndOfFile((HANDLE)_get_osfhandle(fd)) == 0) {
      errno = b_errno_win32;
      return -1;
   }
   errno = 0;
   return 0;
}

int fcntl(int fd, int cmd, long arg)
{
   int rval = 0;

   switch (cmd) {
   case F_GETFL:
      rval = O_NONBLOCK;
      break;

   case F_SETFL:
      rval = 0;
      break;

   default:
      errno = EINVAL;
      rval = -1;
      break;
   }

   return rval;
}

int
lstat(const char *file, struct stat *sb)
{
   uint64_t winattr=0;
   return do_stat(file, sb, &winattr);
}

int
win32_lstat(const char *file, struct stat *sb, uint64_t *winattr)
{
   return do_stat(file, sb, winattr);
}

void
sleep(int sec)
{
   Sleep(sec * 1000);
}

int
geteuid(void)
{
   return 0;
}

int
execvp(const char *, char *[]) {
   errno = ENOSYS;
   return -1;
}


int
fork(void)
{
   errno = ENOSYS;
   return -1;
}

int
pipe(int[])
{
   errno = ENOSYS;
   return -1;
}

int
waitpid(int, int*, int)
{
   errno = ENOSYS;
   return -1;
}

int
readlink(const char *, char *, int)
{
   errno = ENOSYS;
   return -1;
}

int
strncasecmp(const char *s1, const char *s2, int len)
{
   register int ch1 = 0, ch2 = 0;

   if (s1==s2)
      return 0;       /* strings are equal if same object. */
   else if (!s1)
      return -1;
   else if (!s2)
      return 1;

   while (len--) {
      ch1 = *s1;
      ch2 = *s2;
      s1++;
      s2++;
      if (ch1 == 0 || tolower(ch1) != tolower(ch2)) break;
   }

   return (ch1 - ch2);
}

int
gettimeofday(struct timeval *tv, struct timezone *)
{
    SYSTEMTIME now;
    FILETIME tmp;

    GetSystemTime(&now);

    if (tv == NULL) {
       errno = EINVAL;
       return -1;
    }
    if (!SystemTimeToFileTime(&now, &tmp)) {
       errno = b_errno_win32;
       return -1;
    }

    int64_t _100nsec = tmp.dwHighDateTime;
    _100nsec <<= 32;
    _100nsec |= tmp.dwLowDateTime;
    _100nsec -= WIN32_FILETIME_ADJUST;

    tv->tv_sec = (long)(_100nsec / 10000000);
    tv->tv_usec = (long)((_100nsec % 10000000)/10);
    return 0;

}

/* For apcupsd this is in src/lib/wincompat.c */
extern "C" void syslog(int type, const char *fmt, ...) 
{
/*#ifndef HAVE_CONSOLE
    MessageBox(NULL, msg, "Burp", MB_OK);
#endif*/
}

void
closelog()
{
}

struct passwd *
getpwuid(uid_t)
{
    return NULL;
}

struct group *
getgrgid(uid_t)
{
    return NULL;
}

// implement opendir/readdir/closedir on top of window's API

typedef struct _dir
{
    WIN32_FIND_DATAA data_a;    // window's file info (ansii version)
    WIN32_FIND_DATAW data_w;    // window's file info (wchar version)
    const char *spec;           // the directory we're traversing
    HANDLE      dirh;           // the search handle
    BOOL        valid_a;        // the info in data_a field is valid
    BOOL        valid_w;        // the info in data_w field is valid
    UINT32      offset;         // pseudo offset for d_off
} _dir;

DIR *
opendir(const char *path)
{
    ssize_t len=0;
    char *tspec=NULL;

    /* enough space for VSS !*/
    int max_len = strlen(path) + MAX_PATH;
    _dir *rval = NULL;
    if (path == NULL) {
       errno = ENOENT;
       return NULL;
    }

    if(!(rval = (_dir *)malloc(sizeof(_dir))))
	return NULL;
    memset (rval, 0, sizeof (_dir));
    if(!(tspec = (char *)malloc(max_len)))
    {
	free(rval);
	return NULL;
    }

    conv_unix_to_win32_path(path, tspec, max_len);

    len=strlen(tspec);
    // add backslash only if there is none yet (think of c:\)
    if (tspec[len-1] != '\\') {
	if(len+1<max_len) {
		tspec[len++]='\\';
		tspec[len]='\0';
	}
    }
    if(len+1<max_len) {
	    tspec[len++]='*';
	    tspec[len]='\0';
    }

    rval->spec = tspec;

    // convert to wchar_t
    if (p_FindFirstFileW) {
      char* pwcBuf = sm_get_pool_memory(PM_FNAME);
      make_win32_path_UTF8_2_wchar(&pwcBuf, rval->spec);

      rval->dirh = p_FindFirstFileW((LPCWSTR)pwcBuf, &rval->data_w);

      sm_free_pool_memory(pwcBuf);

      if (rval->dirh != INVALID_HANDLE_VALUE)
        rval->valid_w = 1;
    } else if (p_FindFirstFileA) {
      rval->dirh = p_FindFirstFileA(rval->spec, &rval->data_a);

      if (rval->dirh != INVALID_HANDLE_VALUE)
        rval->valid_a = 1;
    } else goto err;

    rval->offset = 0;
    if (rval->dirh == INVALID_HANDLE_VALUE)
        goto err;

    if (rval->valid_w) {
    }

    if (rval->valid_a) {
    }

    return (DIR *)rval;

err:
    free((void *)rval->spec);
    free(rval);
    errno = b_errno_win32;
    return NULL;
}

int
closedir(DIR *dirp)
{
    _dir *dp = (_dir *)dirp;
    FindClose(dp->dirh);
    free((void *)dp->spec);
    free((void *)dp);
    return 0;
}

/*
  typedef struct _WIN32_FIND_DATA {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    TCHAR cFileName[MAX_PATH];
    TCHAR cAlternateFileName[14];
} WIN32_FIND_DATA, *PWIN32_FIND_DATA;
*/

static int
copyin(struct dirent &dp, const char *fname)
{
    dp.d_ino = 0;
    dp.d_reclen = 0;
    char *cp = dp.d_name;
    while (*fname) {
        *cp++ = *fname++;
        dp.d_reclen++;
    }
        *cp = 0;
    return dp.d_reclen;
}

int
readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result)
{
    _dir *dp = (_dir *)dirp;
    if (dp->valid_w || dp->valid_a) {
      entry->d_off = dp->offset;

      // copy unicode
      if (dp->valid_w) {
         char szBuf[MAX_PATH_UTF8+1];
         wchar_2_UTF8(szBuf,dp->data_w.cFileName);
         dp->offset += copyin(*entry, szBuf);
      } else if (dp->valid_a) { // copy ansi (only 1 will be valid)
         dp->offset += copyin(*entry, dp->data_a.cFileName);
      }

      *result = entry;              /* return entry address */
    } else {
        errno = b_errno_win32;
        return -1;
    }

    // get next file, try unicode first
    if (p_FindNextFileW)
       dp->valid_w = p_FindNextFileW(dp->dirh, &dp->data_w);
    else if (p_FindNextFileA)
       dp->valid_a = p_FindNextFileA(dp->dirh, &dp->data_a);
    else {
       dp->valid_a = FALSE;
       dp->valid_w = FALSE;
    }

    return 0;
}

/*
 * Dotted IP address to network address
 *
 * Returns 1 if  OK
 *         0 on error
 */
int
inet_aton(const char *a, struct in_addr *inp)
{
   const char *cp = a;
   uint32_t acc = 0, tmp = 0;
   int dotc = 0;

   if (!isdigit(*cp)) {         /* first char must be digit */
      return 0;                 /* error */
   }
   do {
      if (isdigit(*cp)) {
         tmp = (tmp * 10) + (*cp -'0');
      } else if (*cp == '.' || *cp == 0) {
         if (tmp > 255) {
            return 0;           /* error */
         }
         acc = (acc << 8) + tmp;
         dotc++;
         tmp = 0;
      } else {
         return 0;              /* error */
      }
   } while (*cp++ != 0);
   if (dotc != 4) {              /* want 3 .'s plus EOS */
      return 0;                  /* error */
   }
   inp->s_addr = htonl(acc);     /* store addr in network format */
   return 1;
}

/*
int
nanosleep(const struct timespec *req, struct timespec *rem)
{
    if (rem)
        rem->tv_sec = rem->tv_nsec = 0;
    Sleep((req->tv_sec * 1000) + (req->tv_nsec/100000));
    return 0;
}
*/

void
init_stack_dump(void)
{

}


long
pathconf(const char *path, int name)
{
    switch(name) {
    case _PC_PATH_MAX :
        if (strncmp(path, "\\\\?\\", 4) == 0)
            return 32767;
    case _PC_NAME_MAX :
        return 255;
    }
    errno = ENOSYS;
    return -1;
}

int
WSA_Init(void)
{
    WORD wVersionRequested = MAKEWORD( 1, 1);
    WSADATA wsaData;

    int err = WSAStartup(wVersionRequested, &wsaData);


    if (err != 0) {
        printf("Can not start Windows Sockets\n");
        errno = ENOSYS;
        return -1;
    }

    return 0;
}

static
int win32_chmod_old(const char *path, mode_t mode)
{
   DWORD attr = (DWORD)-1;

   if (p_GetFileAttributesW) {
      char* pwszBuf = sm_get_pool_memory(PM_FNAME);
      make_win32_path_UTF8_2_wchar(&pwszBuf, path);

      attr = p_GetFileAttributesW((LPCWSTR) pwszBuf);
      if (attr != INVALID_FILE_ATTRIBUTES) {
         /* Use Burp mappings define in stat() above */
         if (!(mode & (S_IRUSR|S_IRGRP|S_IROTH))) {
            attr |= FILE_ATTRIBUTE_READONLY;
         } else {
            attr &= ~FILE_ATTRIBUTE_READONLY;
         }
         if (!(mode & S_IRWXO)) { 
            attr |= FILE_ATTRIBUTE_SYSTEM;
         } else {
            attr &= ~FILE_ATTRIBUTE_SYSTEM;
         }
         if (mode & S_ISVTX) {
            attr |= FILE_ATTRIBUTE_HIDDEN;
         } else {
            attr &= ~FILE_ATTRIBUTE_HIDDEN;
         }
         attr = p_SetFileAttributesW((LPCWSTR)pwszBuf, attr);
      }
      sm_free_pool_memory(pwszBuf);
   } else if (p_GetFileAttributesA) {
         if (!(mode & (S_IRUSR|S_IRGRP|S_IROTH))) {
            attr |= FILE_ATTRIBUTE_READONLY;
         } else {
            attr &= ~FILE_ATTRIBUTE_READONLY;
         }
         if (!(mode & S_IRWXO)) { 
            attr |= FILE_ATTRIBUTE_SYSTEM;
         } else {
            attr &= ~FILE_ATTRIBUTE_SYSTEM;
         }
         if (mode & S_ISVTX) {
            attr |= FILE_ATTRIBUTE_HIDDEN;
         } else {
            attr &= ~FILE_ATTRIBUTE_HIDDEN;
         }
      attr = p_GetFileAttributesA(path);
      if (attr != INVALID_FILE_ATTRIBUTES) {
         attr = p_SetFileAttributesA(path, attr);
      }
   } else {
   }

   if (attr == (DWORD)-1) {
      const char *err = errorString();
      LocalFree((void *)err);
      errno = b_errno_win32;
      return -1;
   }
   return 0;
}

/** Define attributes that are legal to set with SetFileAttributes() */
#define SET_ATTRS ( \
	FILE_ATTRIBUTE_ARCHIVE| \
	FILE_ATTRIBUTE_HIDDEN| \
	FILE_ATTRIBUTE_NORMAL| \
	FILE_ATTRIBUTE_NOT_CONTENT_INDEXED| \
	FILE_ATTRIBUTE_OFFLINE| \
	FILE_ATTRIBUTE_READONLY| \
	FILE_ATTRIBUTE_SYSTEM| \
	FILE_ATTRIBUTE_TEMPORARY)

static
int win32_chmod_new(const char *path, int64_t winattr)
{
	//if(winattr & FILE_ATTRIBUTE_ENCRYPTED) printf("\n   %s was encrypted!\n", path);
   DWORD attr = (DWORD)-1;

   if (p_GetFileAttributesW) {
      char* pwszBuf = sm_get_pool_memory(PM_FNAME);
      make_win32_path_UTF8_2_wchar(&pwszBuf, path);

      attr = p_GetFileAttributesW((LPCWSTR) pwszBuf);
      if (attr != INVALID_FILE_ATTRIBUTES) {
         attr = p_SetFileAttributesW((LPCWSTR)pwszBuf, winattr & SET_ATTRS);
      }
      sm_free_pool_memory(pwszBuf);
   } else if (p_GetFileAttributesA) {
      attr = p_GetFileAttributesA(path);
      if (attr != INVALID_FILE_ATTRIBUTES) {
         winattr = p_SetFileAttributesA(path, attr & SET_ATTRS);
      }
   } else {
   }

   if (attr == (DWORD)-1) {
      const char *err = errorString();
      LocalFree((void *)err);
      errno = b_errno_win32;
      return -1;
   }
   return 0;
}

int win32_chmod(const char *path, mode_t mode, int64_t winattr)
{
	/* Graham says: used to try to encode attributes in a mode_t.
	   The new way is to just have an int64_t with them set properly.
	   Old backups will not have winattr set, so if we have winattr,
	   use it, other try to use the mode_t. */
	/* After a few releases, get rid of the old stuff. */
	if(winattr) return win32_chmod_new(path, winattr);
	else if(mode) return win32_chmod_old(path, mode);
	return 0;
}

int
win32_chdir(const char *dir)
{
   if (p_SetCurrentDirectoryW) {
      char* pwszBuf = sm_get_pool_memory(PM_FNAME);
      make_win32_path_UTF8_2_wchar(&pwszBuf, dir);

      BOOL b=p_SetCurrentDirectoryW((LPCWSTR)pwszBuf);
      
      sm_free_pool_memory(pwszBuf);

      if (!b) {
         errno = b_errno_win32;
         return -1;
      }
   } else if (p_SetCurrentDirectoryA) {
      if (0 == p_SetCurrentDirectoryA(dir)) {
         errno = b_errno_win32;
         return -1;
      }
   } else {
      return -1;
   }

   return 0;
}

int
win32_mkdir(const char *dir)
{
   if (p_wmkdir){
      char* pwszBuf = sm_get_pool_memory(PM_FNAME);
      make_win32_path_UTF8_2_wchar(&pwszBuf, dir);

      int n = p_wmkdir((LPCWSTR)pwszBuf);
      sm_free_pool_memory(pwszBuf);
      return n;
   }

   return _mkdir(dir);
}


char *
win32_getcwd(char *buf, int maxlen)
{
   int n=0;

   if (p_GetCurrentDirectoryW) {
      char* pwszBuf = sm_get_pool_memory(PM_FNAME);
      pwszBuf = sm_check_pool_memory_size (pwszBuf, maxlen*sizeof(wchar_t));

      n = p_GetCurrentDirectoryW(maxlen, (LPWSTR) pwszBuf);
      if (n!=0)
         n = wchar_2_UTF8 (buf, (wchar_t *)pwszBuf, maxlen)-1;
      sm_free_pool_memory(pwszBuf);

   } else if (p_GetCurrentDirectoryA)
      n = p_GetCurrentDirectoryA(maxlen, buf);

   if (n == 0 || n > maxlen) return NULL;

   if (n+1 > maxlen) return NULL;
   if (n != 3) {
       buf[n] = '\\';
       buf[n+1] = 0;
   }
   return buf;
}

int
win32_fputs(const char *string, FILE *stream)
{
   /* we use WriteConsoleA / WriteConsoleA
      so we can be sure that unicode support works on win32.
      with fallback if something fails
   */

   HANDLE hOut = GetStdHandle (STD_OUTPUT_HANDLE);
   if (hOut && (hOut != INVALID_HANDLE_VALUE) && p_WideCharToMultiByte &&
       p_MultiByteToWideChar && (stream == stdout)) {

      char* pwszBuf = sm_get_pool_memory(PM_MESSAGE);

      DWORD dwCharsWritten;
      DWORD dwChars;

      dwChars = UTF8_2_wchar(&pwszBuf, string);

      /* try WriteConsoleW */
      if (WriteConsoleW (hOut, pwszBuf, dwChars-1, &dwCharsWritten, NULL)) {
         sm_free_pool_memory(pwszBuf);
         return dwCharsWritten;
      }

      /* convert to local codepage and try WriteConsoleA */
      char* pszBuf = sm_get_pool_memory(PM_MESSAGE);
      pszBuf = sm_check_pool_memory_size(pszBuf, dwChars+1);

      dwChars = p_WideCharToMultiByte(GetConsoleOutputCP(),0,(LPCWSTR)pwszBuf,-1,pszBuf,dwChars,NULL,NULL);
      sm_free_pool_memory(pwszBuf);

      if (WriteConsoleA (hOut, pszBuf, dwChars-1, &dwCharsWritten, NULL)) {
         sm_free_pool_memory(pszBuf);
         return dwCharsWritten;
      }
      sm_free_pool_memory(pszBuf);
   }
   /* Fall back */
   return fputs(string, stream);
}

char*
win32_cgets (char* buffer, int len)
{
   /* we use console ReadConsoleA / ReadConsoleW to be able to read unicode
      from the win32 console and fallback if seomething fails */

   HANDLE hIn = GetStdHandle (STD_INPUT_HANDLE);
   if (hIn && (hIn != INVALID_HANDLE_VALUE) && p_WideCharToMultiByte && p_MultiByteToWideChar) {
      DWORD dwRead;
      wchar_t wszBuf[1024];
      char  szBuf[1024];

      /* nt and unicode conversion */
      if (ReadConsoleW (hIn, wszBuf, 1024, &dwRead, NULL)) {

         /* null terminate at end */
         if (wszBuf[dwRead-1] == L'\n') {
            wszBuf[dwRead-1] = L'\0';
            dwRead --;
         }

         if (wszBuf[dwRead-1] == L'\r') {
            wszBuf[dwRead-1] = L'\0';
            dwRead --;
         }

         wchar_2_UTF8(buffer, wszBuf, len);
         return buffer;
      }

      /* win 9x and unicode conversion */
      if (ReadConsoleA (hIn, szBuf, 1024, &dwRead, NULL)) {

         /* null terminate at end */
         if (szBuf[dwRead-1] == L'\n') {
            szBuf[dwRead-1] = L'\0';
            dwRead --;
         }

         if (szBuf[dwRead-1] == L'\r') {
            szBuf[dwRead-1] = L'\0';
            dwRead --;
         }

         /* convert from ansii to wchar_t */
         p_MultiByteToWideChar(GetConsoleCP(), 0, szBuf, -1, wszBuf,1024);
         /* convert from wchar_t to UTF-8 */
         if (wchar_2_UTF8(buffer, wszBuf, len))
            return buffer;
      }
   }

   /* fallback */
   if (fgets(buffer, len, stdin))
      return buffer;
   else
      return NULL;
}

int
win32_unlink(const char *filename)
{
   int nRetCode;
   if (p_wunlink) {
      char* pwszBuf = sm_get_pool_memory(PM_FNAME);
      make_win32_path_UTF8_2_wchar(&pwszBuf, filename);

      nRetCode = _wunlink((LPCWSTR) pwszBuf);

      /*
       * special case if file is readonly,
       * we retry but unset attribute before
       */
      if (nRetCode == -1 && errno == EACCES && p_SetFileAttributesW && p_GetFileAttributesW) {
         DWORD dwAttr =  p_GetFileAttributesW((LPCWSTR)pwszBuf);
         if (dwAttr != INVALID_FILE_ATTRIBUTES) {
            if (p_SetFileAttributesW((LPCWSTR)pwszBuf, dwAttr & ~FILE_ATTRIBUTE_READONLY)) {
               nRetCode = _wunlink((LPCWSTR) pwszBuf);
               /* reset to original if it didn't help */
               if (nRetCode == -1)
                  p_SetFileAttributesW((LPCWSTR)pwszBuf, dwAttr);
            }
         }
      }
      sm_free_pool_memory(pwszBuf);
   } else {
      nRetCode = _unlink(filename);

      /* special case if file is readonly,
      we retry but unset attribute before */
      if (nRetCode == -1 && errno == EACCES && p_SetFileAttributesA && p_GetFileAttributesA) {
         DWORD dwAttr =  p_GetFileAttributesA(filename);
         if (dwAttr != INVALID_FILE_ATTRIBUTES) {
            if (p_SetFileAttributesA(filename, dwAttr & ~FILE_ATTRIBUTE_READONLY)) {
               nRetCode = _unlink(filename);
               /* reset to original if it didn't help */
               if (nRetCode == -1)
                  p_SetFileAttributesA(filename, dwAttr);
            }
         }
      }
   }
   return nRetCode;
}


#include "mswinver.h"

char WIN_VERSION_LONG[64];
char WIN_VERSION[32];
char WIN_RAWVERSION[32];

class winver {
public:
    winver(void);
};

static winver INIT;                     // cause constructor to be called before main()


winver::winver(void)
{
    const char *version = "";
    const char *platform = "";
    OSVERSIONINFO osvinfo;
    osvinfo.dwOSVersionInfoSize = sizeof(osvinfo);

    // Get the current OS version
    if (!GetVersionEx(&osvinfo)) {
        version = "Unknown";
        platform = "Unknown";
    }
        const int ver = _mkversion(osvinfo.dwPlatformId,
                                   osvinfo.dwMajorVersion,
                                   osvinfo.dwMinorVersion);
        snprintf(WIN_RAWVERSION, sizeof(WIN_RAWVERSION), "Windows %#08x", ver);
        switch (ver)
        {
        case MS_WINDOWS_95: (version =  "Windows 95"); break;
        case MS_WINDOWS_98: (version =  "Windows 98"); break;
        case MS_WINDOWS_ME: (version =  "Windows ME"); break;
        case MS_WINDOWS_NT4:(version =  "Windows NT 4.0"); platform = "NT"; break;
        case MS_WINDOWS_2K: (version =  "Windows 2000");platform = "NT"; break;
        case MS_WINDOWS_XP: (version =  "Windows XP");platform = "NT"; break;
        case MS_WINDOWS_S2003: (version =  "Windows Server 2003");platform = "NT"; break;
        default: version = WIN_RAWVERSION; break;
        }

    snprintf(WIN_VERSION_LONG, sizeof(WIN_VERSION_LONG), "%s", version);
    snprintf(WIN_VERSION, sizeof(WIN_VERSION), "%s %lu.%lu.%lu",
             platform, osvinfo.dwMajorVersion, osvinfo.dwMinorVersion, osvinfo.dwBuildNumber);

#if 0
    HANDLE h = CreateFile("G:\\foobar", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    CloseHandle(h);
#endif
}

VOID WriteToPipe(VOID);
VOID ReadFromPipe(VOID);
VOID ErrorExit(LPCSTR);
VOID ErrMsg(LPTSTR, BOOL);

/**
 * Check for a quoted path,  if an absolute path name is given and it contains
 * spaces it will need to be quoted.  i.e.  "c:/Program Files/foo/bar.exe"
 * CreateProcess() says the best way to ensure proper results with executables
 * with spaces in path or filename is to quote the string.
 */
const char *
getArgv0(const char *cmdline)
{

    int inquote = 0;
    const char *cp;
    for (cp = cmdline; *cp; cp++)
    {
        if (*cp == '"') {
            inquote = !inquote;
        }
        if (!inquote && isspace(*cp))
            break;
    }


    int len = cp - cmdline;
    char *rval = (char *)malloc(len+1);

    cp = cmdline;
    char *rp = rval;

    while (len--)
        *rp++ = *cp++;

    *rp = 0;
    return rval;
}

/*
 * Extracts the executable or script name from the first string in 
 * cmdline.
 *
 * If the name contains blanks then it must be quoted with double quotes,
 * otherwise quotes are optional.  If the name contains blanks then it 
 * will be converted to a short name.
 *
 * The optional quotes will be removed.  The result is copied to a malloc'ed
 * buffer and returned through the pexe argument.  The pargs parameter is set
 * to the address of the character in cmdline located after the name.
 *
 * The malloc'ed buffer returned in *pexe must be freed by the caller.
 */
bool
GetApplicationName(const char *cmdline, char **pexe, const char **pargs)
{
   const char *pExeStart = NULL;    /* Start of executable name in cmdline */
   const char *pExeEnd = NULL;      /* Character after executable name (separator) */

   const char *pBasename = NULL;    /* Character after last path separator */
   const char *pExtension = NULL;   /* Period at start of extension */

   const char *current = cmdline;

   bool bQuoted = false;

   /* Skip initial whitespace */

   while (*current == ' ' || *current == '\t')
   {
      current++;
   }

   /* Calculate start of name and determine if quoted */

   if (*current == '"') {
      pExeStart = ++current;
      bQuoted = true;
   } else {
      pExeStart = current;
      bQuoted = false;
   }

   *pargs = NULL;
   *pexe = NULL;

   /* 
    * Scan command line looking for path separators (/ and \\) and the 
    * terminator, either a quote or a blank.  The location of the 
    * extension is also noted.
    */

   for ( ; *current != '\0'; current++)
   {
      if (*current == '.') {
         pExtension = current;
      } else if (IsPathSeparator(*current) && current[1] != '\0') {
         pBasename = &current[1];
         pExtension = NULL;
      }

      /* Check for terminator, either quote or blank */
      if (bQuoted) {
         if (*current != '"') {
            continue;
         }
      } else {
         if (*current != ' ') {
            continue;
         }
      }

      /*
       * Hit terminator, remember end of name (address of terminator) and 
       * start of arguments 
       */
      pExeEnd = current;

      if (bQuoted && *current == '"') {
         *pargs = &current[1];
      } else {
         *pargs = current;
      }

      break;
   }

   if (pBasename == NULL) {
      pBasename = pExeStart;
   }

   if (pExeEnd == NULL) {
      pExeEnd = current;
   }

   if (*pargs == NULL)
   {
      *pargs = current;
   }

   bool bHasPathSeparators = pExeStart != pBasename;

   /* We have pointers to all the useful parts of the name */

   /* Default extensions in the order cmd.exe uses to search */

   static const char ExtensionList[][5] = { ".com", ".exe", ".bat", ".cmd" };
   DWORD dwBasePathLength = pExeEnd - pExeStart;

   DWORD dwAltNameLength = 0;
   char *pPathname = (char *)alloca(MAX_PATHLENGTH + 1);
   char *pAltPathname = (char *)alloca(MAX_PATHLENGTH + 1);

   pPathname[MAX_PATHLENGTH] = '\0';
   pAltPathname[MAX_PATHLENGTH] = '\0';

   memcpy(pPathname, pExeStart, dwBasePathLength);
   pPathname[dwBasePathLength] = '\0';

   if (pExtension == NULL) {
      /* Try appending extensions */
      for (int index = 0; index < (int)(sizeof(ExtensionList) / sizeof(ExtensionList[0])); index++) {

         if (!bHasPathSeparators) {
            /* There are no path separators, search in the standard locations */
            dwAltNameLength = SearchPath(NULL, pPathname, ExtensionList[index], MAX_PATHLENGTH, pAltPathname, NULL);
            if (dwAltNameLength > 0 && dwAltNameLength <= MAX_PATHLENGTH) {
               memcpy(pPathname, pAltPathname, dwAltNameLength);
               pPathname[dwAltNameLength] = '\0';
               break;
            }
         } else {
            snprintf(&pPathname[dwBasePathLength], MAX_PATHLENGTH - dwBasePathLength, "%s", ExtensionList[index]);
            if (GetFileAttributes(pPathname) != INVALID_FILE_ATTRIBUTES) {
               break;
            }
            pPathname[dwBasePathLength] = '\0';
         }
      }
   } else if (!bHasPathSeparators) {
      /* There are no path separators, search in the standard locations */
      dwAltNameLength = SearchPath(NULL, pPathname, NULL, MAX_PATHLENGTH, pAltPathname, NULL);
      if (dwAltNameLength > 0 && dwAltNameLength < MAX_PATHLENGTH) {
         memcpy(pPathname, pAltPathname, dwAltNameLength);
         pPathname[dwAltNameLength] = '\0';
      }
   }

   if (strchr(pPathname, ' ') != NULL) {
      dwAltNameLength = GetShortPathName(pPathname, pAltPathname, MAX_PATHLENGTH);

      if (dwAltNameLength > 0 && dwAltNameLength <= MAX_PATHLENGTH) {
         *pexe = (char *)malloc(dwAltNameLength + 1);
         if (*pexe == NULL) {
            return false;
         }
         memcpy(*pexe, pAltPathname, dwAltNameLength + 1);
      }
   }

   if (*pexe == NULL) {
      DWORD dwPathnameLength = strlen(pPathname);
      *pexe = (char *)malloc(dwPathnameLength + 1);
      if (*pexe == NULL) {
         return false;
      }
      memcpy(*pexe, pPathname, dwPathnameLength + 1);
   }

   return true;
}

void
ErrorExit (LPCSTR lpszMessage)
{
}

int
kill(int pid, int signal)
{
   int rval = 0;
   if (!TerminateProcess((HANDLE)pid, (UINT) signal)) {
      rval = -1;
      errno = b_errno_win32;
   }
   CloseHandle((HANDLE)pid);
   return rval;
}

/* syslog function, added by Nicolas Boichat */
void openlog(const char *ident, int option, int facility) {}  

static pid_t do_forkchild(FILE **sin, FILE **sout, FILE **serr, const char *path, char * const argv[], int do_wait)
{
    int a=0;
    char cmd[1024]="";
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );

    while(argv[a] && strlen(cmd)+strlen(argv[a])+10<sizeof(cmd))
    {
	if(a>0) strcat(cmd, " ");
	strcat(cmd, "\"");
	strcat(cmd, argv[a++]);
	strcat(cmd, "\"");
    }
    if( !CreateProcess( NULL,   
        cmd,        
        NULL,         
        NULL,         
        FALSE,        
        0,            
        NULL,           
        NULL,           
        &si,            
        &pi )           
        ) 
    {
        printf( "CreateProcess %s failed\n", path);
        return -1;
    }
    if(do_wait) WaitForSingleObject( pi.hProcess, INFINITE );
    CloseHandle( pi.hProcess );
    CloseHandle( pi.hThread );
    return 0;
}

pid_t forkchild(FILE **sin, FILE **sout, FILE **serr, const char *path, char * const argv[])
{
	return do_forkchild(sin, sout, serr, path, argv, 1 /* wait */);
}

pid_t forkchild_no_wait(FILE **sin, FILE **sout, FILE **serr, const char *path, char * const argv[])
{
	return do_forkchild(sin, sout, serr, path, argv, 0 /* do not wait */);
}

int win32_utime(const char *fname, struct utimbuf *times)
{
    FILETIME acc, mod;
    char tmpbuf[5000];

    conv_unix_to_win32_path(fname, tmpbuf, 5000);

    cvt_utime_to_ftime(times->actime, acc);
    cvt_utime_to_ftime(times->modtime, mod);

    HANDLE h = INVALID_HANDLE_VALUE;

    if (p_CreateFileW) {
       char* pwszBuf = sm_get_pool_memory(PM_FNAME);
       make_win32_path_UTF8_2_wchar(&pwszBuf, tmpbuf);

       h = p_CreateFileW((LPCWSTR)pwszBuf,
                        FILE_WRITE_ATTRIBUTES,
                        FILE_SHARE_WRITE|FILE_SHARE_READ|FILE_SHARE_DELETE,
                        NULL,
                        OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS, // required for directories
                        NULL);

       sm_free_pool_memory(pwszBuf);
    } else if (p_CreateFileA) {
       h = p_CreateFileA(tmpbuf,
                        FILE_WRITE_ATTRIBUTES,
                        FILE_SHARE_WRITE|FILE_SHARE_READ|FILE_SHARE_DELETE,
                        NULL,
                        OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS, // required for directories
                        NULL);
    }

    if (h == INVALID_HANDLE_VALUE) {
       const char *err = errorString();
       fprintf(stderr, "Cannot open %s for utime(): ERR=%s\n", tmpbuf, err);
       LocalFree((void *)err);
       errno = b_errno_win32;
       return -1;
    }

    int rval = SetFileTime(h, NULL, &acc, &mod) ? 0 : -1;
    CloseHandle(h);
    if (rval == -1) {
       errno = b_errno_win32;
    }
    return rval;
}
