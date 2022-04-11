/*
   Bacula® - The Network Backup Solution

   Copyright (C) 2004-2009 Free Software Foundation Europe e.V.

   The main author of Bacula is Kern Sibbald, with contributions from
   many others, a complete list can be found in the file AUTHORS.
   This program is Free Software; you can redistribute it and/or
   modify it under the terms of version three of the GNU Affero General Public
   License as published by the Free Software Foundation and included
   in the file LICENSE.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
   General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301, USA.

   Bacula® is a registered trademark of Kern Sibbald.
   The licensor of Bacula is the Free Software Foundation Europe
   (FSFE), Fiduciary Program, Sumatrastrasse 25, 8006 Zürich,
   Switzerland, email:ftf@fsfeurope.org.
*/
//                              -*- Mode: C++ -*-
// compat.cpp -- compatibilty layer to make bacula-fd run
//               natively under windows
//
// Copyright transferred from Raider Solutions, Inc to
//   Kern Sibbald and John Walker by express permission.
//
// Author          : Christopher S. Hull
// Created On      : Sat Jan 31 15:55:00 2004

#include "burp.h"
#include "compat.h"
#include "sys/time.h"
#include "mem_pool.h"
#include "berrno.h"

/* UTF-8 to UCS2 path conversion is expensive,
   so we cache the conversion. During backup the
   conversion is called 3 times (lstat, attribs, open),
   by using the cache this is reduced to 1 time */

static char *g_pWin32ConvUTF8Cache = NULL;
static char *g_pWin32ConvUCS2Cache = NULL;
static DWORD g_dwWin32ConvUTF8strlen = 0;

static t_pVSSPathConvert g_pVSSPathConvert;
static t_pVSSPathConvertW g_pVSSPathConvertW;

// Forward referenced functions.
static const char *errorString(void);

void SetVSSPathConvert(t_pVSSPathConvert pPathConvert,
	t_pVSSPathConvertW pPathConvertW)
{
	g_pVSSPathConvert = pPathConvert;
	g_pVSSPathConvertW = pPathConvertW;
}

static void Win32ConvInitCache(void)
{
	if(g_pWin32ConvUTF8Cache) return;
	g_pWin32ConvUTF8Cache=sm_get_pool_memory();
	g_pWin32ConvUCS2Cache=sm_get_pool_memory();
}

void Win32ConvCleanupCache(void)
{
	if(g_pWin32ConvUTF8Cache)
	{
		sm_free_pool_memory(g_pWin32ConvUTF8Cache);
		g_pWin32ConvUTF8Cache=NULL;
	}

	if(g_pWin32ConvUCS2Cache)
	{
		sm_free_pool_memory(g_pWin32ConvUCS2Cache);
		g_pWin32ConvUCS2Cache=NULL;
	}

	g_dwWin32ConvUTF8strlen=0;
}

//#define USE_WIN32_COMPAT_IO 1
#define USE_WIN32_32KPATHCONVERSION 1

extern DWORD g_platform_id;
extern DWORD g_MinorVersion;

// From MicroSoft SDK (KES) is the diff between Jan 1 1601 and Jan 1 1970.
#define WIN32_FILETIME_ADJUST 0x19DB1DED53E8000ULL

#define WIN32_FILETIME_SCALE 10000000 // 100ns/second

void conv_unix_to_win32_path(const char *name, char *win32_name, DWORD dwSize)
{
	char *tname=win32_name;
	const char *fname=name;

	if(IsPathSeparator(name[0])
	  && IsPathSeparator(name[1])
	  && name[2]=='.'
	  && IsPathSeparator(name[3]))
	{
		*win32_name++='\\';
		*win32_name++='\\';
		*win32_name++='.';
		*win32_name++='\\';
		name+=4;
	}
	else if(g_platform_id!=VER_PLATFORM_WIN32_WINDOWS
	  && !g_pVSSPathConvert)
	{
		// Allow path to be 32767 bytes.
		*win32_name++='\\';
		*win32_name++='\\';
		*win32_name++='?';
		*win32_name++='\\';
	}

	while(*name)
	{
		// Check for Unix separator and convert to Win32.
		if(name[0]=='/' && name[1]=='/')
			name++;
		if(*name=='/')
			*win32_name++='\\';
		else if(*name=='\\'&& name[1]=='\\')
		{
			*win32_name++='\\';
			name++;
		}
		else
			*win32_name++=*name;
		name++;
	}

	// Strip any trailing slash, if we stored something.
	// But leave "c:\" with backslash (root directory case).
	if(*fname && win32_name[-1]=='\\' && strlen(fname)!=3)
		win32_name[-1]=0;
	else
		*win32_name=0;

	/* Here we convert to VSS specific file name which
	   can get longer because VSS will make something like
	   \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\burp\\x.exe
	   from c:\burp\x.exe
	 */
	if(g_pVSSPathConvert)
	{
		char *pszBuf=sm_get_pool_memory();
		pszBuf=sm_check_pool_memory_size(pszBuf, dwSize);
		snprintf(pszBuf, strlen(tname)+1, "%s", tname);
		g_pVSSPathConvert(pszBuf, tname, dwSize);
		sm_free_pool_memory(pszBuf);
	}
}

/* Created 02/27/2006 Thorsten Engel.
   This function expects an UCS-encoded standard wchar_t in pszUCSPath and
   will complete the input path to an absolue path of the form \\?\c:\path\file

   With this trick, it is possible to have 32K characters long paths.

   Optionally one can use pBIsRawPath to determine id pszUCSPath contains a
   path to a raw windows partition. */
char *make_wchar_win32_path(char *pszUCSPath, BOOL *pBIsRawPath)
{
	if(pBIsRawPath) *pBIsRawPath=FALSE;

	if(!p_GetCurrentDirectoryW) return pszUCSPath;

	wchar_t *name=(wchar_t *)pszUCSPath;

	// If it has already the desired form, exit without changes.
	if(wcslen(name)>3 && !wcsncmp(name, L"\\\\?\\", 4))
		return pszUCSPath;

	wchar_t *pwszBuf=(wchar_t *)sm_get_pool_memory();
	wchar_t *pwszCurDirBuf=(wchar_t *)sm_get_pool_memory();
	DWORD dwCurDirPathSize=0;

	// Get buffer with enough size (name+max 6. wchars+1 null terminator.
	DWORD dwBufCharsNeeded=(wcslen(name)+7);
	pwszBuf=(wchar_t *)sm_check_pool_memory_size((char *)pwszBuf,
		dwBufCharsNeeded*sizeof(wchar_t));

	/* Add \\?\ to support 32K long filepaths.
	   It is important to make absolute paths, so we add drive and
	   current path if necessary. */

	BOOL bAddDrive=TRUE;
	BOOL bAddCurrentPath=TRUE;
	BOOL bAddPrefix=TRUE;

	// Does path begin with drive? if yes, it is absolute.
	if(iswalpha(name[0]) && name[1]==':' && IsPathSeparator(name[2]))
	{
		bAddDrive=FALSE;
		bAddCurrentPath=FALSE;
	}

	// Is path absolute?
	if(IsPathSeparator(name[0])) bAddCurrentPath=FALSE;

	// Skip ./ if path is relative to itself?
	if(name[0]=='.' && IsPathSeparator(name[1])) name+=2;

	// Is path of form '//./'?
	if(IsPathSeparator(name[0])
	  && IsPathSeparator(name[1])
	  && name[2]=='.'
	  && IsPathSeparator(name[3]))
	{
		bAddDrive=FALSE;
		bAddCurrentPath=FALSE;
		bAddPrefix=FALSE;
		if(pBIsRawPath) *pBIsRawPath=TRUE;
	}

	int nParseOffset=0;

	// add 4 bytes header.
	if(bAddPrefix)
	{
		nParseOffset=4;
		wcscpy(pwszBuf, L"\\\\?\\");
	}

	// Get current path if needed.
	if(bAddDrive || bAddCurrentPath)
	{
		dwCurDirPathSize=p_GetCurrentDirectoryW(0, NULL);
		if(dwCurDirPathSize>0)
		{
			/* Get directory into own buffer as it may either
			   return c:\... or \\?\C:\.... */
			pwszCurDirBuf=(wchar_t *)sm_check_pool_memory_size(
				(char *)pwszCurDirBuf,
				(dwCurDirPathSize+1)*sizeof(wchar_t));
			p_GetCurrentDirectoryW(dwCurDirPathSize,
				pwszCurDirBuf);
		}
		else
		{
			// We have no info for doing so.
			bAddDrive=FALSE;
			bAddCurrentPath=FALSE;
		}
	}

	// Add drive if needed.
	if(bAddDrive && !bAddCurrentPath)
	{
		wchar_t szDrive[3];

		if(IsPathSeparator(pwszCurDirBuf[0])
		  && IsPathSeparator(pwszCurDirBuf[1])
		  && pwszCurDirBuf[2]=='?'
		  && IsPathSeparator(pwszCurDirBuf[3]))
			szDrive[0]=pwszCurDirBuf[4];
		else
			szDrive[0]=pwszCurDirBuf[0];

		szDrive[1]=':';
		szDrive[2]=0;

		wcscat(pwszBuf, szDrive);
		nParseOffset+=2;
	}

	// Add path if needed.
	if(bAddCurrentPath)
	{
		// The 1 add. character is for the eventually added backslash.
		dwBufCharsNeeded+=dwCurDirPathSize+1;
		pwszBuf=(wchar_t *)sm_check_pool_memory_size((char *)pwszBuf,
			dwBufCharsNeeded*sizeof(wchar_t));
		/* get directory into own buffer as it may either
		   return c:\... or \\?\C:\.... */

		if(IsPathSeparator(pwszCurDirBuf[0])
		  && IsPathSeparator(pwszCurDirBuf[1])
		  && pwszCurDirBuf[2]=='?'
		  && IsPathSeparator(pwszCurDirBuf[3]))
			wcscpy(pwszBuf, pwszCurDirBuf);
		else
			wcscat(pwszBuf, pwszCurDirBuf);

		nParseOffset=wcslen((LPCWSTR) pwszBuf);

		// check if path ends with backslash, if not, add one.
		if(!IsPathSeparator(pwszBuf[nParseOffset-1]))
		{
			wcscat(pwszBuf, L"\\");
			nParseOffset++;
		}
	}

	wchar_t *win32_name=&pwszBuf[nParseOffset];
	wchar_t *name_start=name;

	while(*name)
	{
		/* Check for Unix separator and convert to Win32, eliminating
		  duplicate separators.  */
		if(IsPathSeparator(*name))
		{
			*win32_name++ = '\\';
			/* Eliminate consecutive slashes, but not at the start
			   so that  \\.\ still works.  */
			if(name_start!=name && IsPathSeparator(name[1]))
				name++;
		}
		else
			*win32_name++=*name;
		name++;
	}

	// Null terminate string.
	*win32_name=0;

	/* here we convert to VSS specific file name which
	   can get longer because VSS will make something like
	   \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\burp\\x.exe
	   from c:\burp\x.exe */
	if(g_pVSSPathConvertW)
	{
		// Is output buffer large enough?
		pwszBuf=(wchar_t *)sm_check_pool_memory_size((char *)pwszBuf,
			(dwBufCharsNeeded+MAX_PATH)*sizeof(wchar_t));
		// Create temp. buffer.
		wchar_t *pszBuf=(wchar_t *)sm_get_pool_memory();
		pszBuf=(wchar_t *)sm_check_pool_memory_size((char *)pszBuf,
			(dwBufCharsNeeded+MAX_PATH)*sizeof(wchar_t));
		if(bAddPrefix) nParseOffset=4;
		else nParseOffset=0;
		wcsncpy(pszBuf, &pwszBuf[nParseOffset],
			wcslen(pwszBuf)+1-nParseOffset);
		g_pVSSPathConvertW(pszBuf, pwszBuf, dwBufCharsNeeded+MAX_PATH);
		sm_free_pool_memory((char *)pszBuf);
	}

	sm_free_pool_memory(pszUCSPath);
	sm_free_pool_memory((char *)pwszCurDirBuf);

	return (char *)pwszBuf;
}

/* The return value is the number of bytes written to the buffer.
   The number includes the byte for the null terminator. */
int wchar_2_UTF8(char *pszUTF, const wchar_t *pszUCS, int cchChar)
{
	int ret=0;
	ret=p_WideCharToMultiByte(CP_UTF8,
		0, pszUCS, -1, pszUTF, cchChar, NULL, NULL);
	ASSERT(ret>0);
	return ret;
}

/* The return value is the number of wide characters written to the buffer.
   Convert null terminated string from utf-8 to ucs2, enlarge buffer if
   necessary. */
int UTF8_2_wchar(char **ppszUCS, const char *pszUTF)
{
	int ret=0;
	DWORD cchSize;
	if(!p_MultiByteToWideChar) return ret;

	// strlen of UTF8 +1 is enough.
	cchSize=strlen(pszUTF)+1;
	*ppszUCS=sm_check_pool_memory_size(*ppszUCS, cchSize*sizeof(wchar_t));
	ret=p_MultiByteToWideChar(CP_UTF8,
		0, pszUTF, -1, (LPWSTR)*ppszUCS, cchSize);

	ASSERT(ret>0);
	return ret;
}

// Allows one or both pointers to be NULL
static bool bstrcmp(const char *s1, const char *s2)
{
	if(s1 == s2) return true;
	if(!s1 || !s2) return false;
	return !strcmp(s1, s2);
}

/* If we find the utf8 string in cache, we use the cached ucs2 version.
   We compare the stringlength first (quick check) and then compare the
   content.            */
int make_win32_path_UTF8_2_wchar(
	char **pszUCS,
	const char *pszUTF,
	BOOL *pBIsRawPath
) {
	if(!g_pWin32ConvUTF8Cache)
		Win32ConvInitCache();
	else if(g_dwWin32ConvUTF8strlen==strlen(pszUTF))
	{
		if(bstrcmp(pszUTF, g_pWin32ConvUTF8Cache))
		{
			// Return cached value.
			int32_t nBufSize=sm_sizeof_pool_memory(
				g_pWin32ConvUCS2Cache);
			*pszUCS=sm_check_pool_memory_size(*pszUCS, nBufSize);
			wcscpy((LPWSTR)*pszUCS, (LPWSTR)g_pWin32ConvUCS2Cache);
			return nBufSize/sizeof(WCHAR);
		}
	}

	/* Helper to convert from utf-8 to UCS-2 and to complete a path for 32K
	   path syntax */
	int nRet=UTF8_2_wchar(pszUCS, pszUTF);

#ifdef USE_WIN32_32KPATHCONVERSION
	// Add \\?\ to support 32K long filepaths.
	*pszUCS=make_wchar_win32_path(*pszUCS, pBIsRawPath);
#else
	if(pBIsRawPath) *pBIsRawPath=FALSE;
#endif

	// Populate cache.
	g_pWin32ConvUCS2Cache=sm_check_pool_memory_size(g_pWin32ConvUCS2Cache,
		sm_sizeof_pool_memory(*pszUCS));
	wcscpy((LPWSTR)g_pWin32ConvUCS2Cache, (LPWSTR)*pszUCS);

	g_dwWin32ConvUTF8strlen=strlen(pszUTF);
	g_pWin32ConvUTF8Cache=sm_check_pool_memory_size(g_pWin32ConvUTF8Cache,
		g_dwWin32ConvUTF8strlen+2);
	snprintf(g_pWin32ConvUTF8Cache,
		g_dwWin32ConvUTF8strlen+1, "%s", pszUTF);

	return nRet;
}

char *make_win32_path_UTF8_2_wchar_w(const char *pszUTF)
{
	int size=0;
	char *ret=NULL;
	char *tmp=sm_get_pool_memory();

	size=make_win32_path_UTF8_2_wchar(&tmp, pszUTF);
	if(size>0)
	{
		ret=(char *)malloc(2*strlen(pszUTF)+MAX_PATH);
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
	handle=LoadLibraryEx(file, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
	return handle;
}

void *dlsym(void *handle, const char *name)
{
	void *symaddr;
	symaddr=(void *)GetProcAddress((HMODULE)handle, name);
	return symaddr;
}

int dlclose(void *handle)
{
	if(handle && !FreeLibrary((HMODULE)handle))
	{
		errno=b_errno_win32;
		return 1; // Failed.
	}
	return 0;
}

char *dlerror(void)
{
	static char buf[200];
	const char *err=errorString();
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

long int random(void)
{
	return rand();
}

void srandom(unsigned int seed)
{
	srand(seed);
}

// Convert from Windows concept of time to Unix concept of time.
void cvt_utime_to_ftime(const time_t &time, FILETIME &wintime)
{
	uint64_t mstime=time;
	mstime*=WIN32_FILETIME_SCALE;
	mstime+=WIN32_FILETIME_ADJUST;

#if defined(_MSC_VER)
	wintime.dwLowDateTime=(DWORD)(mstime & 0xffffffffI64);
#else
	wintime.dwLowDateTime=(DWORD)(mstime & 0xffffffffUL);
#endif
	wintime.dwHighDateTime=(DWORD)((mstime>>32)& 0xffffffffUL);
}

time_t cvt_ftime_to_utime(const FILETIME &time)
{
	uint64_t mstime=time.dwHighDateTime;
	mstime<<=32;
	mstime|=time.dwLowDateTime;

	mstime-=WIN32_FILETIME_ADJUST;
	mstime/=WIN32_FILETIME_SCALE; // convert to seconds.

	return (time_t)(mstime & 0xffffffff);
}

static const char *errorString(void)
{
	char *cp;
	char *rval;
	LPVOID lpMsgBuf;

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER
		| FORMAT_MESSAGE_FROM_SYSTEM
		| FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default lang
		(LPTSTR)&lpMsgBuf,
		0,
		NULL);

	// Strip any \r or \n.
	rval=(char *)lpMsgBuf;
	if((cp=strchr(rval, '\r'))) *cp=0;
	else if((cp=strchr(rval, '\n'))) *cp=0;
	return rval;
}

// Explicitly open the file to read the reparse point, then call
// DeviceIoControl to find out if it points to a volume or to a directory.
static void reparse_or_mount_song_and_dance(
	const char *file,
	struct stat *sb,
	DWORD reparse_tag
) {
	char dummy[1000]="";
	char *utf8=NULL;
	char *pwszBuf=NULL;
	REPARSE_DATA_BUFFER *rdb=NULL;
	HANDLE h=INVALID_HANDLE_VALUE;
	DWORD bytes;

	sb->st_rdev=WIN32_MOUNT_POINT;

	pwszBuf=sm_get_pool_memory();
	make_win32_path_UTF8_2_wchar(&pwszBuf, file);
	rdb=(REPARSE_DATA_BUFFER *)dummy;

	h=CreateFileW((LPCWSTR)pwszBuf, GENERIC_READ,
		FILE_SHARE_READ, NULL, OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS
		| FILE_FLAG_OPEN_REPARSE_POINT,
		NULL);
	sm_free_pool_memory(pwszBuf);

	if(h==INVALID_HANDLE_VALUE)
		return;
	rdb->ReparseTag=reparse_tag;
	if(!DeviceIoControl(h, FSCTL_GET_REPARSE_POINT,
		NULL, 0, // in buffer, bytes
		(LPVOID)rdb,
		(DWORD)sizeof(dummy), // out buffer, btyes
		(LPDWORD)&bytes, (LPOVERLAPPED)0))
			return;

	utf8=sm_get_pool_memory();

	wchar_2_UTF8(utf8,
		(wchar_t *)rdb->SymbolicLinkReparseBuffer.PathBuffer);
	if(!strncasecmp(utf8, "\\??\\volume{", 11))
		sb->st_rdev=WIN32_MOUNT_POINT;
	else // Points to a directory so we ignore it.
		sb->st_rdev=WIN32_JUNCTION_POINT;
	sm_free_pool_memory(utf8);

	CloseHandle(h);
}

static int statDir(const char *file, struct stat *sb, uint64_t *winattr)
{
	WIN32_FIND_DATAW info_w; // window's file info

	// cache some common vars to make code more transparent
	DWORD *pdwFileAttributes;
	DWORD *pnFileSizeHigh;
	DWORD *pnFileSizeLow;
	DWORD *pdwReserved0;
	FILETIME *pftLastAccessTime;
	FILETIME *pftLastWriteTime;
	FILETIME *pftCreationTime;

	/* Oh, cool, another exception: Microsoft doesn't let us do
	   FindFile operations on a Drive, so simply fake root attibutes. */
	if(file[1]==':' && !file[2])
	{
		time_t now=time(NULL);
		sb->st_mode=S_IFDIR;
		sb->st_mode|=S_IREAD|S_IEXEC|S_IWRITE;
		sb->st_ctime=now;
		sb->st_mtime=now;
		sb->st_atime=now;
		sb->st_rdev=0;
		return 0;
	}

	HANDLE h=INVALID_HANDLE_VALUE;

	// use unicode
	if(p_FindFirstFileW)
	{
		char *pwszBuf=sm_get_pool_memory();
		make_win32_path_UTF8_2_wchar(&pwszBuf, file);

		h=p_FindFirstFileW((LPCWSTR)pwszBuf, &info_w);
		sm_free_pool_memory(pwszBuf);

		pdwFileAttributes=&info_w.dwFileAttributes;
		pdwReserved0     =&info_w.dwReserved0;
		pnFileSizeHigh   =&info_w.nFileSizeHigh;
		pnFileSizeLow    =&info_w.nFileSizeLow;
		pftLastAccessTime=&info_w.ftLastAccessTime;
		pftLastWriteTime =&info_w.ftLastWriteTime;
		pftCreationTime  =&info_w.ftCreationTime;
		// use ASCII
	}

	if(h==INVALID_HANDLE_VALUE)
	{
		const char *err = errorString();
		/* Note, in creating leading paths, it is normal that
		   the file does not exist. */
		LocalFree((void *)err);
		errno=b_errno_win32;
		return -1;
	}
	else
		FindClose(h);

	*winattr=(int64_t)*pdwFileAttributes;

	/* Graham says: all the following stuff seems rather complicated.
	   It is probably not all needed anymore, since I have added *winattr
	   above, which bacula did not do.
	   One reason for keeping it is that some of the values get converted
	   to unix-style permissions that show up in the long list
	   functionality.
	   I think I would prefer to remove it all at some point. */

	sb->st_mode = 0777;  // start with everything
	if(*pdwFileAttributes & FILE_ATTRIBUTE_READONLY)
		sb->st_mode &= ~(S_IRUSR|S_IRGRP|S_IROTH);
	if(*pdwFileAttributes & FILE_ATTRIBUTE_SYSTEM)
		sb->st_mode &= ~S_IRWXO; // remove everything for other
	if(*pdwFileAttributes & FILE_ATTRIBUTE_HIDDEN)
		sb->st_mode |= S_ISVTX; // use sticky bit -> hidden
	sb->st_mode |= S_IFDIR;

	/* Store reparse/mount point info in st_rdev.  Note a
	   Win32 reparse point (junction point) is like a link
	   though it can have many properties (directory link,
	   soft link, hard link, HSM, ...
	   A mount point is a reparse point where another volume
	   is mounted, so it is like a Unix mount point (change of
	   filesystem).  */
	sb->st_rdev=0;
	if(*pdwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
		reparse_or_mount_song_and_dance(file, sb, *pdwReserved0);

	sb->st_size=*pnFileSizeHigh;
	sb->st_size<<=32;
	sb->st_size|=*pnFileSizeLow;
	sb->st_blksize=4096;
	sb->st_blocks=(uint32_t)(sb->st_size+4095)/4096;

	sb->st_atime=cvt_ftime_to_utime(*pftLastAccessTime);
	sb->st_mtime=cvt_ftime_to_utime(*pftLastWriteTime);
	sb->st_ctime=cvt_ftime_to_utime(*pftCreationTime);

	return 0;
}

static int do_fstat(intptr_t fd, struct stat *sb, uint64_t *winattr)
{
	BY_HANDLE_FILE_INFORMATION info;

	if(!GetFileInformationByHandle((HANDLE)_get_osfhandle(fd), &info))
	{
		const char *err=errorString();
		LocalFree((void *)err);
		errno=b_errno_win32;
		return -1;
	}

	sb->st_dev=info.dwVolumeSerialNumber;
	sb->st_ino=info.nFileIndexHigh;
	sb->st_ino<<=32;
	sb->st_ino|=info.nFileIndexLow;
	sb->st_nlink=(short)info.nNumberOfLinks;
	*winattr=(int64_t)info.dwFileAttributes;

	/* Graham says: all the following stuff seems rather complicated.
	   It is probably not all needed anymore, since I have added *winattr
	   above, which bacula did not do.
	   One reason for keeping it is that some of the values get converted
	   to unix-style permissions that show up in the long list
	   functionality.
	   I think I would prefer to remove it all though.  */
	sb->st_mode = 0777; // Start with everything.
	if(info.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
		sb->st_mode &= ~(S_IRUSR|S_IRGRP|S_IROTH);
	if(info.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)
		sb->st_mode &= ~S_IRWXO; // Remove everything for other.
	if(info.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)
		sb->st_mode |= S_ISVTX; // Use sticky bit -> hidden.
	sb->st_mode |= S_IFREG;

	// Use st_rdev to store reparse attribute.
	if(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
		sb->st_rdev=WIN32_REPARSE_POINT;

	sb->st_size=info.nFileSizeHigh;
	sb->st_size<<=32;
	sb->st_size|=info.nFileSizeLow;
	sb->st_blksize=4096;
	sb->st_blocks=(uint32_t)(sb->st_size + 4095)/4096;
	sb->st_atime=cvt_ftime_to_utime(info.ftLastAccessTime);
	sb->st_mtime=cvt_ftime_to_utime(info.ftLastWriteTime);
	sb->st_ctime=cvt_ftime_to_utime(info.ftCreationTime);

	return 0;
}

int fstat(intptr_t fd, struct stat *sb)
{
	uint64_t winattr=0;
	return do_fstat(fd, sb, &winattr);
}

static char tmpbuf[_MAX_PATH]="";

static int stat2(const char *file, struct stat *sb, uint64_t *winattr)
{
	HANDLE h=INVALID_HANDLE_VALUE;
	int rval=0;
	conv_unix_to_win32_path(file, tmpbuf, _MAX_PATH);

	DWORD attr=(DWORD)-1;

	if(p_GetFileAttributesW)
	{
		char *pwszBuf=sm_get_pool_memory();
		make_win32_path_UTF8_2_wchar(&pwszBuf, tmpbuf);

		attr=p_GetFileAttributesW((LPCWSTR) pwszBuf);
		if(p_CreateFileW)
			h=CreateFileW((LPCWSTR)pwszBuf, GENERIC_READ,
				FILE_SHARE_READ,
				NULL, OPEN_EXISTING, 0, NULL);
		sm_free_pool_memory(pwszBuf);
	}

	if(attr==(DWORD)-1)
	{
		const char *err=errorString();
		LocalFree((void *)err);
		if(h!=INVALID_HANDLE_VALUE) CloseHandle(h);
		errno=b_errno_win32;
		return -1;
	}

	if(h==INVALID_HANDLE_VALUE)
	{
		const char *err=errorString();
		LocalFree((void *)err);
		errno=b_errno_win32;
		return -1;
	}

	rval=do_fstat((intptr_t)h, sb, winattr);
	CloseHandle(h);

	if(attr & FILE_ATTRIBUTE_DIRECTORY && file[1]==':' && file[2])
		rval = statDir(file, sb, winattr);

	return rval;
}

static int do_stat(const char *file, struct stat *sb, uint64_t *winattr)
{
	WIN32_FILE_ATTRIBUTE_DATA data;
	errno=0;

	memset(sb, 0, sizeof(*sb));
	memset(winattr, 0, sizeof(*winattr));

	if(p_GetFileAttributesExW)
	{
		// Dynamically allocate enough space for UCS2 filename.
		char *pwszBuf=sm_get_pool_memory();
		make_win32_path_UTF8_2_wchar(&pwszBuf, file);

		BOOL b=p_GetFileAttributesExW((LPCWSTR)pwszBuf,
			GetFileExInfoStandard, &data);
		sm_free_pool_memory(pwszBuf);

		if(!b) return stat2(file, sb, winattr);

	}

	*winattr=(int64_t)data.dwFileAttributes;

	/* Graham says: all the following stuff seems rather complicated.
	   It is probably not all needed anymore, since I have added *winattr
	   above, which bacula did not do.
	   One reason for keeping it is that some of the values get converted to
	   unix-style permissions that show up in the long list functionality.
	   I think I would prefer to remove it all though.
	 */
	sb->st_mode = 0777; // Start with everything.
	if(data.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
		sb->st_mode &= ~(S_IRUSR|S_IRGRP|S_IROTH);
	if(data.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)
		sb->st_mode &= ~S_IRWXO; // Remove everything for other.
	if(data.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)
		sb->st_mode |= S_ISVTX; // use sticky bit -> hidden.
	if(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		sb->st_mode |= S_IFDIR;
	else
		sb->st_mode |= S_IFREG;

	// Use st_rdev to store reparse attribute.
	sb->st_rdev=(data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)?1:0;

	sb->st_nlink=1;
	sb->st_size=data.nFileSizeHigh;
	sb->st_size<<=32;
	sb->st_size|=data.nFileSizeLow;
	sb->st_blksize=4096;
	sb->st_blocks=(uint32_t)(sb->st_size + 4095)/4096;
	sb->st_atime=cvt_ftime_to_utime(data.ftLastAccessTime);
	sb->st_mtime=cvt_ftime_to_utime(data.ftLastWriteTime);
	sb->st_ctime=cvt_ftime_to_utime(data.ftCreationTime);

	/* If we are not at the root, then to distinguish a reparse
	   point from a mount point, we must call FindFirstFile() to
	   get the WIN32_FIND_DATA, which has the bit that indicates
	   that this directory is a mount point -- aren't Win32 APIs
	   wonderful? (sarcasm).  The code exists in the statDir
	   subroutine.  */
	if(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY
	  && file[1]==':' && file[2])
		statDir(file, sb, winattr);
	return 0;
}

/* We write our own ftruncate because the one in the
   Microsoft library mrcrt.dll does not truncate
   files greater than 2GB.
   KES - May 2007 */
int win32_ftruncate(int fd, int64_t length)
{
	// Set point we want to truncate file.
	__int64 pos=_lseeki64(fd, (__int64)length, SEEK_SET);

	if(pos!=(__int64)length)
	{
		errno=EACCES;
		return -1;
	}

	// Truncate file.
	if(!SetEndOfFile((HANDLE)_get_osfhandle(fd)))
	{
		errno=b_errno_win32;
		return -1;
	}
	errno=0;
	return 0;
}

int fcntl(int fd, int cmd, long arg)
{
	int rval=0;

	switch(cmd)
	{
		case F_GETFL:
			rval=O_NONBLOCK;
			break;
		case F_SETFL:
			break;
		default:
			errno=EINVAL;
			rval=-1;
			break;
	}

	return rval;
}

int stat(const char *file, struct stat *sb)
{
	uint64_t winattr=0;
	return do_stat(file, sb, &winattr);
}

int lstat(const char *file, struct stat *sb)
{
	uint64_t winattr=0;
	return do_stat(file, sb, &winattr);
}

int win32_lstat(const char *file, struct stat *sb, uint64_t *winattr)
{
	return do_stat(file, sb, winattr);
}

void sleep(int sec)
{
	Sleep(sec*1000);
}

int geteuid(void)
{
	return 0;
}

static int system_error(void)
{
	errno=ENOSYS;
	return -1;
}

int execvp(const char *, char *[]) { return system_error(); }
int fork(void) { return system_error(); }
int pipe(int[]) { return system_error(); }
int waitpid(int, int *, int) { return system_error(); }
int readlink(const char *, char *, int) { return system_error(); }

int strncasecmp(const char *s1, const char *s2, int len)
{
	register int ch1=0;
	register int ch2=0;

	if(s1==s2)
		return 0; // Strings are equal if same object.
	else if(!s1)
		return -1;
	else if(!s2)
		return 1;

	while(len--)
	{
		ch1=*s1;
		ch2=*s2;
		s1++;
		s2++;
		if(!ch1 || tolower(ch1)!=tolower(ch2))
			break;
	}

	return (ch1-ch2);
}

int gettimeofday(struct timeval *tv, struct timezone *)
{
	SYSTEMTIME now;
	FILETIME tmp;

	GetSystemTime(&now);

	if(!tv)
	{
		errno=EINVAL;
		return -1;
	}
	if(!SystemTimeToFileTime(&now, &tmp))
	{
		errno=b_errno_win32;
		return -1;
	}

	int64_t _100nsec=tmp.dwHighDateTime;
	_100nsec<<=32;
	_100nsec|=tmp.dwLowDateTime;
	_100nsec-=WIN32_FILETIME_ADJUST;

	tv->tv_sec=(long)(_100nsec / 10000000);
	tv->tv_usec=(long)((_100nsec % 10000000)/10);
	return 0;

}

// For apcupsd this is in src/lib/wincompat.c.
extern "C" void syslog(int type, const char *fmt, ...)
{
}

void closelog()
{
}

struct passwd *getpwuid(uid_t)
{
	return NULL;
}

struct group * getgrgid(uid_t)
{
	return NULL;
}

// Implement opendir/readdir/closedir on top of window's API.

typedef struct _dir
{
	WIN32_FIND_DATAA data_a; // Window's file info (ansii version).
	WIN32_FIND_DATAW data_w; // Window's file info (wchar version).
	const char *spec;        // The directory we're traversing.
	HANDLE dirh;             // The search handle.
	UINT32 offset;           // Pseudo offset for d_off.
	struct dirent entry;
} _dir;

static void _dir_free(_dir *d)
{
	if(!d) return;
	if(d->spec) free((void *)d->spec);
	free((void *)d);
}

DIR *opendir(const char *path)
{
	ssize_t len=0;
	char *tspec=NULL;
	_dir *rval=NULL;
	int max_len;

	max_len=strlen(path)+MAX_PATH; // Enough space for VSS!

	if(!path)
	{
		errno=ENOENT;
		goto err;
	}

	if(!(rval=(_dir *)calloc(1, sizeof(_dir)))
	  || !(tspec=(char *)malloc(max_len)))
	{
		errno=b_errno_win32;
		goto err;
	}
	rval->dirh=INVALID_HANDLE_VALUE;

	conv_unix_to_win32_path(path, tspec, max_len);

	len=strlen(tspec);
	// Add backslash only if there is none yet (think of c:\).
	if(tspec[len-1] != '\\' && len+1<max_len)
	{
		tspec[len++]='\\';
		tspec[len]='\0';
	}
	if(len+1<max_len)
	{
		tspec[len++]='*';
		tspec[len]='\0';
	}

	rval->spec=tspec;

	return (DIR *)rval;
err:
	_dir_free(rval);
	return NULL;
}

int closedir(DIR *dirp)
{
	if(!dirp) return 0;
	_dir *dp=(_dir *)dirp;
	FindClose(dp->dirh);
	_dir_free(dp);
	return 0;
}

static void copyin(struct dirent *entry, const char *fname)
{
	char *cp=entry->d_name;
	while( *fname && entry->d_reclen < (MAX_PATH_UTF8-1) )
	{
		*cp++=*fname++;
		entry->d_reclen++;
	}
	*cp=0;
}

struct dirent *readdir(DIR *dirp)
{
	_dir *dp=(_dir *)dirp;
	BOOL valid_a=FALSE;
	BOOL valid_w=FALSE;

	if(dp->dirh==INVALID_HANDLE_VALUE)
	{
		// First time through.

		// Convert to wchar_t.
		if(p_FindFirstFileW)
		{
			char *pwcBuf=sm_get_pool_memory();
			make_win32_path_UTF8_2_wchar(&pwcBuf, dp->spec);

			dp->dirh=p_FindFirstFileW((LPCWSTR)pwcBuf,
				&dp->data_w);

			sm_free_pool_memory(pwcBuf);

			if(dp->dirh==INVALID_HANDLE_VALUE)
				goto err;
			valid_w=TRUE;
		}
		else
			goto err;

		dp->offset=0;
	}
	else
	{
		// Get next file, try unicode first.
		if(p_FindNextFileW)
			valid_w=p_FindNextFileW(dp->dirh, &dp->data_w);
	}

	dp->entry.d_ino=0;
	dp->entry.d_reclen=0;
	dp->entry.d_off=dp->offset;

	if(valid_w)
	{
		// Copy unicode.
		char szBuf[MAX_PATH_UTF8+1];
		wchar_2_UTF8(szBuf, dp->data_w.cFileName);
		copyin(&dp->entry, szBuf);
	}
	else if(valid_a)
	{
		// Copy ansi.
		copyin(&dp->entry, dp->data_a.cFileName);
	}
	else
	{
		if(GetLastError()!=ERROR_NO_MORE_FILES)
			goto err;
		return NULL;
	}

	dp->offset=dp->entry.d_reclen;

	return &dp->entry;
err:
	errno=b_errno_win32;
	return NULL;
}

void init_stack_dump(void)
{
}

long pathconf(const char *path, int name)
{
	switch(name)
	{
		case _PC_PATH_MAX:
			if(!strncmp(path, "\\\\?\\", 4))
				return MAX_PATH_W;
		case _PC_NAME_MAX:
			return MAX_PATH;
	}
	return system_error();
}

int WSA_Init(void)
{
	WORD wVersionRequested=MAKEWORD(1, 1);
	WSADATA wsaData;

	if(WSAStartup(wVersionRequested, &wsaData))
	{
		printf("Can not start Windows Sockets\n");
		return system_error();
	}

	return 0;
}

static int win32_chmod_old(const char *path, mode_t mode)
{
	DWORD attr=(DWORD)-1;

	if(p_GetFileAttributesW)
	{
		char *pwszBuf=sm_get_pool_memory();
		make_win32_path_UTF8_2_wchar(&pwszBuf, path);

		attr=p_GetFileAttributesW((LPCWSTR)pwszBuf);
		if(attr!=INVALID_FILE_ATTRIBUTES)
		{
			// Use mappings defined in stat() above.
			if(!(mode & (S_IRUSR|S_IRGRP|S_IROTH)))
				attr |= FILE_ATTRIBUTE_READONLY;
			else
				attr &= ~FILE_ATTRIBUTE_READONLY;
			if(!(mode & S_IRWXO))
				attr |= FILE_ATTRIBUTE_SYSTEM;
			else
				attr &= ~FILE_ATTRIBUTE_SYSTEM;
			if(mode & S_ISVTX)
				attr |= FILE_ATTRIBUTE_HIDDEN;
			else
				attr &= ~FILE_ATTRIBUTE_HIDDEN;
			attr=p_SetFileAttributesW((LPCWSTR)pwszBuf, attr);
		}
		sm_free_pool_memory(pwszBuf);
	}

	if(attr==(DWORD)-1)
	{
		const char *err=errorString();
		LocalFree((void *)err);
		errno=b_errno_win32;
		return -1;
	}
	return 0;
}

// Define attributes that are legal to set with SetFileAttributes().
#define SET_ATTRS ( \
	FILE_ATTRIBUTE_ARCHIVE| \
	FILE_ATTRIBUTE_HIDDEN| \
	FILE_ATTRIBUTE_NORMAL| \
	FILE_ATTRIBUTE_NOT_CONTENT_INDEXED| \
	FILE_ATTRIBUTE_OFFLINE| \
	FILE_ATTRIBUTE_READONLY| \
	FILE_ATTRIBUTE_SYSTEM| \
	FILE_ATTRIBUTE_TEMPORARY)

static int win32_chmod_new(const char *path, int64_t winattr)
{
	//if(winattr & FILE_ATTRIBUTE_ENCRYPTED)
	//	printf("\n   %s was encrypted!\n", path);
	DWORD attr=(DWORD)-1;

	if(p_GetFileAttributesW)
	{
		char *pwszBuf=sm_get_pool_memory();
		make_win32_path_UTF8_2_wchar(&pwszBuf, path);

		attr=p_GetFileAttributesW((LPCWSTR) pwszBuf);
		if(attr!=INVALID_FILE_ATTRIBUTES)
			attr=p_SetFileAttributesW((LPCWSTR)pwszBuf,
				winattr & SET_ATTRS);
		sm_free_pool_memory(pwszBuf);
	}

	if(attr==(DWORD)-1)
	{
		const char *err=errorString();
		LocalFree((void *)err);
		errno=b_errno_win32;
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

int win32_chdir(const char *dir)
{
	if(p_SetCurrentDirectoryW)
	{
		char *pwszBuf=sm_get_pool_memory();
		make_win32_path_UTF8_2_wchar(&pwszBuf, dir);

		BOOL b=p_SetCurrentDirectoryW((LPCWSTR)pwszBuf);

		sm_free_pool_memory(pwszBuf);

		if(!b)
		{
			errno=b_errno_win32;
			return -1;
		}
	}
	else
		return -1;

	return 0;
}

int win32_mkdir(const char *dir)
{
	if(p_wmkdir)
	{
		char *pwszBuf=sm_get_pool_memory();
		make_win32_path_UTF8_2_wchar(&pwszBuf, dir);

		int n=p_wmkdir((LPCWSTR)pwszBuf);
		sm_free_pool_memory(pwszBuf);
		return n;
	}
	return _mkdir(dir);
}

static void backslashes_to_forward_slashes(char *path)
{
	char *cp;
	// Windows gives us backslashes, but we want forward slashes.
	for(cp=path; *cp; cp++)
		if(*cp=='\\')
			*cp='/';
}

char *win32_getcwd(char *buf, int maxlen)
{
	int n=0;

	if(p_GetCurrentDirectoryW)
	{
		char *pwszBuf=sm_get_pool_memory();
		pwszBuf=sm_check_pool_memory_size(pwszBuf,
			maxlen*sizeof(wchar_t));

		if((n=p_GetCurrentDirectoryW(maxlen, (LPWSTR)pwszBuf)))
			n=wchar_2_UTF8(buf, (wchar_t *)pwszBuf, maxlen)-1;
		sm_free_pool_memory(pwszBuf);
	}

	if(!n || n>maxlen) return NULL;

	if(n+1 > maxlen) return NULL;
	if(n!=3)
		buf[n]=0;

	backslashes_to_forward_slashes(buf);

	return buf;
}

char *win32_cgets(char* buffer, int len)
{
	/* We use console ReadConsoleA / ReadConsoleW to be able to read
	   unicode from the win32 console and fallback if seomething fails. */

	HANDLE hIn=GetStdHandle (STD_INPUT_HANDLE);
	if(hIn
	  && (hIn!=INVALID_HANDLE_VALUE))
	{
		DWORD dwRead;
		wchar_t wszBuf[1024];
		char  szBuf[1024];

		// NT and unicode conversion.
		if(ReadConsoleW(hIn, wszBuf, 1024, &dwRead, NULL))
		{
			// Null terminate at end.
			if(wszBuf[dwRead-1]==L'\n')
			{
				wszBuf[dwRead-1]=L'\0';
				dwRead--;
			}

			if(wszBuf[dwRead-1]==L'\r')
			{
				wszBuf[dwRead-1]=L'\0';
				dwRead--;
			}

			wchar_2_UTF8(buffer, wszBuf, len);
			return buffer;
		}

		// Win 9x and unicode conversion.
		if(ReadConsoleA(hIn, szBuf, 1024, &dwRead, NULL))
		{
			// Null terminate at end.
			if(szBuf[dwRead-1]==L'\n')
			{
				szBuf[dwRead-1]=L'\0';
				dwRead--;
			}

			if(szBuf[dwRead-1]==L'\r')
			{
				szBuf[dwRead-1]=L'\0';
				dwRead--;
			}

			// Convert from ansii to wchar_t.
			p_MultiByteToWideChar(GetConsoleCP(),
				0, szBuf, -1, wszBuf, 1024);
			// Convert from wchar_t to UTF-8.
			if(wchar_2_UTF8(buffer, wszBuf, len))
				return buffer;
		}
	}

	// Fallback.
	if(fgets(buffer, len, stdin)) return buffer;
	return NULL;
}

int win32_unlink(const char *filename)
{
	int nRetCode=-1;

	if(p_wunlink)
	{
		char* pwszBuf=sm_get_pool_memory();
		make_win32_path_UTF8_2_wchar(&pwszBuf, filename);

		nRetCode=_wunlink((LPCWSTR) pwszBuf);

		/* Special case if file is readonly,
		   we retry but unset attribute before. */
		if(nRetCode==-1
		  && errno==EACCES
		  && p_SetFileAttributesW
		  && p_GetFileAttributesW)
		{
			DWORD dwAttr=p_GetFileAttributesW((LPCWSTR)pwszBuf);
			if(dwAttr!=INVALID_FILE_ATTRIBUTES)
			{
				if(p_SetFileAttributesW((LPCWSTR)pwszBuf,
				  dwAttr & ~FILE_ATTRIBUTE_READONLY))
				{
					nRetCode=_wunlink((LPCWSTR) pwszBuf);
					// Reset to original if it didn't help.
					if(nRetCode==-1)
						p_SetFileAttributesW(
						  (LPCWSTR)pwszBuf, dwAttr);
				}
			}
		}
		sm_free_pool_memory(pwszBuf);
	}
	return nRetCode;
}


#include "mswinver.h"

char WIN_VERSION_LONG[64];
char WIN_VERSION[32];
char WIN_RAWVERSION[32];

class winver
{
public:
	winver(void);
};

static winver INIT; // cause constructor to be called before main()

winver::winver(void)
{
	const char *version="";
	const char *platform="";
	OSVERSIONINFO osvinfo;
	osvinfo.dwOSVersionInfoSize=sizeof(osvinfo);

	// Get the current OS version.
	if(!GetVersionEx(&osvinfo))
	{
		version = "Unknown";
		platform = "Unknown";
	}
	const int ver =_mkversion(osvinfo.dwPlatformId,
			osvinfo.dwMajorVersion,
			osvinfo.dwMinorVersion);
	snprintf(WIN_RAWVERSION, sizeof(WIN_RAWVERSION), "Windows %#08x", ver);
	switch(ver)
	{
		case MS_WINDOWS_95: (version="Windows 95"); break;
		case MS_WINDOWS_98: (version="Windows 98"); break;
		case MS_WINDOWS_ME: (version="Windows ME"); break;
		case MS_WINDOWS_NT4:(version="Windows NT 4.0");
				platform = "NT"; break;
		case MS_WINDOWS_2K: (version="Windows 2000");
				platform = "NT"; break;
		case MS_WINDOWS_XP: (version="Windows XP");
				platform = "NT"; break;
		case MS_WINDOWS_S2003: (version =  "Windows Server 2003");
				platform = "NT"; break;
		default: version = WIN_RAWVERSION; break;
	}

	snprintf(WIN_VERSION_LONG, sizeof(WIN_VERSION_LONG), "%s", version);
	snprintf(WIN_VERSION, sizeof(WIN_VERSION), "%s %lu.%lu.%lu",
			platform, osvinfo.dwMajorVersion,
			osvinfo.dwMinorVersion, osvinfo.dwBuildNumber);
}

VOID WriteToPipe(VOID);
VOID ReadFromPipe(VOID);
VOID ErrorExit(LPCSTR);
VOID ErrMsg(LPTSTR, BOOL);

static int dwAltNameLength_ok(DWORD dwAltNameLength)
{
	return dwAltNameLength>0 && dwAltNameLength<MAX_PATH_UTF8;
}

/* Extracts the executable or script name from the first string in
   cmdline.

   If the name contains blanks then it must be quoted with double quotes,
   otherwise quotes are optional.  If the name contains blanks then it
   will be converted to a short name.

   The optional quotes will be removed.  The result is copied to a malloc'ed
   buffer and returned through the pexe argument.  The pargs parameter is set
   to the address of the character in cmdline located after the name.

   The malloc'ed buffer returned in *pexe must be freed by the caller.  */
bool GetApplicationName(const char *cmdline, char **pexe, const char **pargs)
{
	// Start of executable name in cmdline.
	const char *pExeStart=NULL;
	// Character after executable name (separator).
	const char *pExeEnd=NULL;

	// Character after last path separator.
	const char *pBasename=NULL;
	// Period at start of extension.
	const char *pExtension=NULL;

	const char *current=cmdline;

	bool bQuoted=false;

	// Skip initial whitespace.
	while(*current==' ' || *current=='\t') current++;

	// Calculate start of name and determine if quoted.

	if(*current=='"')
	{
		pExeStart=++current;
		bQuoted=true;
	}
	else
	{
		pExeStart=current;
		bQuoted=false;
	}

	*pargs=NULL;
	*pexe=NULL;

	/* Scan command line looking for path separators (/ and \\) and the
	   terminator, either a quote or a blank.  The location of the
	   extension is also noted.  */
	for( ; *current!='\0'; current++)
	{
		if(*current=='.')
			pExtension=current;
		else if(IsPathSeparator(*current) && current[1]!='\0')
		{
			pBasename=&current[1];
			pExtension=NULL;
		}

		// Check for terminator, either quote or blank.
		if(bQuoted)
		{
			if(*current!='"') continue;
		}
		else
		{
			if(*current!=' ') continue;
		}

		/* Hit terminator, remember end of name (address of terminator)
		   and start of arguments. */
		pExeEnd=current;

		if(bQuoted && *current=='"')
			*pargs=&current[1];
		else
			*pargs=current;
		break;
	}

	if(!pBasename) pBasename=pExeStart;

	if(!pExeEnd) pExeEnd=current;

	if(!*pargs) *pargs=current;

	bool bHasPathSeparators=pExeStart!=pBasename;

	// We have pointers to all the useful parts of the name.

	// Default extensions in the order cmd.exe uses to search.

	static const char ExtensionList[][5]={".com", ".exe", ".bat", ".cmd"};
	DWORD dwBasePathLength=pExeEnd-pExeStart;

	DWORD dwAltNameLength=0;
	char *pPathname=(char *)alloca(MAX_PATH_UTF8+1);
	char *pAltPathname=(char *)alloca(MAX_PATH_UTF8+1);

	pPathname[MAX_PATH_UTF8]='\0';
	pAltPathname[MAX_PATH_UTF8]='\0';

	memcpy(pPathname, pExeStart, dwBasePathLength);
	pPathname[dwBasePathLength]='\0';

	if(!pExtension)
	{
		// Try appending extensions.
		for(int index=0;
		  index<(int)(sizeof(ExtensionList)/sizeof(ExtensionList[0]));
		  index++)
		{
			if(!bHasPathSeparators)
			{
				// There are no path separators, search in the
				// standard locations
				dwAltNameLength=SearchPath(NULL, pPathname,
				  ExtensionList[index], MAX_PATH_UTF8,
				  pAltPathname, NULL);
				if(dwAltNameLength_ok(dwAltNameLength))
				{
					memcpy(pPathname, pAltPathname,
						dwAltNameLength);
					pPathname[dwAltNameLength]='\0';
					break;
				}
			}
			else
			{
				snprintf(&pPathname[dwBasePathLength],
					MAX_PATH_UTF8-dwBasePathLength,
					"%s", ExtensionList[index]);
				if(GetFileAttributes(pPathname)
				  !=INVALID_FILE_ATTRIBUTES)
					break;
				pPathname[dwBasePathLength]='\0';
			}
		}
	}
	else if(!bHasPathSeparators)
	{
		// There are no path separators, search in the standard
		// locations.
		dwAltNameLength=SearchPath(NULL, pPathname,
			NULL, MAX_PATH_UTF8, pAltPathname, NULL);
		if(dwAltNameLength_ok(dwAltNameLength))
		{
			memcpy(pPathname, pAltPathname, dwAltNameLength);
			pPathname[dwAltNameLength] = '\0';
		}
	}

	if(strchr(pPathname, ' '))
	{
		dwAltNameLength=GetShortPathName(pPathname,
			pAltPathname, MAX_PATH_UTF8);

		if(dwAltNameLength_ok(dwAltNameLength))
		{
			*pexe=(char *)malloc(dwAltNameLength+1);
			if(!*pexe) return false;
			memcpy(*pexe, pAltPathname, dwAltNameLength+1);
		}
	}

	if(!*pexe)
	{
		DWORD dwPathnameLength=strlen(pPathname);
		*pexe=(char *)malloc(dwPathnameLength+1);
		if(!*pexe) return false;
		memcpy(*pexe, pPathname, dwPathnameLength+1);
	}

	return true;
}

void ErrorExit(LPCSTR lpszMessage)
{
}

// syslog function, added by Nicolas Boichat.
void openlog(const char *ident, int option, int facility)
{
}

static pid_t do_forkchild(struct fzp **sin,
	struct fzp **sout, struct fzp **serr,
	const char *path, char * const argv[], int do_wait)
{
	int a=0;
	char cmd[1024]="";
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb=sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	while(argv[a] && strlen(cmd)+strlen(argv[a])+10<sizeof(cmd))
	{
		if(a>0) strcat(cmd, " ");
		strcat(cmd, "\"");
		strcat(cmd, argv[a++]);
		strcat(cmd, "\"");
	}
	if(!CreateProcess(NULL, cmd, NULL, NULL,
		FALSE, 0, NULL, NULL, &si, &pi))
	{
		printf( "CreateProcess %s failed\n", path);
		return -1;
	}
	if(do_wait) WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	return 0;
}

pid_t forkchild(struct fzp **sin, struct fzp **sout, struct fzp **serr,
	const char *path, char * const argv[])
{
	return do_forkchild(sin, sout, serr, path, argv, 1 /* wait */);
}

pid_t forkchild_no_wait(struct fzp **sin, struct fzp **sout, struct fzp **serr,
	const char *path, char * const argv[])
{
	return do_forkchild(sin, sout, serr, path, argv, 0 /* do not wait */);
}

int win32_utime(const char *fname, struct stat *statp)
{
	FILETIME cre;
	FILETIME acc;
	FILETIME mod;

	conv_unix_to_win32_path(fname, tmpbuf, _MAX_PATH);

	// We save creation date in st_ctime.
	cvt_utime_to_ftime(statp->st_ctime, cre);
	cvt_utime_to_ftime(statp->st_atime, acc);
	cvt_utime_to_ftime(statp->st_mtime, mod);

	HANDLE h=INVALID_HANDLE_VALUE;

	if(p_CreateFileW)
	{
		char* pwszBuf=sm_get_pool_memory();
		make_win32_path_UTF8_2_wchar(&pwszBuf, tmpbuf);

		h=p_CreateFileW((LPCWSTR)pwszBuf,
				FILE_WRITE_ATTRIBUTES,
				FILE_SHARE_WRITE
				|FILE_SHARE_READ
				|FILE_SHARE_DELETE,
				NULL,
				OPEN_EXISTING,
				// required for directories
				FILE_FLAG_BACKUP_SEMANTICS,
				NULL);

		sm_free_pool_memory(pwszBuf);
	}

	if(h==INVALID_HANDLE_VALUE)
	{
		const char *err=errorString();
		fprintf(stderr, "Cannot open %s for utime(): ERR=%s\n",
			tmpbuf, err);
		LocalFree((void *)err);
		errno=b_errno_win32;
		return -1;
	}

	int rval=SetFileTime(h, &cre, &acc, &mod)?0:-1;
	CloseHandle(h);
	if(rval==-1) errno=b_errno_win32;
	return rval;
}

int win32_getfsname(const char *path, char *fsname, size_t fsname_size)
{
	// I do not think anyone still needs non-Unicode stuff.
	WCHAR fsname_ucs2[MAX_PATH + 1];
	{
		WCHAR *pwsz_path=(WCHAR*)sm_get_pool_memory();
		make_win32_path_UTF8_2_wchar((char**)&pwsz_path, path);
		int path_len=wcslen(pwsz_path);
		if (path_len && pwsz_path[path_len-1] != '\\')
		{
			pwsz_path=(WCHAR*)sm_check_pool_memory_size((char*)pwsz_path,
				sizeof(WCHAR)*path_len+sizeof(L"\\"));
			wcscpy(pwsz_path+path_len++, L"\\");
		}

		int error;
		for(;;)
		{
			error=GetVolumeInformationW(
				pwsz_path /* lpRootPathName */,
				NULL /* lpVolumeNameBuffer */,
				0 /* nVolumeNameSize */,
				NULL /* lpVolumeSerialNumber */,
				NULL /* lpMaximumComponentLength */,
				NULL /* lpFileSystemFlags */,
				fsname_ucs2 /* lpFileSystemNameBuffer */,
				MAX_PATH + 1 /* nFileSystemNameSize */
			) ? 0 : GetLastError();
			if(error!=ERROR_DIR_NOT_ROOT)
				break;

			// We are not in root, let's try upper directory.
			do --path_len; while(path_len && pwsz_path[path_len-1]!='\\');
			if (!path_len)
				break;
			// Terminate string right after earlier slash.
			pwsz_path[path_len]=0;
		}
		sm_free_pool_memory((char*)pwsz_path);

		if(error)
		{
			char used_path[MAX_PATH_UTF8 + 1];
			wchar_2_UTF8(used_path, (WCHAR*)pwsz_path, sizeof(used_path));
			fprintf(stderr, "Cannot get volume information for %s: ERR=%d\n",
				used_path, error);
			return error;
		}
	}
	wchar_2_UTF8(fsname, fsname_ucs2, fsname_size);
	return 0;
}

char *realpath(const char *path, char *resolved_path)
{
	DWORD size=0;
	char *ret=NULL;
	HANDLE h=INVALID_HANDLE_VALUE;
	char *pwszBuf=NULL;
	size_t s=strlen(path);
	int junk_len=4;

	// Passing in an existing buffer is not supported.
	ASSERT(resolved_path==NULL);

	// Have to special case the drive letter by itself, because the
	// functions that are provided to us fail on them.
	if((s==2 || s==3) // Could have a trailing slash.
	  && isalpha(path[0])
	  && path[1]==':')
		return strdup(path);

	errno=0;
	SetLastError(0);
	conv_unix_to_win32_path(path, tmpbuf, _MAX_PATH);

	pwszBuf=sm_get_pool_memory();

	if(p_CreateFileW)
	{
		make_win32_path_UTF8_2_wchar(&pwszBuf, tmpbuf);

		h=p_CreateFileW(
			(LPCWSTR)pwszBuf,
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS,
			NULL
		);
	}

	if(h==INVALID_HANDLE_VALUE)
	{
		DWORD e=GetLastError();
		switch(e)
		{
			case ERROR_NOT_ENOUGH_MEMORY:
				errno=ENOMEM;
				break;
			case ERROR_FILE_NOT_FOUND:
			case ERROR_PATH_NOT_FOUND:
				errno=ENOENT;
				break;
			case ERROR_ACCESS_DENIED:
			default:
				errno=EACCES;
				break;
		}
		goto end;
	}

	if(!(size=p_GetFinalPathNameByHandleW(h, NULL, 0, 0)))
	{
		errno=ENOENT;
		goto end;
	}

	pwszBuf=sm_check_pool_memory_size(pwszBuf, size);
	if(p_GetFinalPathNameByHandleW(h,
		(LPWSTR)pwszBuf, size, 0)<junk_len)
			goto end;
	// Get size of wanted buffer.
	size=p_WideCharToMultiByte(CP_UTF8, 0,
		(LPCWSTR)pwszBuf+junk_len, -1,
		NULL, 0, // <- 0 to get buffer size
		NULL, NULL);
	ASSERT(size>0);
	// Allocate and fill buffer.
	if(!(ret=(char *)malloc(size+1)))
		goto end;
	size=p_WideCharToMultiByte(CP_UTF8, 0,
		(LPCWSTR)pwszBuf+junk_len, -1,
		ret, size,
		NULL, NULL);
	ASSERT(size>0);

	backslashes_to_forward_slashes(ret);
end:
	if(pwszBuf) sm_free_pool_memory(pwszBuf);
	if(h!=INVALID_HANDLE_VALUE)
		CloseHandle(h);
	return ret;
}

char *get_fixed_drives(void)
{
	static char ret[256]="";
	size_t r=0;
	char *drive=NULL;
	char pwszBuf[256];

	memset(&ret, 0, sizeof(ret));

	if(!p_GetLogicalDriveStringsW(sizeof(pwszBuf), (LPWSTR)pwszBuf))
		return NULL;

	// The function above fills a buffer with widechars like this:
	// C:/<null>D:/<null><null>
	// So we have to work to extract the letters.
	drive=pwszBuf;
	while(*drive)
	{
		int l;
		char u[8];
		l=wchar_2_UTF8(u, (const wchar_t *)drive, sizeof(u));
		if(GetDriveTypeW((const wchar_t *)drive)==DRIVE_FIXED)
		{
			if(isalpha(*u))
				ret[r++]=toupper(*u);
		}
		drive+=l*2;
	}

	return ret;
}
