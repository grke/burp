/*
   Bacula® - The Network Backup Solution

   Copyright (C) 2003-2008 Free Software Foundation Europe e.V.

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
/*
 * Windows APIs that are different for each system.
 *   We use pointers to the entry points so that a
 *   single binary will run on all Windows systems.
 *
 *     Kern Sibbald MMIII
 */

#ifndef __WINAPI_H
#define __WINAPI_H

#if defined(HAVE_WIN32)
#include <windef.h>

// unicode enabling of win 32 needs some defines and functions

// MAX_PATH_UTF8 moved to burpconfig.h
// winapi.h used only in burp.h just after using burpconfig.h
#include "burpconfig.h"

int wchar_2_UTF8(char *pszUTF, const WCHAR *pszUCS, int cchChar = MAX_PATH_UTF8);
char *make_win32_path_UTF8_2_wchar_w(const char *pszUTF);

// init with win9x, but maybe set to NT in InitWinAPI
extern DWORD DLL_IMP_EXP g_platform_id;
extern DWORD DLL_IMP_EXP g_MinorVersion;
extern DWORD DLL_IMP_EXP g_MajorVersion;

/* In ADVAPI32.DLL */
typedef BOOL (WINAPI * t_OpenProcessToken)(HANDLE, DWORD, PHANDLE);
typedef BOOL (WINAPI * t_AdjustTokenPrivileges)(HANDLE, BOOL,
          PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
typedef BOOL (WINAPI * t_LookupPrivilegeValue)(LPCTSTR, LPCTSTR, PLUID);

extern t_OpenProcessToken      DLL_IMP_EXP p_OpenProcessToken;
extern t_AdjustTokenPrivileges DLL_IMP_EXP p_AdjustTokenPrivileges;
extern t_LookupPrivilegeValue  DLL_IMP_EXP p_LookupPrivilegeValue;

/* In MSVCRT.DLL */
typedef int (__cdecl * t_wunlink) (const wchar_t *);
typedef int (__cdecl * t_wmkdir) (const wchar_t *);
typedef int (__cdecl * t_wopen)  (const wchar_t *, int, ...);

extern t_wunlink   DLL_IMP_EXP p_wunlink;
extern t_wmkdir    DLL_IMP_EXP p_wmkdir;

/* In KERNEL32.DLL */
typedef BOOL (WINAPI * t_GetFileAttributesExW)(LPCWSTR, GET_FILEEX_INFO_LEVELS,
       LPVOID);

typedef DWORD (WINAPI * t_GetFileAttributesW)(LPCWSTR);
typedef BOOL (WINAPI * t_SetFileAttributesW)(LPCWSTR, DWORD);

/* Graham says: PFE_EXPORT_FUNC/PFE_IMPORT_FUNC are defined in mingw64 but no
   mingw32. Put them here and see if it works. */
typedef DWORD (WINAPI *PFE_EXPORT_FUNC)(PBYTE pbData,PVOID pvCallbackContext,ULONG ulLength);
typedef DWORD (WINAPI *PFE_IMPORT_FUNC)(PBYTE pbData,PVOID pvCallbackContext,PULONG ulLength);

typedef DWORD (WINAPI * t_OpenEncryptedFileRawW)(LPCWSTR, ULONG, PVOID);

typedef HANDLE (WINAPI * t_CreateFileW) (LPCWSTR, DWORD ,DWORD, LPSECURITY_ATTRIBUTES,
        DWORD , DWORD, HANDLE);

typedef BOOL (WINAPI * t_CreateDirectoryW) (LPCWSTR, LPSECURITY_ATTRIBUTES);

typedef BOOL (WINAPI * t_GetFinalPathNameByHandleW) (HANDLE, LPWSTR, DWORD, DWORD);
typedef UINT (WINAPI * t_GetLogicalDriveStringsW) (UINT, LPWSTR);
typedef UINT (WINAPI * t_GetDriveTypeW) (LPCWSTR);

typedef BOOL (WINAPI * t_SetProcessShutdownParameters)(DWORD, DWORD);
typedef BOOL (WINAPI * t_BackupRead)(HANDLE,LPBYTE,DWORD,LPDWORD,BOOL,BOOL,LPVOID*);
typedef BOOL (WINAPI * t_BackupWrite)(HANDLE,LPBYTE,DWORD,LPDWORD,BOOL,BOOL,LPVOID*);

typedef int (WINAPI * t_WideCharToMultiByte) (UINT CodePage, DWORD , LPCWSTR, int,
                                              LPSTR, int, LPCSTR, LPBOOL);

typedef int (WINAPI * t_MultiByteToWideChar) (UINT, DWORD, LPCSTR, int, LPWSTR, int);
typedef HANDLE (WINAPI * t_FindFirstFileW) (LPCWSTR, LPWIN32_FIND_DATAW);

typedef BOOL (WINAPI * t_FindNextFileW) (HANDLE, LPWIN32_FIND_DATAW);

typedef BOOL (WINAPI * t_SetCurrentDirectoryW) (LPCWSTR);

typedef DWORD (WINAPI * t_GetCurrentDirectoryW) (DWORD, LPWSTR);

typedef BOOL (WINAPI * t_GetVolumePathNameW) (LPCWSTR, LPWSTR, DWORD);
typedef BOOL (WINAPI * t_GetVolumeNameForVolumeMountPointW) (LPCWSTR, LPWSTR, DWORD);

typedef BOOL (WINAPI * t_AttachConsole) (DWORD);

typedef BOOL (WINAPI *t_CreateProcessW) (
   LPCWSTR,
   LPWSTR,
   LPSECURITY_ATTRIBUTES,
   LPSECURITY_ATTRIBUTES,
   BOOL,
   DWORD,
   PVOID,
   LPCWSTR,
   LPSTARTUPINFOW,
   LPPROCESS_INFORMATION);

extern t_CreateProcessW DLL_IMP_EXP p_CreateProcessW;

extern t_OpenEncryptedFileRawW  DLL_IMP_EXP p_OpenEncryptedFileRawW;

extern t_GetFileAttributesW   DLL_IMP_EXP p_GetFileAttributesW;

extern t_GetFileAttributesExW   DLL_IMP_EXP p_GetFileAttributesExW;

extern t_SetFileAttributesW   DLL_IMP_EXP p_SetFileAttributesW;

extern t_CreateFileW   DLL_IMP_EXP p_CreateFileW;

extern t_CreateDirectoryW   DLL_IMP_EXP p_CreateDirectoryW;

extern t_GetFinalPathNameByHandleW   DLL_IMP_EXP p_GetFinalPathNameByHandleW;

extern t_GetLogicalDriveStringsW   DLL_IMP_EXP p_GetLogicalDriveStringsW;

extern t_GetDriveTypeW   DLL_IMP_EXP p_GetDriveTypeW;

extern t_SetProcessShutdownParameters DLL_IMP_EXP p_SetProcessShutdownParameters;
extern t_BackupRead         DLL_IMP_EXP p_BackupRead;
extern t_BackupWrite        DLL_IMP_EXP p_BackupWrite;

extern t_WideCharToMultiByte DLL_IMP_EXP p_WideCharToMultiByte;
extern t_MultiByteToWideChar DLL_IMP_EXP p_MultiByteToWideChar;

extern t_FindFirstFileW DLL_IMP_EXP p_FindFirstFileW;

extern t_FindNextFileW DLL_IMP_EXP p_FindNextFileW;

extern t_SetCurrentDirectoryW DLL_IMP_EXP p_SetCurrentDirectoryW;

extern t_GetCurrentDirectoryW DLL_IMP_EXP p_GetCurrentDirectoryW;

extern t_GetVolumePathNameW DLL_IMP_EXP p_GetVolumePathNameW;
extern t_GetVolumeNameForVolumeMountPointW DLL_IMP_EXP p_GetVolumeNameForVolumeMountPointW;

extern t_AttachConsole DLL_IMP_EXP p_AttachConsole;

void InitWinAPIWrapper();

/* In SHFolder.dll on older systems, and now Shell32.dll */
typedef BOOL (WINAPI * t_SHGetFolderPath)(HWND, int, HANDLE, DWORD, LPTSTR);
extern t_SHGetFolderPath  DLL_IMP_EXP p_SHGetFolderPath;

#endif

#endif /* __WINAPI_H */
