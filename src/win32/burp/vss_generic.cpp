/*
   Bacula® - The Network Backup Solution

   Copyright (C) 2005-2008 Free Software Foundation Europe e.V.

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
// vss.cpp -- Interface to Volume Shadow Copies (VSS)
//
// Copyright transferred from MATRIX-Computer GmbH to
//   Kern Sibbald by express permission.
//
// Author          : Thorsten Engel
// Created On      : Fri May 06 21:44:00 2005


#ifdef WIN32_VSS

#include "burp.h"
#include "berrno.h"
#include "../../log.h"

#undef setlocale

// STL includes.
#include <vector>
#include <algorithm>
#include <string>
#include <sstream>
#include <fstream>
using namespace std;

#include "ms_atl.h"
#include <objbase.h>

/* Kludges to get Vista code to compile.             
   KES - June 2007 */
#define __in  IN
#define __out OUT
#define __RPC_unique_pointer
#define __RPC_string
#define __RPC__deref_inout_opt
#define __RPC__out

#ifndef ENABLE_NLS
	#define setlocale(p, d)
#endif

#ifdef HAVE_STRSAFE_H
	// Used for safe string manipulation
	#include <strsafe.h>
#endif

BOOL VSSPathConvert(const char *szFilePath,
	char *szShadowPath, int nBuflen);
BOOL VSSPathConvertW(const wchar_t *szFilePath,
	wchar_t *szShadowPath, int nBuflen);

class IXMLDOMDocument;

// Reduce compiler warnings from Windows vss code.
#define uuid(x)

#ifdef B_VSS_XP
	#define VSSClientGeneric VSSClientXP
	#include "inc/winxp/vss.h"
	#include "inc/winxp/vswriter.h"
	#include "inc/winxp/vsbackup.h"
#endif

#ifdef B_VSS_W2K3
	#define VSSClientGeneric VSSClient2003
	#include "inc/win2003/vss.h"
	#include "inc/win2003/vswriter.h"
	#include "inc/win2003/vsbackup.h"
#endif

#ifdef B_VSS_VISTA
	#define VSSClientGeneric VSSClientVista
	#include "inc/win2003/vss.h"
	#include "inc/win2003/vswriter.h"
	#include "inc/win2003/vsbackup.h"
#endif
   
// In VSSAPI.DLL.
typedef HRESULT (STDAPICALLTYPE* t_CreateVssBackupComponents)
	(OUT IVssBackupComponents **);
typedef void (APIENTRY* t_VssFreeSnapshotProperties)
	(IN VSS_SNAPSHOT_PROP*);
   
static t_CreateVssBackupComponents p_CreateVssBackupComponents=NULL;
static t_VssFreeSnapshotProperties p_VssFreeSnapshotProperties=NULL;

#include "vss.h"

// Some helper functions.

inline wstring AppendBackslash(wstring str)
{
	if(!str.length())
		return wstring(L"\\");
	if(str[str.length() - 1]==L'\\')
		return str;
	return str.append(L"\\");
}

// Get the unique volume name for the given path.
inline wstring GetUniqueVolumeNameForPath(wstring path)
{
	if(path.length()<=0) return L"";

	// Add the backslash termination, if needed
	path=AppendBackslash(path);

	// Get the root path of the volume
	wchar_t volumeRootPath[MAX_PATH];
	wchar_t volumeName[MAX_PATH];
	wchar_t volumeUniqueName[MAX_PATH];

	if(!p_GetVolumePathNameW
	  || !p_GetVolumePathNameW((LPCWSTR)path.c_str(),
		volumeRootPath, MAX_PATH))
			return L"";

	// Get the volume name alias (might be different from the unique volume
	// name in rare cases).
	if(!p_GetVolumeNameForVolumeMountPointW
	  || !p_GetVolumeNameForVolumeMountPointW(volumeRootPath,
		volumeName, MAX_PATH))
			return L"";

	// Get the unique volume name.
	if(!p_GetVolumeNameForVolumeMountPointW(volumeName,
		volumeUniqueName, MAX_PATH))
			return L"";

	return volumeUniqueName;
}


// Helper macro for quick treatment of case statements for error codes.
#define GEN_MERGE(A, B) A##B
#define GEN_MAKE_W(A) GEN_MERGE(L, A)

#define CHECK_CASE_FOR_CONSTANT(value) case value: return (GEN_MAKE_W(#value));


// Convert a writer status into a string.
inline const wchar_t* GetStringFromWriterStatus(VSS_WRITER_STATE eWriterStatus)
{
	switch(eWriterStatus)
	{
		CHECK_CASE_FOR_CONSTANT(VSS_WS_STABLE);
		CHECK_CASE_FOR_CONSTANT(VSS_WS_WAITING_FOR_FREEZE);
		CHECK_CASE_FOR_CONSTANT(VSS_WS_WAITING_FOR_THAW);
		CHECK_CASE_FOR_CONSTANT(VSS_WS_WAITING_FOR_POST_SNAPSHOT);
		CHECK_CASE_FOR_CONSTANT(VSS_WS_WAITING_FOR_BACKUP_COMPLETE);
		CHECK_CASE_FOR_CONSTANT(VSS_WS_FAILED_AT_IDENTIFY);
		CHECK_CASE_FOR_CONSTANT(VSS_WS_FAILED_AT_PREPARE_BACKUP);
		CHECK_CASE_FOR_CONSTANT(VSS_WS_FAILED_AT_PREPARE_SNAPSHOT);
		CHECK_CASE_FOR_CONSTANT(VSS_WS_FAILED_AT_FREEZE);
		CHECK_CASE_FOR_CONSTANT(VSS_WS_FAILED_AT_THAW);
		CHECK_CASE_FOR_CONSTANT(VSS_WS_FAILED_AT_POST_SNAPSHOT);
		CHECK_CASE_FOR_CONSTANT(VSS_WS_FAILED_AT_BACKUP_COMPLETE);
		CHECK_CASE_FOR_CONSTANT(VSS_WS_FAILED_AT_PRE_RESTORE);
		CHECK_CASE_FOR_CONSTANT(VSS_WS_FAILED_AT_POST_RESTORE);

		default:
			return L"Error or Undefined";
	}
}

#ifdef HAVE_VSS64
	// 64 bit entrypoint name.
	#define VSSVBACK_ENTRY \
	  "?CreateVssBackupComponents@@YAJPEAPEAVIVssBackupComponents@@@Z"
#else
	// 32 bit entrypoint name.
	#define VSSVBACK_ENTRY \
	  "?CreateVssBackupComponents@@YGJPAPAVIVssBackupComponents@@@Z"
#endif

VSSClientGeneric::VSSClientGeneric()
{
	m_hLib=LoadLibraryA("VSSAPI.DLL");
	if(!m_hLib) return;
	p_CreateVssBackupComponents=(t_CreateVssBackupComponents)
		GetProcAddress(m_hLib, VSSVBACK_ENTRY);
	p_VssFreeSnapshotProperties=(t_VssFreeSnapshotProperties)
		GetProcAddress(m_hLib, "VssFreeSnapshotProperties");      
}

VSSClientGeneric::~VSSClientGeneric()
{
	if(m_hLib) FreeLibrary(m_hLib);
}

static BOOL bsystem_error(void)
{
	errno=ENOSYS;
	return FALSE;
}

static BOOL set_errno(void)
{
	errno=b_errno_win32;
	return FALSE;
}

// Initialize the COM infrastructure and the internal pointers.
BOOL VSSClientGeneric::Initialize(struct asfd *asfd, struct cntr *cntr)
{
	if(!(p_CreateVssBackupComponents && p_VssFreeSnapshotProperties))
	{
		logw(asfd, cntr, "%s error\n", __func__);
		return bsystem_error();
	}

	HRESULT hr;
	// Initialize COM.
	if(!m_bCoInitializeCalled)
	{
		hr=CoInitialize(NULL);
		if(FAILED(hr))
		{
			logw(asfd, cntr, "%s: CoInitialize returned 0x%08X\n",
				__func__, (unsigned int)hr);
			return set_errno();
		}
		m_bCoInitializeCalled=true;
	}

	// Initialize COM security.
	if(!m_bCoInitializeSecurityCalled)
	{
		hr=CoInitializeSecurity(
			NULL, // Allow *all* VSS writers to communicate back!
			-1,   // Default COM authentication service.
			NULL, // Default COM authorization service.
			NULL, // Reserved parameter.
			// Strongest COM authentication level.
			RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
			// Minimal impersonation abilities.
			RPC_C_IMP_LEVEL_IDENTIFY,
			NULL, // Default COM authentication settings.
			EOAC_NONE, //  No special options.
			NULL  //  Reserved parameter.
			);

		if(FAILED(hr))
		{
			logw(asfd, cntr,
			  "%s: CoInitializeSecurity returned 0x%08X\n",
			  __func__, (unsigned int)hr);
			return set_errno();
		}
		m_bCoInitializeSecurityCalled=true;
	}

	// Release the IVssBackupComponents interface.
	if(m_pVssObject)
	{
		m_pVssObject->Release();
		m_pVssObject=NULL;
	}

	// Create the internal backup components object.
	hr=p_CreateVssBackupComponents((IVssBackupComponents**)&m_pVssObject);
	if(FAILED(hr))
	{
		berrno be;
		berrno_init(&be);
		logw(asfd, cntr,
		  "%s: CreateVssBackupComponents returned 0x%08X. ERR=%s\n",
			__func__, (unsigned int)hr,
			berrno_bstrerror(&be, b_errno_win32));
		return set_errno();
	}

	// 1. InitializeForBackup.
	hr=((IVssBackupComponents*)m_pVssObject)->InitializeForBackup();
	if(FAILED(hr))
	{
		logw(asfd, cntr, "%s: IVssBackupComponents->InitializeForBackup returned 0x%08X\n", __func__, (unsigned int)hr);
		return set_errno();
	}

	// 2. SetBackupState.
	hr=((IVssBackupComponents*)m_pVssObject)->SetBackupState(true,
		true, VSS_BT_FULL, false);
	if(FAILED(hr))
	{
		logw(asfd, cntr, "%s: IVssBackupComponents->SetBackupState returned 0x%08X\n", __func__, (unsigned int)hr);
		return set_errno();
	}

	CComPtr<IVssAsync> pAsync1;
	// 3. GatherWriterMetaData.
	hr=((IVssBackupComponents*)
		m_pVssObject)->GatherWriterMetadata(&pAsync1.p);
	if(FAILED(hr))
	{
		logw(asfd, cntr, "%s: IVssBackupComponents->GatherWriterMetadata returned 0x%08X\n", __func__, (unsigned int)hr);
		return set_errno();
	}
	WaitAndCheckForAsyncOperation(pAsync1.p);

	return TRUE;
}

BOOL VSSClientGeneric::WaitAndCheckForAsyncOperation(IVssAsync* pAsync)
{
	// Wait until the async operation finishes
	// unfortunately we can't use a timeout here yet.
	// the interface would allow it on W2k3,
	// but it is not implemented yet.

	HRESULT hr;

	// Check the result of the asynchronous operation.	
	HRESULT hrReturned=S_OK;

	int timeout=600; // 10 minutes.

	int queryErrors=0;
	do
	{
		if(hrReturned!=S_OK) Sleep(1000);

		hrReturned=S_OK;
		hr=pAsync->QueryStatus(&hrReturned, NULL);

		if(FAILED(hr)) queryErrors++;
	}
	while ((timeout-->0) && (hrReturned==VSS_S_ASYNC_PENDING));

	if(hrReturned==VSS_S_ASYNC_FINISHED) return TRUE;

#ifdef xDEBUG 
	// Check if the async operation succeeded.
	if(hrReturned!=VSS_S_ASYNC_FINISHED)
	{
		wchar_t *pwszBuffer=NULL;
		// I don't see the usefulness of the following -- KES.
		FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER 
				| FORMAT_MESSAGE_FROM_SYSTEM 
				| FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL, hrReturned, 
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
				(LPWSTR)&pwszBuffer, 0, NULL);

		LocalFree(pwszBuffer);         
		errno=b_errno_win32;
	}
#endif
	return FALSE;
}

BOOL VSSClientGeneric::CreateSnapshots(char* szDriveLetters)
{
	// szDriveLetters contains all drive letters in uppercase.
	// If a drive can not being added, it's converted to lowercase in
	// szDriveLetters.
	// http://msdn.microsoft.com/library/default.asp?url=/library/en-us/vss/base/ivssbackupcomponents_startsnapshotset.asp

	if(!m_pVssObject || m_bBackupIsInitialized) return bsystem_error();

	m_uidCurrentSnapshotSet=GUID_NULL;

	IVssBackupComponents *pVss=(IVssBackupComponents*)m_pVssObject;

	pVss->StartSnapshotSet(&m_uidCurrentSnapshotSet);

	wchar_t szDrive[3];
	szDrive[1]=':';
	szDrive[2]=0;

	wstring volume;

	CComPtr<IVssAsync> pAsync1;
	CComPtr<IVssAsync> pAsync2;   
	VSS_ID pid;

	for(size_t i=0; i<strlen (szDriveLetters); i++)
	{
		szDrive[0]=szDriveLetters[i];
		volume=GetUniqueVolumeNameForPath(szDrive);
		// Store uniquevolumname.
		if(SUCCEEDED(pVss->AddToSnapshotSet((LPWSTR)volume.c_str(),
		  GUID_NULL, &pid)))
			wcsncpy(m_wszUniqueVolumeName[szDriveLetters[i]-'A'],
				(LPWSTR) volume.c_str(), MAX_PATH);
		else
			szDriveLetters[i]=tolower(szDriveLetters[i]);
	}

	if(FAILED(pVss->PrepareForBackup(&pAsync1.p))) return set_errno();

	WaitAndCheckForAsyncOperation(pAsync1.p);

	if(!CheckWriterStatus()) return set_errno();

	if(FAILED(pVss->DoSnapshotSet(&pAsync2.p))) return set_errno();

	WaitAndCheckForAsyncOperation(pAsync2.p); 

	QuerySnapshotSet(m_uidCurrentSnapshotSet);

	SetVSSPathConvert(VSSPathConvert, VSSPathConvertW);

	m_bBackupIsInitialized=true;

	return TRUE;
}

BOOL VSSClientGeneric::CloseBackup()
{
	BOOL bRet=FALSE;
	if(!m_pVssObject) errno=ENOSYS;
	else
	{
		IVssBackupComponents *pVss=(IVssBackupComponents*)m_pVssObject;
		CComPtr<IVssAsync> pAsync;

		SetVSSPathConvert(NULL, NULL);

		m_bBackupIsInitialized=false;

		if(SUCCEEDED(pVss->BackupComplete(&pAsync.p)))
		{
			WaitAndCheckForAsyncOperation(pAsync.p);
			bRet=TRUE;     
		}
		else
		{
			errno=b_errno_win32;
			pVss->AbortBackup();
		}

		// Get latest info about writer status.
		CheckWriterStatus();

		if(m_uidCurrentSnapshotSet!=GUID_NULL)
		{
			VSS_ID idNonDeletedSnapshotID=GUID_NULL;
			LONG lSnapshots;

			pVss->DeleteSnapshots(m_uidCurrentSnapshotSet, 
					VSS_OBJECT_SNAPSHOT_SET,
					FALSE,
					&lSnapshots,
					&idNonDeletedSnapshotID);

			m_uidCurrentSnapshotSet=GUID_NULL;
		}

		pVss->Release();
		m_pVssObject=NULL;
	}

	// Call CoUninitialize if the CoInitialize was performed sucesfully.
	if(m_bCoInitializeCalled)
	{
		CoUninitialize();
		m_bCoInitializeCalled=false;
	}

	return bRet;
}

// Query all the shadow copies in the given set.
BOOL VSSClientGeneric::QuerySnapshotSet(GUID snapshotSetID)
{
	if(!(p_CreateVssBackupComponents && p_VssFreeSnapshotProperties))
		return bsystem_error();

	memset(m_szShadowCopyName,0,sizeof(m_szShadowCopyName));

	if(snapshotSetID==GUID_NULL || m_pVssObject==NULL)
		return bsystem_error();

	IVssBackupComponents *pVss=(IVssBackupComponents*)m_pVssObject;

	// Get list all shadow copies. 
	CComPtr<IVssEnumObject> pIEnumSnapshots;
	HRESULT hr=pVss->Query( GUID_NULL, 
			VSS_OBJECT_NONE, 
			VSS_OBJECT_SNAPSHOT, 
			(IVssEnumObject**)(&pIEnumSnapshots));

	// If there are no shadow copies, just return.
	if(FAILED(hr)) return set_errno();

	// Enumerate all shadow copies. 
	VSS_OBJECT_PROP Prop;
	VSS_SNAPSHOT_PROP& Snap=Prop.Obj.Snap;

	while(1)
	{
		// Get the next element.
		ULONG ulFetched;
		hr=(pIEnumSnapshots.p)->Next(1, &Prop, &ulFetched);

		// We reached the end of list.
		if(!ulFetched) break;

		// Print the shadow copy (if not filtered out).
		if(Snap.m_SnapshotSetId == snapshotSetID)
		{
			for(int ch='A'-'A';ch<='Z'-'A';ch++)
			{
				if(!wcscmp(Snap.m_pwszOriginalVolumeName,
				  m_wszUniqueVolumeName[ch]))
				{
					wcsncpy(m_szShadowCopyName[ch],
					  Snap.m_pwszSnapshotDeviceObject,
					  MAX_PATH-1);
					break;
				}
			}
		}
		p_VssFreeSnapshotProperties(&Snap);
	}
	errno=0;
	return TRUE;
}

// Check the status for all selected writers.
BOOL VSSClientGeneric::CheckWriterStatus()
{
	// http://msdn.microsoft.com/library/default.asp?url=/library/en-us/vss/base/ivssbackupcomponents_startsnapshotset.asp
	IVssBackupComponents *pVss=(IVssBackupComponents*)m_pVssObject;
	DestroyWriterInfo();

	// Gather writer status to detect potential errors
	CComPtr<IVssAsync> pAsync;

	HRESULT hr=pVss->GatherWriterStatus(&pAsync.p);
	if(FAILED(hr)) return set_errno();

	WaitAndCheckForAsyncOperation(pAsync.p);

	unsigned cWriters=0;

	hr=pVss->GetWriterStatusCount(&cWriters);
	if(FAILED(hr)) return set_errno();

	int nState;

	// Enumerate each writer.
	for(unsigned iWriter=0; iWriter<cWriters; iWriter++)
	{
		VSS_ID idInstance=GUID_NULL;
		VSS_ID idWriter= GUID_NULL;
		VSS_WRITER_STATE eWriterStatus=VSS_WS_UNKNOWN;
		CComBSTR bstrWriterName;
		HRESULT hrWriterFailure=S_OK;

		// Get writer status
		hr=pVss->GetWriterStatus(iWriter,
				&idInstance,
				&idWriter,
				&bstrWriterName,
				&eWriterStatus,
				&hrWriterFailure);
		if(FAILED(hr)) nState=0; // Unknown.
		else
		{
			switch(eWriterStatus)
			{
				case VSS_WS_FAILED_AT_IDENTIFY:
				case VSS_WS_FAILED_AT_PREPARE_BACKUP:
				case VSS_WS_FAILED_AT_PREPARE_SNAPSHOT:
				case VSS_WS_FAILED_AT_FREEZE:
				case VSS_WS_FAILED_AT_THAW:
				case VSS_WS_FAILED_AT_POST_SNAPSHOT:
				case VSS_WS_FAILED_AT_BACKUP_COMPLETE:
				case VSS_WS_FAILED_AT_PRE_RESTORE:
				case VSS_WS_FAILED_AT_POST_RESTORE:
#if defined(B_VSS_W2K3) || defined(B_VSS_VISTA)
				case VSS_WS_FAILED_AT_BACKUPSHUTDOWN:
#endif
					// Failed.
					nState=-1;
					break;

				default:
					// OK.
					nState=1;
			}
		}
		// Store text info.
		char str[1000];
		char szBuf1[200];
		char szBuf2[200];
		char szBuf3[200];
		wchar_2_UTF8(szBuf1, bstrWriterName.p, sizeof(szBuf1));
		itoa(eWriterStatus, szBuf2, sizeof(szBuf2));
		wchar_2_UTF8(szBuf3, GetStringFromWriterStatus(eWriterStatus),
			sizeof(szBuf3));
		snprintf(str, sizeof(str), "\"%s\", State: 0x%s (%s)",
			szBuf1, szBuf2, szBuf3);

		AppendWriterInfo(nState, (const char *)str);     
	}

	hr=pVss->FreeWriterStatus();

	if(FAILED(hr)) return set_errno();

	errno=0;
	return TRUE;
}

#endif
