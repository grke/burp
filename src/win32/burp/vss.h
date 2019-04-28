/*
   Bacula® - The Network Backup Solution

   Copyright (C) 2006-2007 Free Software Foundation Europe e.V.

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
/*                               -*- Mode: C -*-
 * vss.h --
 */
//
// Copyright transferred from MATRIX-Computer GmbH to
//   Kern Sibbald by express permission.
/*
 *
 * Author          : Thorsten Engel
 * Created On      : Fri May 06 21:44:00 2006
 */


#ifndef __VSS_H_
#define __VSS_H_

#include "../../asfd.h"
#include "../../cntr.h"

// Some forward declarations.
struct IVssAsync;

class VSSClient
{
public:
	VSSClient();
	virtual ~VSSClient();

	// Backup Process
	BOOL InitializeForBackup(struct asfd *asfd, struct cntr *cntr);
	virtual BOOL CreateSnapshots(char *szDriveLetters)=0;
	virtual BOOL CloseBackup()=0;
	virtual const char* GetDriverName()=0;
	BOOL GetShadowPath(const char *szFilePath, char *szShadowPath,
		int nBuflen);
	BOOL GetShadowPathW(const wchar_t *szFilePath, wchar_t *szShadowPath,
		int nBuflen); // nBuflen in characters.

	const size_t GetWriterCount();
	const char *GetWriterInfo(int nIndex);
	const int GetWriterState(int nIndex);
	void DestroyWriterInfo();
	void AppendWriterInfo(int nState, const char* pszInfo);
	const BOOL IsInitialized() { return m_bBackupIsInitialized; };

private:
	virtual BOOL Initialize(
		struct asfd *asfd,
		struct cntr *cntr
	)=0;
	virtual BOOL WaitAndCheckForAsyncOperation(IVssAsync *pAsync)=0;
	virtual BOOL QuerySnapshotSet(GUID snapshotSetID)=0;

protected:
	HMODULE m_hLib;

	BOOL m_bCoInitializeCalled;
	BOOL m_bCoInitializeSecurityCalled;

	IUnknown *m_pVssObject;
	GUID m_uidCurrentSnapshotSet;
	BOOL m_bBackupIsInitialized;

	// drive A will be stored on position 0,Z on pos. 25
	wchar_t m_wszUniqueVolumeName[26][MAX_PATH]; // approx. 7 KB
	wchar_t m_szShadowCopyName[26][MAX_PATH]; // approx. 7 KB

	void *m_pAlistWriterState;
	void *m_pAlistWriterInfoText;
};

class VSSClientXP:public VSSClient
{
public:
	VSSClientXP();
	virtual ~VSSClientXP();
	virtual BOOL CreateSnapshots(char *szDriveLetters);
	virtual BOOL CloseBackup();
	virtual const char *GetDriverName() { return "VSS WinXP"; };
private:
	virtual BOOL Initialize(
		struct asfd *asfd,
		struct cntr *cntr
	);
	virtual BOOL WaitAndCheckForAsyncOperation(IVssAsync *pAsync);
	virtual BOOL QuerySnapshotSet(GUID snapshotSetID);
	BOOL CheckWriterStatus();   
};

class VSSClient2003:public VSSClient
{
public:
	VSSClient2003();
	virtual ~VSSClient2003();
	virtual BOOL CreateSnapshots(char *szDriveLetters);
	virtual BOOL CloseBackup();   
	virtual const char *GetDriverName() { return "VSS Win 2003"; };
private:
	virtual BOOL Initialize(
		struct asfd *asfd,
		struct cntr *cntr
	);
	virtual BOOL WaitAndCheckForAsyncOperation(IVssAsync *pAsync);
	virtual BOOL QuerySnapshotSet(GUID snapshotSetID);
	BOOL CheckWriterStatus();
};

class VSSClientVista:public VSSClient
{
public:
	VSSClientVista();
	virtual ~VSSClientVista();
	virtual BOOL CreateSnapshots(char *szDriveLetters);
	virtual BOOL CloseBackup();   
	virtual const char *GetDriverName() { return "VSS Vista"; };
private:
	virtual BOOL Initialize(
		struct asfd *asfd,
		struct cntr *cntr
	);
	virtual BOOL WaitAndCheckForAsyncOperation(IVssAsync *pAsync);
	virtual BOOL QuerySnapshotSet(GUID snapshotSetID);
	BOOL CheckWriterStatus();
};

extern VSSClient *g_pVSSClient;

extern int VSSInit(void);

#endif
