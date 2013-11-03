#ifdef WIN32_VSS
#include "burp.h"
#include "compat.h"

#include "ms_atl.h"
#include <objbase.h>

#include "vss.h"
#include "alist.h"

VSSClient *g_pVSSClient;

// {b5946137-7b9f-4925-af80-51abd60b20d5}

static const GUID VSS_SWPRV_ProviderID = {
	0xb5946137, 0x7b9f, 0x4925, {
		0xaf, 0x80, 0x51, 0xab, 0xd6, 0x0b, 0x20, 0xd5
	}
};


void VSSCleanup()
{
	if(g_pVSSClient) delete (g_pVSSClient);
}

void VSSInit()
{
	// Decide which vss class to initialize.
	if(g_MajorVersion==5)
	{
		switch(g_MinorVersion)
		{
			case 1: 
				g_pVSSClient=new VSSClientXP();
				atexit(VSSCleanup);
				return;
			case 2: 
				g_pVSSClient=new VSSClient2003();
				atexit(VSSCleanup);
				return;
		}
		// Vista or Longhorn or later.
		//       } else if(g_MajorVersion==6 && g_MinorVersion==0) {
	}
	else if(g_MajorVersion> 6)
	{
		g_pVSSClient=new VSSClientVista();
		atexit(VSSCleanup);
		return;
	}
}

BOOL VSSPathConvert(const char *szFilePath,
	char *szShadowPath, int nBuflen)
{
	return g_pVSSClient->GetShadowPath(szFilePath, szShadowPath, nBuflen);
}

BOOL VSSPathConvertW(const wchar_t *szFilePath,
	wchar_t *szShadowPath, int nBuflen)
{ 
	return g_pVSSClient->GetShadowPathW(szFilePath, szShadowPath, nBuflen);
}

VSSClient::VSSClient()
{
	m_bCoInitializeCalled=false;
	m_bCoInitializeSecurityCalled=false;
	m_dwContext=0; // VSS_CTX_BACKUP;
	m_bDuringRestore=false;
	m_bBackupIsInitialized=false;
	m_pVssObject=NULL;
	m_pAlistWriterState=New(alist(10, not_owned_by_alist));
	m_pAlistWriterInfoText=New(alist(10, owned_by_alist));
	m_uidCurrentSnapshotSet=GUID_NULL;
	memset(m_wszUniqueVolumeName, 0, sizeof(m_wszUniqueVolumeName));
	memset(m_szShadowCopyName, 0, sizeof(m_szShadowCopyName));
}

VSSClient::~VSSClient()
{
	// Release the IVssBackupComponents interface 
	// WARNING: this must be done BEFORE calling CoUninitialize()
	if(m_pVssObject)
	{
		m_pVssObject->Release();
		m_pVssObject=NULL;
	}

	DestroyWriterInfo();
	delete (alist*)m_pAlistWriterState;
	delete (alist*)m_pAlistWriterInfoText;

	// Call CoUninitialize if the CoInitialize was performed successfully
	if(m_bCoInitializeCalled) CoUninitialize();
}

BOOL VSSClient::InitializeForBackup()
{
	//return Initialize (VSS_CTX_BACKUP);
	return Initialize(0);
}

static char *bstrncat(char *dest, const char *src, int maxlen)
{
	strncat(dest, src, maxlen-1);
	dest[maxlen-1]=0;
	return dest;
}

BOOL VSSClient::GetShadowPath(const char *szFilePath,
	char *szShadowPath, int nBuflen)
{
	if(!m_bBackupIsInitialized) return FALSE;

	// check for valid pathname.
	BOOL bIsValidName;

	bIsValidName=strlen(szFilePath)>3;
	if(bIsValidName)
		bIsValidName &= isalpha(szFilePath[0]) &&
			szFilePath[1]==':' && 
			szFilePath[2]=='\\';

	if(bIsValidName)
	{
		int nDriveIndex=toupper(szFilePath[0])-'A';
		if(m_szShadowCopyName[nDriveIndex][0])
		{

			if(WideCharToMultiByte(CP_UTF8, 0,
			  m_szShadowCopyName[nDriveIndex], -1, szShadowPath,
			  nBuflen-1, NULL, NULL))
			{
				nBuflen-=(int)strlen(szShadowPath);
				bstrncat(szShadowPath, szFilePath+2, nBuflen);
				return TRUE;
			}
		}
	}

	snprintf(szShadowPath, nBuflen, "%s", szFilePath);
	errno=EINVAL;
	return FALSE;   
}

BOOL VSSClient::GetShadowPathW(const wchar_t *szFilePath,
	wchar_t *szShadowPath, int nBuflen)
{
	if(!m_bBackupIsInitialized) return FALSE;

	// check for valid pathname.
	BOOL bIsValidName;

	bIsValidName=wcslen(szFilePath)>3;
	if(bIsValidName)
		bIsValidName &= iswalpha(szFilePath[0]) &&
			szFilePath[1]==':' && 
			szFilePath[2] == '\\';

	if(bIsValidName)
	{
		int nDriveIndex=towupper(szFilePath[0])-'A';
		if(m_szShadowCopyName[nDriveIndex][0])
		{
			wcsncpy(szShadowPath,
				m_szShadowCopyName[nDriveIndex], nBuflen);
			nBuflen-=(int)wcslen(m_szShadowCopyName[nDriveIndex]);
			wcsncat(szShadowPath, szFilePath+2, nBuflen);
			return TRUE;
		}
	}

	wcsncpy(szShadowPath, szFilePath, nBuflen);
	errno=EINVAL;
	return FALSE;   
}


const size_t VSSClient::GetWriterCount()
{
	alist* pV=(alist*)m_pAlistWriterInfoText;
	return pV->size();
}

const char* VSSClient::GetWriterInfo(int nIndex)
{
	alist* pV=(alist*)m_pAlistWriterInfoText;
	return (char*)pV->get(nIndex);
}


const int VSSClient::GetWriterState(int nIndex)
{
	alist* pV=(alist*)m_pAlistWriterState;   
	return (intptr_t)pV->get(nIndex);
}

void VSSClient::AppendWriterInfo(int nState, const char* pszInfo)
{
	alist* pT=(alist*) m_pAlistWriterInfoText;
	alist* pS=(alist*) m_pAlistWriterState;

	pT->push(strdup(pszInfo));
	pS->push((void*)nState);   
}

void VSSClient::DestroyWriterInfo()
{
	alist* pT=(alist*)m_pAlistWriterInfoText;
	alist* pS=(alist*)m_pAlistWriterState;

	while(!pT->empty()) free(pT->pop());

	while(!pS->empty()) pS->pop();      
}

#endif
