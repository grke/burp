#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "rs_buf.h"
#include "handy.h"
#include "asyncio.h"
#include "counter.h"
#include "berrno.h"
#include "client_vss.h"
#include "extrameta.h"

#if defined(WIN32_VSS)
#include "vss.h"

int win32_start_vss(struct config *conf)
{
	int errors=0;
	//char buf[256]="";

	if(g_pVSSClient->InitializeForBackup())
	{
		int i=0;
		int j=0;
		/* tell vss which drives to snapshot */
		char szWinDriveLetters[27];
		for(i=0, j=0; i < conf->sdcount && j<26; i++)
		{
			const char *path=NULL;
			if(!conf->startdir[i]->flag) continue;
			path=conf->startdir[i]->path;
			if(strlen(path)>2 && isalpha(path[0]) && path[1]==':')
			{
				int x=0;
				// Try not to add the same letter twice.
				for(x=0; x<j; x++)
				  if(toupper(path[0])==szWinDriveLetters[x])
					break;
				if(x<j) continue;
				szWinDriveLetters[j++]=toupper(path[0]);
			}
		}
		szWinDriveLetters[j]='\0';
		printf("Generate VSS snapshots.\n");
		printf("Driver=\"%s\", Drive(s)=\"%s\"\n",
			g_pVSSClient->GetDriverName(),
			szWinDriveLetters);
		if(!g_pVSSClient->CreateSnapshots(szWinDriveLetters))
		{
			logp("Generate VSS snapshots failed.\n");
			errors++;
		}
		else
		{
			int i;
			for(i=0; i<(int)strlen(szWinDriveLetters); i++)
			{
			  logp("VSS drive letters: %d\n", i);
			  if(islower(szWinDriveLetters[i]))
			  {
				logp(_("Generate VSS snapshot of drive \"%c:\\\" failed. VSS support is disabled on this drive.\n"), szWinDriveLetters[i]);
				errors++;
			  }
			}

			for(i=0; i<(int)g_pVSSClient->GetWriterCount(); i++)
			{
			  logp("VSS writer count: %d\n", i);
			  if(g_pVSSClient->GetWriterState(i)<1)
			  {
				logp("VSS Writer (PrepareForBackup): %s\n", g_pVSSClient->GetWriterInfo(i));
				errors++;
			  }
			}
		}
	}
	else
	{
		berrno be;
		logp("VSS was not initialized properly.\n");
		logp("VSS support is disabled. ERR=%s\n",
			be.bstrerror(b_errno_win32));
		errors++;
	}

	return errors;
}

int win32_stop_vss(void)
{
	int errors=0;

	if(g_pVSSClient->CloseBackup())
	{
		int i=0;
		for(i=0; i<(int)g_pVSSClient->GetWriterCount(); i++)
		{
			if(g_pVSSClient->GetWriterState(i)<1)
				errors++;
			logp("VSS Writer (BackupComplete): %s\n",
				g_pVSSClient->GetWriterInfo(i));
		}
	}
	Win32ConvCleanupCache();
	return errors;
}

#endif // WIN32_VSS

#if defined(HAVE_WIN32)

static int enable_priv(HANDLE hToken, const char *name, int ignore_errors)
{
    TOKEN_PRIVILEGES tkp;
    DWORD lerror;

    if (!(p_LookupPrivilegeValue && p_AdjustTokenPrivileges)) {
       return 0;                      /* not avail on this OS */
    }

    // Get the LUID for the security privilege.
    if (!p_LookupPrivilegeValue(NULL, name,  &tkp.Privileges[0].Luid)) {
	logp("LookupPrivilegeValue: %s\n", GetLastError());
       return 0;
    }

    /* Set the security privilege for this process. */
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    p_AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, NULL);
    lerror = GetLastError();
    if (lerror != ERROR_SUCCESS) {
       if (!ignore_errors) {
	  logp("AdjustTokenPrivileges set %s: %s\n", name, lerror);
       }
       return 0;
    }
    return 1;
}

/*
 * Setup privileges we think we will need.  We probably do not need
 *  the SE_SECURITY_NAME, but since nothing seems to be working,
 *  we get it hoping to fix the problems.
 */
int win32_enable_backup_privileges(int ignore_errors)
{
    HANDLE hToken, hProcess;
    int stat = 0;

    if (!p_OpenProcessToken) {
       return 0;                      /* No avail on this OS */
    }

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());

    // Get a token for this process.
    if (!p_OpenProcessToken(hProcess,
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
       if (!ignore_errors) {
          logp("OpenProcessToken: %s\n", GetLastError());
       }
       /* Forge on anyway */
    }

    /* Return a bit map of permissions set. */
    if (enable_priv(hToken, SE_BACKUP_NAME, ignore_errors)) {
       stat |= 1<<1;
    }
    if (enable_priv(hToken, SE_RESTORE_NAME, ignore_errors)) {
       stat |= 1<<2;
    }
#if 0
    if (enable_priv(hToken, SE_SECURITY_NAME, ignore_errors)) {
       stat |= 1<<0;
    }
    if (enable_priv(hToken, SE_TAKE_OWNERSHIP_NAME, ignore_errors)) {
       stat |= 1<<3;
    }
    if (enable_priv(hToken, SE_ASSIGNPRIMARYTOKEN_NAME, ignore_errors)) {
       stat |= 1<<4;
    }
    if (enable_priv(hToken, SE_SYSTEM_ENVIRONMENT_NAME, ignore_errors)) {
       stat |= 1<<5;
    }
    if (enable_priv(hToken, SE_CREATE_TOKEN_NAME, ignore_errors)) {
       stat |= 1<<6;
    }
    if (enable_priv(hToken, SE_MACHINE_ACCOUNT_NAME, ignore_errors)) {
       stat |= 1<<7;
    }
    if (enable_priv(hToken, SE_TCB_NAME, ignore_errors)) {
       stat |= 1<<8;
    }
    if (enable_priv(hToken, SE_CREATE_PERMANENT_NAME, ignore_errors)) {
       stat |= 1<<10;
    }
#endif
    if (stat) {
       stat |= 1<<9;
    }

    CloseHandle(hToken);
    CloseHandle(hProcess);
    return stat;
}

// This is the shape of the Windows VSS header structure.
// It is size 20. Using sizeof(struct bsid) seems to give 24, I guess due to
// some alignment issue.
struct bsid {
	int32_t dwStreamId;
	int32_t dwStreamAttributes;
	int64_t Size;
	int32_t dwStreamNameSize;
};
#define bsidsize	20

int get_vss(BFILE *bfd, const char *path, struct stat *statp, char **vssdata, size_t *vlen, int64_t winattr, struct cntr *cntr)
{
	bsid sid;
	char *tmp=NULL;
	*vlen=0;
	while(bread(bfd, &sid, bsidsize)>0)
	{
		int64_t s=0;
		int64_t g=0;

		if(!(tmp=(char *)realloc(tmp, (*vlen)+bsidsize)))
		{
			log_out_of_memory(__FUNCTION__);
			goto error;
		}
		memcpy(tmp+(*vlen), &sid, bsidsize);
		(*vlen)+=bsidsize;

		// dwStreamId==1 means start of backup data, so finish.
		if(sid.dwStreamId==1)
		{
		//	logp("\n%s: %d + %d\n",
		//		path, (int)sid.Size, (int)sid.dwStreamNameSize);
			break;
		}

		// Otherwise, need to read in the rest of the VSS header.
		s=(sid.Size)+(sid.dwStreamNameSize);
		if(!(tmp=(char *)realloc(tmp, (*vlen)+s)))
		{
			goto error;
			log_out_of_memory(__FUNCTION__);
			return -1;
		}
		if((g=bread(bfd, tmp+(*vlen), s))!=s)
		{
			logp("Short bread: %d!=%d\n", g, s);
			goto error;
			return -1;
		}
		(*vlen)+=s;
	}
	if(!(*vssdata=(char *)realloc(*vssdata, (*vlen)+9)))
	{
		log_out_of_memory(__FUNCTION__);
		goto error;
	}
	snprintf(*vssdata, 9, "%c%08X", META_VSS, *vlen);
	memcpy((*vssdata)+9, tmp, *vlen);
	(*vlen)+=9;
	return 0;
error:
	if(tmp) free(tmp);
	if(*vssdata)
	{
		free(*vssdata);
		*vssdata=NULL;
	}
	*vlen=0;
	return -1;
}

int set_vss(BFILE *bfd, const char *vssdata, size_t vlen, struct cntr *cntr)
{
	int ret=0;
	// Just need to write the VSS stuff to the file.
	if(!vlen || !vssdata) return 0;
	if((ret=bwrite(bfd, (void *)vssdata, vlen))<=0)
	{
		logp("error when writing %d VSS data: %d\n", vlen, ret);
		return -1;
	}
	return 0;
}

#endif  /* HAVE_WIN32 */
