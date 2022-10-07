#include "../burp.h"
#include "../alloc.h"
#include "../berrno.h"
#include "../bfile.h"
#include "../cmd.h"
#include "../cntr.h"
#include "../log.h"
#include "../strlist.h"
#include "cvss.h"
#include "extrameta.h"

#if defined(WIN32_VSS)
#include "vss.h"

// Attempt to stop VSS nicely if the client is interrupted by the user.
BOOL CtrlHandler(DWORD fdwCtrlType)
{
	switch(fdwCtrlType)
	{
		// Handle the CTRL-C signal.
		case CTRL_C_EVENT:
		case CTRL_CLOSE_EVENT:
		case CTRL_BREAK_EVENT:
			win32_stop_vss();
			return FALSE;
		default:
			return FALSE;
	}
}

static int in_remote_drives(const char *remote_drives, char letter)
{
	int d;
	for(d=0; remote_drives && remote_drives[d]; d++) {
		if(toupper(letter)==toupper(remote_drives[d])) {
			return 1;
		}
	}
	return 0;
}

int get_use_winapi(const char *remote_drives, char letter)
{
	return !in_remote_drives(remote_drives, letter);
}

int win32_start_vss(struct asfd *asfd, struct conf **confs)
{
	int errors=0;
	struct cntr *cntr=get_cntr(confs);
	const char *drives_vss=get_string(confs[OPT_VSS_DRIVES]);
	const char *drives_remote=get_string(confs[OPT_REMOTE_DRIVES]);

	if(SetConsoleCtrlHandler((PHANDLER_ROUTINE) CtrlHandler, TRUE))
		logp("Control handler registered.\n");
	else
	{
		logw(asfd, cntr, "Could not register control handler.\n");
		errors++;
		return errors;
	}

	if(g_pVSSClient->InitializeForBackup(asfd, cntr))
	{
		char drive_letters[27];
		// Tell vss which drives to snapshot.
		if(drives_vss)
		{
			unsigned int i=0;
			for(i=0; i<strlen(drives_vss) && i<26; i++)
			  drive_letters[i]=toupper(drives_vss[i]);
			drive_letters[i]='\0';
		}
		else
		{
			// Not given anything specific. Figure out what to do
			// from the given starting directories.
			int j=0;
			struct strlist *s;
			for(s=get_strlist(confs[OPT_STARTDIR]), j=0;
				s && j<26; s=s->next)
			{
				const char *path=NULL;
				if(!s->flag) continue;
				path=s->path;
				if(strlen(path)>2
				  && isalpha(path[0]) && path[1]==':')
				{
					int x=0;
					char letter=toupper(path[0]);
					// Try not to add the same letter twice.
					for(x=0; x<j; x++)
					  if(letter==drive_letters[x])
						break;
					if(x<j) continue;

					if(in_remote_drives(
						drives_remote,
						letter
					)) continue;
					drive_letters[j++]=letter;
				}
			}
			drive_letters[j]='\0';
		}
		logp("Generate VSS snapshots.\n");
		logp("Driver=\"%s\", Drive(s)=\"%s\"\n",
			g_pVSSClient->GetDriverName(),
			drive_letters);
		if(!g_pVSSClient->CreateSnapshots(drive_letters))
		{
			berrno be;
			berrno_init(&be);
			logw(asfd, cntr,
				"Generate VSS snapshots failed.ERR=%s\n",
				berrno_bstrerror(&be, b_errno_win32));
			errors++;
		}
		else
		{
			int i;
			for(i=0; i<(int)strlen(drive_letters); i++)
			{
			  if(islower(drive_letters[i]))
			  {
				logw(asfd, cntr, "Generate VSS snapshot of drive \"%c:\\\" failed.\n", drive_letters[i]);
				errors++;
			  }
			}

			for(i=0; i<(int)g_pVSSClient->GetWriterCount(); i++)
			{
				if(g_pVSSClient->GetWriterState(i)<1)
				{
					logw(asfd, cntr,
						"Start GetWriterState(%d)<1\n", i);
					errors++;
				}
				logp("VSS Writer (PrepareForBackup): %s\n",
					g_pVSSClient->GetWriterInfo(i));
			}
		}
	}
	else
	{
		berrno be;
		berrno_init(&be);
		logw(asfd, cntr, "VSS was not initialized properly. ERR=%s",
			berrno_bstrerror(&be, b_errno_win32));
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
			{
				// Would be better to be a logw, but this gets
				// called by some weird handler thing above, so
				// it is hard to pass in asfd and cntr.
				logp("Stop GetWriterState(%d)<1\n", i);
				errors++;
			}
			logp("VSS Writer (BackupComplete): %s\n",
				g_pVSSClient->GetWriterInfo(i));
		}
	}
	Win32ConvCleanupCache();
	return errors;
}

#endif // WIN32_VSS

#if defined(HAVE_WIN32)

static int enable_priv(HANDLE hToken, const char *name)
{
	TOKEN_PRIVILEGES tkp;
	DWORD lerror;

	if(!(p_LookupPrivilegeValue && p_AdjustTokenPrivileges))
		return 0; /* not avail on this OS */

	// Get the LUID for the security privilege.
	if(!p_LookupPrivilegeValue(NULL, name, &tkp.Privileges[0].Luid))
	{
		logp("LookupPrivilegeValue: %lu\n",
			(unsigned long)GetLastError());
		return 0;
	}

	/* Set the security privilege for this process. */
	tkp.PrivilegeCount=1;
	tkp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
	p_AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, NULL);
	lerror=GetLastError();
	if(lerror==ERROR_SUCCESS) return 0;
	logp("Could not set privilege %s\n", name);
	return 1;
}

/*
 * Setup privileges we think we will need.  We probably do not need
 *  the SE_SECURITY_NAME, but since nothing seems to be working,
 *  we get it hoping to fix the problems.
 */
int win32_enable_backup_privileges()
{
	int ret=0;
	HANDLE hToken;
	HANDLE hProcess;

	if(!p_OpenProcessToken) return 0; /* No avail on this OS */

	hProcess=OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());

	// Get a token for this process.
	if(!p_OpenProcessToken(hProcess,
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		logp("Could not OpenProcessToken\n");
		/* Forge on anyway */
	}

	if(enable_priv(hToken, SE_BACKUP_NAME)) ret=-1;
	if(enable_priv(hToken, SE_RESTORE_NAME)) ret=-1;
	if(enable_priv(hToken, SE_SECURITY_NAME)) ret=-1;
/*
	enable_priv(hToken, SE_TAKE_OWNERSHIP_NAME);
	enable_priv(hToken, SE_ASSIGNPRIMARYTOKEN_NAME);
	enable_priv(hToken, SE_SYSTEM_ENVIRONMENT_NAME);
	enable_priv(hToken, SE_CREATE_TOKEN_NAME);
	enable_priv(hToken, SE_MACHINE_ACCOUNT_NAME);
	enable_priv(hToken, SE_TCB_NAME);
	enable_priv(hToken, SE_CREATE_PERMANENT_NAME);
*/

	CloseHandle(hToken);
	CloseHandle(hProcess);

	if(ret)
	{
		logp("Some privileges were not enabled.\n\n");
		logp("Are you running as Administrator?\n\n");
	}
	return ret;
}

static int ensure_read(BFILE *bfd, char *buf, size_t s, int print_err)
{
	ssize_t got=0;
	size_t offset=0;
	while((got=bfd->read(bfd, buf+offset, s-offset))>0)
	{
		offset+=got;
		if(offset>=s) break;
	}
	if(offset!=s)
	{
		if(print_err)
			logp("Error in read - got %lu, wanted %lu\n",
				(unsigned long)offset,
				(unsigned long)s);
		return -1;
	}
	return 0;
}

int get_vss(BFILE *bfd, char **vssdata, size_t *vlen)
{
	bsid sid;
	char *tmp=NULL;
	*vlen=0;
	while(!ensure_read(bfd, (char *)&sid, bsidsize, 0))
	{
		int64_t s=0;

		if(!(tmp=(char *)realloc_w(tmp, (*vlen)+bsidsize, __func__)))
			goto error;
		memcpy(tmp+(*vlen), &sid, bsidsize);
		(*vlen)+=bsidsize;

		// dwStreamId==1 means start of backup data, so finish.
		if(sid.dwStreamId==1)
		{
		//	logp("\n%s: %d + %d\n",
		//		path, (int)sid.Size, (int)sid.dwStreamNameSize);
			bfd->datalen=sid.Size;
			break;
		}

		// Otherwise, need to read in the rest of the VSS header.
		s=(sid.Size)+(sid.dwStreamNameSize);
		if(!(tmp=(char *)realloc_w(tmp, (*vlen)+s, __func__))
		  || ensure_read(bfd, tmp+(*vlen), s, 1))
		{
			goto error;
			return -1;
		}
		(*vlen)+=s;
	}
	if(!(*vssdata=(char *)realloc_w(*vssdata, (*vlen)+9, __func__)))
		goto error;
	snprintf(*vssdata, 9, "%c%08X", META_VSS, (unsigned int)*vlen);
	memcpy((*vssdata)+9, tmp, *vlen);
	(*vlen)+=9;
	free_w(&tmp);
	return 0;
error:
	free_w(&tmp);
	free_w(vssdata);
	*vlen=0;
	return -1;
}

static int ensure_write(BFILE *bfd, const char *buf, size_t got)
{
	size_t wrote=0;
	while((wrote=bfd->write(bfd, (void *)buf, got))>0)
	{
		got-=wrote;
		if(got<=0) return 0;
	}
	logp("error when writing VSS data\n");
	return -1;
}

int set_vss(BFILE *bfd, const char *vssdata, size_t vlen)
{
	// Just need to write the VSS stuff to the file.
	if(!vlen || !vssdata) return 0;
	return ensure_write(bfd, vssdata, vlen);
}

#endif  /* HAVE_WIN32 */
