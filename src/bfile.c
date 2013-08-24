#include "burp.h"
#include "prog.h"
#include "find.h"
#include "berrno.h"
#include "log.h"
#include "bfile.h"
#include "attribs.h"

#ifdef HAVE_DARWIN_OS
#include <sys/paths.h>
#endif

#ifdef HAVE_WIN32

char *unix_name_to_win32(char *name);
extern "C" HANDLE get_osfhandle(int fd);

/*
 * Enables using the Backup API (win32_data).
 *   Returns 1 if function worked
 *   Returns 0 if failed (i.e. do not have Backup API on this machine)
 */
bool set_win32_backup(BFILE *bfd)
{
	/* We enable if possible here */
	bfd->use_backup_api=have_win32_api();
	return bfd->use_backup_api;
}

bool have_win32_api()
{
	return p_BackupRead && p_BackupWrite;
}

// Windows flags for the OpenEncryptedFileRaw functions
#define CREATE_FOR_EXPORT	0
// These are already defined
//#define CREATE_FOR_IMPORT	1
//#define CREATE_FOR_DIR	2
//#define OVERWRITE_HIDDEN	4

static int bopen_encrypted(BFILE *bfd, const char *fname, int flags, mode_t mode)
{
	int ret=0;
	ULONG ulFlags=0;
	char *win32_fname=NULL;
	char *win32_fname_wchar=NULL;

	if(!(p_OpenEncryptedFileRawA || p_OpenEncryptedFileRawW))
	{
		logp("no OpenEncryptedFileRaw pointers.\n");
		return 0;
	}
	if(p_OpenEncryptedFileRawW && p_MultiByteToWideChar)
	{
		if(!(win32_fname_wchar=make_win32_path_UTF8_2_wchar_w(fname)))
			logp("could not get widename!");
	}
	if(!(win32_fname=unix_name_to_win32((char *)fname)))
		return 0;

	if((flags & O_CREAT) /* Create */
	  || (flags & O_WRONLY)) /* Open existing for write */
	{
		ulFlags |= CREATE_FOR_IMPORT;
		ulFlags |= OVERWRITE_HIDDEN;
		if(bfd->winattr & FILE_ATTRIBUTE_DIRECTORY)
		{
			mkdir(fname, 0777);
			ulFlags |= CREATE_FOR_DIR;
		}
	}
	else
	{
		/* Open existing for read */
		ulFlags=CREATE_FOR_EXPORT;
	}

	if(p_OpenEncryptedFileRawW && p_MultiByteToWideChar)
	{
        	// unicode open
		ret=p_OpenEncryptedFileRawW((LPCWSTR)win32_fname_wchar,
			ulFlags, &(bfd->pvContext));
		if(ret) bfd->mode=BF_CLOSED;
		else bfd->mode=BF_READ;
		goto end;
	}
	else
	{
		// ascii open
		ret=p_OpenEncryptedFileRawA(win32_fname,
			ulFlags, &(bfd->pvContext));
		if(ret) bfd->mode=BF_CLOSED;
		else bfd->mode=BF_READ;
		goto end;
	}

end:
   	if(win32_fname_wchar) free(win32_fname_wchar);
   	if(win32_fname) free(win32_fname);
	return bfd->mode==BF_CLOSED?-1:1;
}

static int bfile_error(BFILE *bfd)
{
	if(bfd)
	{
		bfd->lerror=GetLastError();
		bfd->berrno=b_errno_win32;
	}
	errno=b_errno_win32;
	return -1;
}

int bopen(BFILE *bfd, const char *fname, int flags, mode_t mode)
{
	DWORD dwaccess;
	DWORD dwflags;
	DWORD dwshare;
	char *win32_fname=NULL;
	char *win32_fname_wchar=NULL;

	if(bfd->winattr & FILE_ATTRIBUTE_ENCRYPTED)
		return bopen_encrypted(bfd, fname, flags, mode);

	if(!(p_CreateFileA || p_CreateFileW)) return 0;

	if(!(win32_fname=unix_name_to_win32((char *)fname))) return 0;

	if(p_CreateFileW && p_MultiByteToWideChar
	  && !(win32_fname_wchar=make_win32_path_UTF8_2_wchar_w(fname)))
		logp("could not get widename!");

	if(flags & O_CREAT)
	{
		/* Create */

		if(bfd->winattr & FILE_ATTRIBUTE_DIRECTORY)
			mkdir(fname, 0777);

		if(bfd->use_backup_api)
		{
			dwaccess=GENERIC_WRITE
				| FILE_ALL_ACCESS
				| WRITE_OWNER
				| WRITE_DAC
				| ACCESS_SYSTEM_SECURITY;
			dwflags=FILE_FLAG_BACKUP_SEMANTICS;
		}
		else
		{
			dwaccess=GENERIC_WRITE;
			dwflags=0;
		}

		if(p_CreateFileW && p_MultiByteToWideChar)
			// unicode open for create write
			bfd->fh=p_CreateFileW((LPCWSTR)win32_fname_wchar,
				dwaccess,      /* Requested access */
				0,             /* Shared mode */
				NULL,          /* SecurityAttributes */
				CREATE_ALWAYS, /* CreationDisposition */
				dwflags,       /* Flags and attributes */
				NULL);         /* TemplateFile */
		else
			// ascii open
			bfd->fh=p_CreateFileA(win32_fname,
				dwaccess,      /* Requested access */
				0,             /* Shared mode */
				NULL,          /* SecurityAttributes */
				CREATE_ALWAYS, /* CreationDisposition */
				dwflags,       /* Flags and attributes */
				NULL);         /* TemplateFile */

		bfd->mode=BF_WRITE;
	}
	else if(flags & O_WRONLY)
	{
		/* Open existing for write */
		if(bfd->use_backup_api)
		{
			dwaccess=GENERIC_WRITE
				| WRITE_OWNER
				| WRITE_DAC;
			dwflags=FILE_FLAG_BACKUP_SEMANTICS
				| FILE_FLAG_OPEN_REPARSE_POINT;
		}
		else
		{
			dwaccess=GENERIC_WRITE;
			dwflags=0;
		}

		if(p_CreateFileW && p_MultiByteToWideChar)
			// unicode open for open existing write
			bfd->fh=p_CreateFileW((LPCWSTR)win32_fname_wchar,
				dwaccess,      /* Requested access */
				0,             /* Shared mode */
				NULL,          /* SecurityAttributes */
				OPEN_EXISTING, /* CreationDisposition */
				dwflags,       /* Flags and attributes */
				NULL);         /* TemplateFile */
		else
			// ascii open
			bfd->fh=p_CreateFileA(win32_fname,
				dwaccess,      /* Requested access */
				0,             /* Shared mode */
				NULL,          /* SecurityAttributes */
				OPEN_EXISTING, /* CreationDisposition */
				dwflags,       /* Flags and attributes */
				NULL);         /* TemplateFile */

		bfd->mode=BF_WRITE;

	}
	else
	{
		/* Read */
		if(bfd->use_backup_api)
		{
			dwaccess=GENERIC_READ|READ_CONTROL
				| ACCESS_SYSTEM_SECURITY;
			dwflags=FILE_FLAG_BACKUP_SEMANTICS
				| FILE_FLAG_SEQUENTIAL_SCAN
				| FILE_FLAG_OPEN_REPARSE_POINT;
			dwshare=FILE_SHARE_READ
				| FILE_SHARE_WRITE
				| FILE_SHARE_DELETE;
		}
		else
		{
			dwaccess=GENERIC_READ;
			dwflags=0;
			dwshare=FILE_SHARE_READ
				| FILE_SHARE_WRITE;
		}

		if(p_CreateFileW && p_MultiByteToWideChar)
			// unicode open for open existing read
			bfd->fh=p_CreateFileW((LPCWSTR)win32_fname_wchar,
				dwaccess,      /* Requested access */
				dwshare,       /* Share modes */
				NULL,          /* SecurityAttributes */
				OPEN_EXISTING, /* CreationDisposition */
				dwflags,       /* Flags and attributes */
				NULL);         /* TemplateFile */
		else
			// ascii open 
			bfd->fh=p_CreateFileA(win32_fname,
				dwaccess,      /* Requested access */
				dwshare,       /* Share modes */
				NULL,          /* SecurityAttributes */
				OPEN_EXISTING, /* CreationDisposition */
				dwflags,       /* Flags and attributes */
				NULL);         /* TemplateFile */
		bfd->mode=BF_READ;
	}

	if(bfd->fh==INVALID_HANDLE_VALUE)
	{
		bfile_error(bfd);
		bfd->mode=BF_CLOSED;
	}
	else
	{
		if(!(bfd->path=strdup(fname)))
		{
			log_out_of_memory(__FUNCTION__);
			return -1;
		}
	}
	bfd->lpContext=NULL;
	if(win32_fname_wchar) free(win32_fname_wchar);
	if(win32_fname) free(win32_fname);
	return bfd->mode==BF_CLOSED?-1:1;
}

static int bclose_encrypted(BFILE *bfd)
{
	CloseEncryptedFileRaw(bfd->pvContext);
	if(bfd->mode==BF_WRITE)
		attribs_set(bfd->path, &bfd->statp, bfd->winattr, bfd->conf);
	bfd->pvContext=NULL;
	bfd->mode=BF_CLOSED;
	if(bfd->path)
	{
		free(bfd->path);
		bfd->path=NULL;
	}
	return 0;
}

// Return 0 on success, -1 on error.
int bclose(BFILE *bfd)
{
	int ret=-1;

	if(!bfd) return 0;

	if(bfd->mode==BF_CLOSED) return 0;

	if(bfd->winattr & FILE_ATTRIBUTE_ENCRYPTED)
		return bclose_encrypted(bfd, conf);

	/*
	 * We need to tell the API to release the buffer it
	 * allocated in lpContext.  We do so by calling the
	 * API one more time, but with the Abort bit set.
	 */
	if(bfd->use_backup_api && bfd->mode==BF_READ)
	{
		BYTE buf[10];
		if(bfd->lpContext
		  && !p_BackupRead(bfd->fh,
			buf,              /* buffer */
			(DWORD)0,         /* bytes to read */
			&bfd->rw_bytes,   /* bytes read */
			1,                /* Abort */
			1,                /* ProcessSecurity */
			&bfd->lpContext)) /* Read context */
		{
			bfile_error(NULL);
			goto end;
		}
	}
	else if(bfd->use_backup_api && bfd->mode==BF_WRITE)
	{
		BYTE buf[10];
		if(bfd->lpContext
		  && !p_BackupWrite(bfd->fh,
			buf,              /* buffer */
			(DWORD)0,         /* bytes to read */
			&bfd->rw_bytes,   /* bytes written */
			1,                /* Abort */
			1,                /* ProcessSecurity */
			&bfd->lpContext)) /* Write context */
		{
			bfile_error(NULL);
			goto end;
		}
	}
	if(!CloseHandle(bfd->fh))
	{
		bfile_error(NULL);
		goto end;
	}

	if(bfd->mode==BF_WRITE)
		attribs_set(bfd->path, &bfd->statp, bfd->winattr, bfd->conf);
	bfd->lpContext=NULL;
	bfd->mode=BF_CLOSED;

	ret=0;
end:
	if(bfd->path)
	{
		free(bfd->path);
		bfd->path=NULL;
	}
	return ret;
}

// Returns: bytes read on success, or 0 on EOF, -1 on error.
ssize_t bread(BFILE *bfd, void *buf, size_t count)
{
	bfd->rw_bytes=0;

	if(bfd->use_backup_api)
	{
		if(!p_BackupRead(bfd->fh,
			(BYTE *)buf,
			count,
			&bfd->rw_bytes,
			0,                /* no Abort */
			1,                /* Process Security */
			&bfd->lpContext)) /* Context */
				return bfile_error(bfd);
	}
	else
	{
		if(!ReadFile(bfd->fh,
			buf,
			count,
			&bfd->rw_bytes,
			NULL))
				return bfile_error(bfd);
	}

	return (ssize_t)bfd->rw_bytes;
}

ssize_t bwrite(BFILE *bfd, void *buf, size_t count)
{
	bfd->rw_bytes = 0;

	if(bfd->use_backup_api)
	{
		if(!p_BackupWrite(bfd->fh,
			(BYTE *)buf,
			count,
			&bfd->rw_bytes,
			0,                /* No abort */
			1,                /* Process Security */
			&bfd->lpContext)) /* Context */
				return bfile_error(bfd);
	}
	else
	{
		if(!WriteFile(bfd->fh,
			buf,
			count,
			&bfd->rw_bytes,
			NULL))
				return bfile_error(bfd);
	}
	return (ssize_t)bfd->rw_bytes;
}

#else

int bclose(BFILE *bfd)
{
	if(!bfd || bfd->mode==BF_CLOSED) return 0;

	if(!close(bfd->fd))
	{
		if(bfd->mode==BF_WRITE)
			attribs_set(bfd->path,
				&bfd->statp, bfd->winattr, bfd->conf);
		bfd->mode=BF_CLOSED;
		bfd->fd=-1;
		if(bfd->path)
		{
			free(bfd->path);
			bfd->path=NULL;
		}
		return 0;
	}
	if(bfd->path)
	{
		free(bfd->path);
		bfd->path=NULL;
	}
	return -1;
}

int bopen(BFILE *bfd, const char *fname, int flags, mode_t mode)
{
	if(bfd->mode!=BF_CLOSED && bclose(bfd))
		return -1;
	if(!(bfd->fd=open(fname, flags, mode))<0)
		return -1;
	if(flags & O_CREAT || flags & O_WRONLY)
		bfd->mode=BF_WRITE;
	else
		bfd->mode=BF_READ;
	if(!(bfd->path=strdup(fname)))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	return 0;
}

ssize_t bread(BFILE *bfd, void *buf, size_t count)
{
	return read(bfd->fd, buf, count);
}

ssize_t bwrite(BFILE *bfd, void *buf, size_t count)
{
	return write(bfd->fd, buf, count);
}

#endif

void binit(BFILE *bfd, int64_t winattr, struct config *conf)
{
	memset(bfd, 0, sizeof(BFILE));
	bfd->mode=BF_CLOSED;
	bfd->winattr=winattr;
	bfd->conf=conf;
#ifdef HAVE_WIN32
	bfd->use_backup_api=have_win32_api();
#else
	bfd->fd=-1;
#endif
}
