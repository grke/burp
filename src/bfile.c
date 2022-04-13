#include "burp.h"
#include "alloc.h"
#include "attribs.h"
#include "berrno.h"
#include "bfile.h"
#include "log.h"

#ifdef HAVE_DARWIN_OS
#include <sys/paths.h>
#endif

void bfile_free(struct BFILE **bfd)
{
	free_v((void **)bfd);
}

#ifdef HAVE_WIN32
static ssize_t bfile_write_windows(struct BFILE *bfd, void *buf, size_t count);
#endif

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

static void setup_vss_strip(struct BFILE *bfd)
{
	memset(&bfd->mysid, 0, sizeof(struct mysid));
	bfd->mysid.needed_s=bsidsize;
}

static ssize_t bfile_write_vss_strip(struct BFILE *bfd, void *buf, size_t count)
{
	size_t mycount;
	struct mysid *mysid;
	struct bsid *sid;

	mysid=&bfd->mysid;
	sid=&mysid->sid;
	char *cp=(char *)buf;
	mycount=count;

	while(mycount)
	{
		if(mysid->needed_s)
		{
			size_t sidlen=bsidsize-mysid->needed_s;
			int got=min(mysid->needed_s, mycount);

			memcpy(sid+sidlen, cp, got);

			cp+=got;
			mycount-=got;
			mysid->needed_s-=got;

			if(!mysid->needed_s)
				mysid->needed_d=sid->Size+sid->dwStreamNameSize;
		}
		if(mysid->needed_d)
		{
			size_t wrote;
			int got=min(mysid->needed_d, mycount);

			if(sid->dwStreamId==1)
			{
#ifdef HAVE_WIN32
				if((wrote=bfile_write_windows(bfd,
					cp, got))<=0)
						return -1;
#else
				if((wrote=write(bfd->fd,
					cp, got))<=0)
						return -1;
#endif
			}
			else
				wrote=got;

			cp+=wrote;
			mycount-=wrote;
			mysid->needed_d-=wrote;
			if(!mysid->needed_d)
				mysid->needed_s=bsidsize;
		}
	}

	return count;
}

#ifdef HAVE_WIN32

extern "C" HANDLE get_osfhandle(int fd);

static void bfile_set_win32_api(struct BFILE *bfd, int on)
{
	if(have_win32_api() && on)
		bfd->use_backup_api=1;
	else
		bfd->use_backup_api=0;
}

int have_win32_api(void)
{
	return p_BackupRead && p_BackupWrite;
}

// Windows flags for the OpenEncryptedFileRaw functions
#define CREATE_FOR_EXPORT	0
// These are already defined
//#define CREATE_FOR_IMPORT	1
//#define CREATE_FOR_DIR	2
//#define OVERWRITE_HIDDEN	4

// Return 0 for success, non zero for error.
static int bfile_open_encrypted(struct BFILE *bfd,
	const char *fname, int flags, mode_t mode)
{
	ULONG ulFlags=0;
	char *win32_fname_wchar=NULL;

	bfd->mode=BF_CLOSED;
	if(!(win32_fname_wchar=make_win32_path_UTF8_2_wchar_w(fname)))
	{
		logp("could not get widename!");
		goto end;
	}

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

	if(p_OpenEncryptedFileRawW((LPCWSTR)win32_fname_wchar,
		ulFlags, &(bfd->pvContext)))
			bfd->mode=BF_CLOSED;
	else
		bfd->mode=BF_READ;

end:
	free_w(&win32_fname_wchar);
	return bfd->mode==BF_CLOSED;
}

static int bfile_error(struct BFILE *bfd)
{
	if(bfd)
	{
		bfd->lerror=GetLastError();
		bfd->berrno=b_errno_win32;
	}
	errno=b_errno_win32;
	return -1;
}

// Return 0 for success, non zero for error.
static int bfile_open(struct BFILE *bfd, struct asfd *asfd,
	const char *fname, int flags, mode_t mode)
{
	DWORD dwaccess;
	DWORD dwflags;
	DWORD dwshare;
	char *win32_fname_wchar=NULL;

	bfd->mode=BF_CLOSED;

	if(bfd->winattr & FILE_ATTRIBUTE_ENCRYPTED)
		return bfile_open_encrypted(bfd, fname, flags, mode);

	if(!(win32_fname_wchar=make_win32_path_UTF8_2_wchar_w(fname)))
	{
		logp("could not get widename!");
		goto end;
	}

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

		// unicode open for create write
		bfd->fh=p_CreateFileW((LPCWSTR)win32_fname_wchar,
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

		// unicode open for open existing write
		bfd->fh=p_CreateFileW((LPCWSTR)win32_fname_wchar,
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

		// unicode open for open existing read
		bfd->fh=p_CreateFileW((LPCWSTR)win32_fname_wchar,
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
		free_w(&bfd->path);
		if(!(bfd->path=strdup_w(fname, __func__)))
			goto end;
	}
end:
	bfd->lpContext=NULL;
	free_w(&win32_fname_wchar);

	if(bfd->vss_strip)
		setup_vss_strip(bfd);

	return bfd->mode==BF_CLOSED;
}

static int bfile_close_encrypted(struct BFILE *bfd, struct asfd *asfd)
{
	CloseEncryptedFileRaw(bfd->pvContext);
	if(bfd->mode==BF_WRITE && bfd->set_attribs_on_close)
		attribs_set(asfd,
			bfd->path, &bfd->statp, bfd->winattr, bfd->cntr);
	bfd->pvContext=NULL;
	bfd->mode=BF_CLOSED;
	free_w(&bfd->path);
	return 0;
}

// Return 0 on success, -1 on error.
static int bfile_close(struct BFILE *bfd, struct asfd *asfd)
{
	int ret=-1;

	if(!bfd) return 0;

	if(bfd->mode==BF_CLOSED)
	{
		ret=0;
		goto end;
	}

	if(bfd->winattr & FILE_ATTRIBUTE_ENCRYPTED)
		return bfile_close_encrypted(bfd, asfd);

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

	if(bfd->mode==BF_WRITE && bfd->set_attribs_on_close)
		attribs_set(asfd,
			bfd->path, &bfd->statp, bfd->winattr, bfd->cntr);
	bfd->lpContext=NULL;
	bfd->mode=BF_CLOSED;

	ret=0;
end:
	free_w(&bfd->path);
	return ret;
}

// Returns: bytes read on success, or 0 on EOF, -1 on error.
static ssize_t bfile_read(struct BFILE *bfd, void *buf, size_t count)
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

static ssize_t bfile_write_windows(struct BFILE *bfd, void *buf, size_t count)
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

static ssize_t bfile_write(struct BFILE *bfd, void *buf, size_t count)
{
	if(bfd->vss_strip)
		return bfile_write_vss_strip(bfd, buf, count);
	return bfile_write_windows(bfd, buf, count);
}

#else

static int bfile_close(struct BFILE *bfd, struct asfd *asfd)
{
	if(!bfd || bfd->mode==BF_CLOSED) return 0;

	if(!close(bfd->fd))
	{
		if(bfd->mode==BF_WRITE && bfd->set_attribs_on_close)
			attribs_set(asfd, bfd->path,
				&bfd->statp, bfd->winattr, bfd->cntr);
		bfd->mode=BF_CLOSED;
		bfd->fd=-1;
		free_w(&bfd->path);
		return 0;
	}
	free_w(&bfd->path);
	return -1;
}

static int bfile_open(struct BFILE *bfd,
	struct asfd *asfd, const char *fname, int flags, mode_t mode)
{
	if(!bfd) return 0;
	if(bfd->mode!=BF_CLOSED && bfd->close(bfd, asfd))
		return -1;
	if((bfd->fd=open(fname, flags, mode))<0)
		return -1;
	if(flags & O_CREAT || flags & O_WRONLY)
		bfd->mode=BF_WRITE;
	else
		bfd->mode=BF_READ;
	free_w(&bfd->path);
	if(!(bfd->path=strdup_w(fname, __func__)))
		return -1;
	if(bfd->vss_strip)
		setup_vss_strip(bfd);
	return 0;
}

static ssize_t bfile_read(struct BFILE *bfd, void *buf, size_t count)
{
	return read(bfd->fd, buf, count);
}

static ssize_t bfile_write(struct BFILE *bfd, void *buf, size_t count)
{
	if(bfd->vss_strip)
		return bfile_write_vss_strip(bfd, buf, count);

	return write(bfd->fd, buf, count);
}

#endif

static int bfile_open_for_send(struct BFILE *bfd, struct asfd *asfd,
	const char *fname, int64_t winattr, int atime,
	struct cntr *cntr)
{
	if(bfd->mode!=BF_CLOSED)
	{
#ifdef HAVE_WIN32
		if(bfd->path && !strcmp(bfd->path, fname))
		{
			// Already open after reading the VSS data.
			// Time now for the actual file data.
			return 0;
		}
		else
		{
#endif
			// Close the open bfd so that it can be
			// used again
			bfd->close(bfd, asfd);
#ifdef HAVE_WIN32
		}
#endif
	}

	bfile_init(bfd, winattr, cntr);
	if(bfile_open(bfd, asfd, fname, O_RDONLY|O_BINARY
#ifdef O_NOFOLLOW
		|O_NOFOLLOW
#endif
#ifdef O_NOATIME
		|(atime?0:O_NOATIME)
#endif
		, 0))
	{
		struct berrno be;
		berrno_init(&be);
		logw(asfd, cntr,
			"Could not open %s: %s\n",
			fname, berrno_bstrerror(&be, errno));
		return -1;
	}
	return 0;
}

static void bfile_set_vss_strip(struct BFILE *bfd, int on)
{
	bfd->vss_strip=on;
}

void bfile_setup_funcs(struct BFILE *bfd)
{
	bfd->open=bfile_open;
	bfd->close=bfile_close;
	bfd->read=bfile_read;
	bfd->write=bfile_write;
	bfd->open_for_send=bfile_open_for_send;
#ifdef HAVE_WIN32
	bfd->set_win32_api=bfile_set_win32_api;
#endif
	bfd->set_vss_strip=bfile_set_vss_strip;
}

void bfile_init(struct BFILE *bfd, int64_t winattr, struct cntr *cntr)
{
	memset(bfd, 0, sizeof(struct BFILE));
	bfd->mode=BF_CLOSED;
	bfd->winattr=winattr;
	bfd->cntr=cntr;
	if(!bfd->open) bfile_setup_funcs(bfd);
#ifdef HAVE_WIN32
	bfile_set_win32_api(bfd, 1);
#else
	bfd->fd=-1;
#endif
}

struct BFILE *bfile_alloc(void)
{
	return (struct BFILE *)calloc_w(1, sizeof(struct BFILE), __func__);
}
