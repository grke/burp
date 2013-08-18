#ifndef __BFILE_H
#define __BFILE_H

#ifdef HAVE_WIN32

enum bf_mode
{
	BF_CLOSED=0,
	BF_READ, /* BackupRead */
	BF_WRITE /* BackupWrite */
};

struct BFILE
{
	enum bf_mode mode;   /* set if file is open */
	char *errmsg;        /* error message buffer */
	int64_t winattr;     /* needed for deciding to open with
				encrypted functions or not */
	char *path;
	bool use_backup_api; /* set if using BackupRead/Write */
	HANDLE fh;           /* Win32 file handle */
	LPVOID lpContext;    /* BackupRead/Write context */
	DWORD rw_bytes;      /* Bytes read or written */
	DWORD lerror;        /* Last error code */
	PVOID pvContext;     /* also for the encrypted functions */
	bool reparse_point;  /* set if reparse point */ 
	int berrno;          /* errno */
};

void    binit(BFILE *bfd, int64_t winattr);
int     bopen(BFILE *bfd, const char *fname, int flags, mode_t mode, int isdir);
int     bclose(BFILE *bfd);
ssize_t bread(BFILE *bfd, void *buf, size_t count);
ssize_t bwrite(BFILE *bfd, void *buf, size_t count);

bool    set_win32_backup(BFILE *bfd);
bool    have_win32_api();

#else

struct BFILE
{
};

#endif

#endif /* __BFILE_H */
