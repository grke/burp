#ifndef __BFILE_H
#define __BFILE_H

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>

enum bf_mode
{
	BF_CLOSED=0,
	BF_READ, /* BackupRead */
	BF_WRITE /* BackupWrite */
};

struct BFILE
{
	enum bf_mode mode;   /* set if file is open */
	uint64_t winattr;     /* needed for deciding to open with
				encrypted functions or not */
	struct stat statp;
	char *path;
	struct config *conf;
#ifdef HAVE_WIN32
	bool use_backup_api; /* set if using BackupRead/Write */
	HANDLE fh;           /* Win32 file handle */
	LPVOID lpContext;    /* BackupRead/Write context */
	DWORD rw_bytes;      /* Bytes read or written */
	DWORD lerror;        /* Last error code */
	PVOID pvContext;     /* also for the encrypted functions */
	bool reparse_point;  /* set if reparse point */ 
	int berrno;          /* errno */
#else
	int fd;
#endif
};

void    binit(BFILE *bfd, int64_t winattr, struct config *conf);
int     bopen(BFILE *bfd, const char *fname, int flags, mode_t mode);
int     bclose(BFILE *bfd);
ssize_t bread(BFILE *bfd, void *buf, size_t count);
ssize_t bwrite(BFILE *bfd, void *buf, size_t count);

#ifdef HAVE_WIN32
bool    set_win32_backup(BFILE *bfd);
bool    have_win32_api();
#endif

#endif /* __BFILE_H */
