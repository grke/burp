#ifndef __BFILE_H
#define __BFILE_H

enum bf_mode
{
	BF_CLOSED=0,
	BF_READ, /* BackupRead */
	BF_WRITE /* BackupWrite */
};

struct BFILE
{
	enum bf_mode mode;   /* set if file is open */
	uint64_t winattr;    /* needed for deciding to open with
				encrypted functions or not */
	struct stat statp;
	char *path;
	struct conf *conf;
	// Windows VSS headers tell us how much file data to expect.
	// Burp1 only for now.
	size_t datalen;
#ifdef HAVE_WIN32
	uint8_t use_backup_api; /* set if using BackupRead/Write */
	HANDLE fh;           /* Win32 file handle */
	LPVOID lpContext;    /* BackupRead/Write context */
	DWORD rw_bytes;      /* Bytes read or written */
	DWORD lerror;        /* Last error code */
	PVOID pvContext;     /* also for the encrypted functions */
	int berrno;          /* errno */
#else
	int fd;
#endif
};

extern BFILE *bfile_alloc(void);
extern void bfile_free(BFILE **bfd);
extern void bfile_init(BFILE *bfd, int64_t winattr, struct conf *conf);
extern int bfile_open(BFILE *bfd, struct asfd *asfd,
	const char *fname, int flags, mode_t mode);
extern int bfile_close(BFILE *bfd, struct asfd *asfd);
extern ssize_t bfile_read(BFILE *bfd, void *buf, size_t count);
extern ssize_t bfile_write(BFILE *bfd, void *buf, size_t count);
extern int bfile_open_for_send(BFILE *bfd, struct asfd *asfd,
	const char *fname, int64_t winattr, int atime, struct conf *conf);

#ifdef HAVE_WIN32
extern void bfile_set_win32_api(BFILE *bfd, int on);
extern int have_win32_api(void);
#endif

#endif
