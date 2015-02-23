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
	// Protocol1 only for now.
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

	// Let us try using function pointers.
	int (*open)(BFILE *bfd, struct asfd *asfd,
		const char *fname, int flags, mode_t mode);
	int (*close)(BFILE *bfd, struct asfd *asfd);
	ssize_t (*read)(BFILE *bfd, void *buf, size_t count);
	ssize_t (*write)(BFILE *bfd, void *buf, size_t count);
	int (*open_for_send)(BFILE *bfd, struct asfd *asfd,
		const char *fname, int64_t winattr,
		int atime, struct conf *conf);
#ifdef HAVE_WIN32
	void (*set_win32_api)(BFILE *bfd, int on);
#endif
};

extern BFILE *bfile_alloc(void);
extern void bfile_free(BFILE **bfd);
// FIX THIS: should be possible to have this as a function pointer too.
// Need to sort out the bfd in sbuf.
extern void bfile_init(BFILE *bfd, int64_t winattr, struct conf *conf);
extern void bfile_setup_funcs(BFILE *bfd);

#ifdef HAVE_WIN32
extern int have_win32_api(void);
#endif

#endif
