#ifndef __BFILE_H
#define __BFILE_H

#include "burp.h"
#include "conf.h"

struct asfd;

enum bf_mode
{
	BF_CLOSED=0,
	BF_READ, /* BackupRead */
	BF_WRITE /* BackupWrite */
};

struct mysid
{
        struct bsid sid;
        size_t needed_s;
        size_t needed_d;
};

struct BFILE
{
	enum bf_mode mode;   /* set if file is open */
	uint64_t winattr;    /* needed for deciding to open with
				encrypted functions or not */
	struct stat statp;
	char *path;
	struct cntr *cntr;
	// Windows VSS headers tell us how much file data to expect.
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
	struct mysid mysid;
	int vss_strip;
	int set_attribs_on_close;

	// Let us try using function pointers.
	int (*open)(struct BFILE *bfd, struct asfd *asfd,
		const char *fname, int flags, mode_t mode);
	int (*close)(struct BFILE *bfd, struct asfd *asfd);
	ssize_t (*read)(struct BFILE *bfd, void *buf, size_t count);
	ssize_t (*write)(struct BFILE *bfd, void *buf, size_t count);
	int (*open_for_send)(
		struct BFILE *bfd,
		struct asfd *asfd,
		const char *fname,
		int use_backup_api,
		int64_t winattr,
		int atime,
		struct cntr *cntr
	);
#ifdef HAVE_WIN32
	void (*set_win32_api)(struct BFILE *bfd, int on);
#endif
	void (*set_vss_strip)(struct BFILE *bfd, int on);
};

extern struct BFILE *bfile_alloc(void);
extern void bfile_free(struct BFILE **bfd);
// FIX THIS: should be possible to have this as a function pointer too.
// Need to sort out the bfd in sbuf.
extern void bfile_init(
	struct BFILE *bfd,
	int use_backup_api,
	int64_t winattr,
	struct cntr *cntr
);
extern void bfile_setup_funcs(struct BFILE *bfd);

#ifdef HAVE_WIN32
extern int have_win32_api(void);
#endif

#endif
