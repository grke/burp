#ifndef __BFILE_H
#define __BFILE_H

/*  =======================================================
 *
 *   W I N D O W S
 *
 *  =======================================================
 */
#ifdef HAVE_WIN32

enum {
   BF_CLOSED=0,
   BF_READ,                           /* BackupRead */
   BF_WRITE                           /* BackupWrite */
};

// Basic Win32 low level I/O file packet.
struct BFILE {
   bool use_backup_api;               /* set if using BackupRead/Write */
   int mode;                          /* set if file is open */
   HANDLE fh;                         /* Win32 file handle */
   LPVOID lpContext;                  /* BackupRead/Write context */
   char *errmsg;                      /* error message buffer */
   DWORD rw_bytes;                    /* Bytes read or written */
   DWORD lerror;                      /* Last error code */
   int berrno;                        /* errno */
   bool reparse_point;                /* set if reparse point */ 
   int64_t winattr;                   /* needed for deciding to open with
					 encrypted functions or not */
   PVOID pvContext;                   /* also for the encrypted functions */
   char *path;
};

#else

// Only exists to make code have fewer #ifdefs
struct BFILE {
};

#endif

void    binit(BFILE *bfd, int64_t winattr);
bool    set_win32_backup(BFILE *bfd);
bool    have_win32_api();
int     bopen(BFILE *bfd, const char *fname, int flags, mode_t mode, int isdir);
int     bclose(BFILE *bfd);
ssize_t bread(BFILE *bfd, void *buf, size_t count);
ssize_t bwrite(BFILE *bfd, void *buf, size_t count);

#endif /* __BFILE_H */
