#ifndef _FZP_H
#define _FZP_H

#include <zlib.h>

enum fzp_type
{
	FZP_FILE=0,
	FZP_COMPRESSED
};

struct fzp
{
	enum fzp_type type;
	union
	{
		FILE *fp;
		gzFile zp;
	};
	char *buf;
	size_t s;
};

extern struct fzp *fzp_open(const char *path, const char *mode);
extern struct fzp *fzp_gzopen(const char *path, const char *mode);
extern int fzp_close(struct fzp **fzp);

extern int fzp_read(struct fzp *fzp, void *ptr, size_t nmemb);
extern size_t fzp_write(struct fzp *fzp, const void *ptr, size_t nmemb);
extern int fzp_eof(struct fzp *fzp);
extern int fzp_flush(struct fzp *fzp);

extern int fzp_seek(struct fzp *fzp, off_t offset, int whence);
extern off_t fzp_tell(struct fzp *fzp);

#ifndef HAVE_WIN32
extern int fzp_truncate(const char *path, enum fzp_type type, off_t length,
	int compression);
#endif

extern int fzp_printf(struct fzp *fzp, const char *format, ...);

extern void fzp_setlinebuf(struct fzp *fzp);

extern char *fzp_gets(struct fzp *fzp, char *s, int size);
extern int fzp_fileno(struct fzp *fzp);

extern struct fzp *fzp_dopen(int fd, const char *mode);
extern struct fzp *fzp_gzdopen(int fd, const char *mode);

extern void fzp_ERR_print_errors_fp(struct fzp *fzp);
extern X509 *fzp_PEM_read_X509(struct fzp *fzp);

extern int fzp_read_ensure(struct fzp *fzp, void *ptr, size_t nmemb,
	const char *func);

#endif
