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
};

extern struct fzp *fzp_open(const char *path, const char *mode);
extern struct fzp *fzp_gzopen(const char *path, const char *mode);
extern int fzp_close(struct fzp **fzp);

extern size_t fzp_read(struct fzp *fzp, void *ptr, size_t nmemb);
extern size_t fzp_write(struct fzp *fzp, const void *ptr, size_t nmemb);
extern int fzp_eof(struct fzp *fzp);
extern int fzp_flush(struct fzp *fzp);

extern int fzp_seek(struct fzp *fzp, off_t offset, int whence);
extern off_t fzp_tell(struct fzp *fzp);

extern int fzp_printf(struct fzp *fzp, const char *format, ...);

#endif
