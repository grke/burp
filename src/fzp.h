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
	FILE *fp;
	gzFile zp;
	enum fzp_type type;
};

extern struct fzp *fzp_open(const char *path, const char *mode);
extern struct fzp *fzp_gzopen(const char *path, const char *mode);
extern int fzp_close(struct fzp **fzp);

extern size_t fzp_read(struct fzp *fzp, void *ptr, size_t nmemb);
extern size_t fzp_write(struct fzp *fzp, void *ptr, size_t nmemb);
extern int fzp_eof(struct fzp *fzp);

#endif
