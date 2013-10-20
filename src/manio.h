#ifndef _MANIO_H
#define _MANIO_H

#include <stdint.h>
#include <zlib.h>

// Manifests are split up into several files in a directory.
// This is for manipulating them.
// 'manio' means 'manifest I/O'

struct manio
{
	gzFile zp;		// File pointer.
	char *directory;	// Directory containing the files.
	uint64_t fcount;	// File name incrementer.
	char *fpath;		// Current file path.
	char *mode;		// Mode with which to open the files.
};

extern struct manio *manio_alloc(void);
extern void manio_free(struct manio *manio);
extern int manio_init_read(struct manio *manio, const char *directory);
extern int manio_init_write(struct manio *manio, const char *directory);

extern int manio_sbuf_fill(struct manio *manio, struct sbuf *sb, struct blk *blk, struct dpth *dpth, struct config *conf);

#endif
