#ifndef _MANIO_H
#define _MANIO_H

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
	int sig_count;		// When writing, need to split the files
				// after every X signatures written.
	uint8_t legacy;		// Whether running in legacy mode or not.
};

extern struct manio *manio_alloc(void);
extern void manio_free(struct manio *manio);
extern int manio_close(struct manio *manio);
extern int manio_init_read(struct manio *manio, const char *directory);
extern int manio_init_write(struct manio *manio, const char *directory);
extern int manio_set_mode_read(struct manio *manio);
extern int manio_set_mode_write(struct manio *manio);
extern void manio_set_legacy(struct manio *manio);

extern int manio_sbuf_fill(struct manio *manio, struct sbuf *sb,
	struct blk *blk, struct dpth *dpth, struct config *conf);

extern int manio_write_sig(struct manio *manio, struct blk *blk);
extern int manio_write_sig_and_path(struct manio *manio, struct blk *blk);
extern int manio_write_sbuf(struct manio *manio, struct sbuf *sb);

#endif
