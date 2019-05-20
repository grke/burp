#ifndef _MANIO_H
#define _MANIO_H

#include "../burp.h"
#include "../conf.h"
#include "sdirs.h"

#define MANIO_MODE_READ		"rb"
#define MANIO_MODE_WRITE	"wb"
#define MANIO_MODE_APPEND	"ab"

struct blk;
struct sbuf;

struct man_off
{
	uint64_t fcount;	// File name incrementer.
	char *fpath;		// Current file path.
	char *ppath;		// Previous file path.
	off_t offset;		// Offset into the file.
};

typedef struct man_off man_off_t;

// Manifests are split up into several files in a directory.
// This is for manipulating them.
// 'manio' means 'manifest I/O'

struct manio
{
	struct fzp *fzp;	// File pointer.
	char *manifest;
	char *mode;		// Mode with which to open the files.
	int sig_count;		// When writing, need to split the files
				// after every X signatures written.
	char *hook_dir;
	uint64_t *hook_sort;	// Array for sorting and writing hooks.
	int hook_count;
	char *rmanifest;	// When renaming the manifest to its final
				// location, hooks need to be written using the
				// final destination. This is for that
				// circumstance.
	char *dindex_dir;
	uint64_t *dindex_sort;	// Array for sorting and writing dindex.
	int dindex_count;
	enum protocol protocol;	// Whether running in protocol1/2 mode.
	int phase;

	man_off_t *offset;
};

extern struct manio *manio_open(const char *manifest, const char *mode,
	enum protocol protocol);
extern struct manio *manio_open_phase1(const char *manifest, const char *mode,
	enum protocol protocol);
extern struct manio *manio_open_phase2(const char *manifest, const char *mode,
	enum protocol protocol);
extern struct manio *manio_open_phase3(const char *manifest, const char *mode,
	enum protocol protocol, const char *rmanifest);
extern int manio_close(struct manio **manio);

extern int manio_read_fcount(struct manio *manio);

extern int manio_read_with_blk(struct manio *manio,
	struct sbuf *sb, struct blk *blk);
extern int manio_read(struct manio *manio, struct sbuf *sb);

extern int manio_write_sig_and_path(struct manio *manio, struct blk *blk);
extern int manio_write_sbuf(struct manio *manio, struct sbuf *sb);

extern int manio_copy_entry(struct sbuf *csb, struct sbuf *sb,
	struct manio *srcmanio, struct manio *dstmanio,
	const char *seed_src, const char *seed_dst);
extern int manio_forward_through_sigs(struct sbuf *csb, struct manio *manio);

extern void man_off_t_free(man_off_t **offset);
extern man_off_t *manio_tell(struct manio *manio);
extern int manio_seek(struct manio *manio, man_off_t *offset);
extern int manio_close_and_truncate(struct manio **manio,
	man_off_t *offset, int compression);

#ifdef UTEST
extern int write_hook_header(struct fzp *fzp, const char *rmanifest,
        const char *msg);
extern int manio_find_boundary(uint8_t *md5sum);
#endif

#endif
