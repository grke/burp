#ifndef SBUF_H
#define SBUF_H

#include <sys/stat.h>
#include <zlib.h>
#include "bfile.h"
#include "blk.h"

// Keep track of what has been sent.
#define SBUF_SENT_STAT			0x01
#define SBUF_SENT_PATH			0x02
#define SBUF_SENT_LINK			0x04
// Keep track of what needs to be received.
#define SBUF_NEED_PATH			0x08
#define SBUF_NEED_LINK			0x10
#define SBUF_NEED_DATA			0x20
#define SBUF_HEADER_WRITTEN_TO_MANIFEST	0x40
#define SBUF_UNUSED			0x80

typedef struct sbuf sbuf_t;

struct sbuf
{
	// FIX THIS: path/link/attr/statp/winattr/compression/flags is the same
	// in struct sbufl. Should be able to put them all a separate struct
	// that buf sbuf and sbufl share.
	struct iobuf path; // File data.
	struct iobuf link; // Link data.
	struct iobuf attr; // Attribute data.

	struct stat statp;
	uint64_t winattr;
	int compression;

	uint8_t flags;

	ssize_t bytes_read;

	uint64_t index;

	BFILE bfd;

	struct blk *bstart;
	struct blk *bend;
	struct blk *bsighead;

	struct sbuf *next;
};

struct slist
{
	struct sbuf *head;
	struct sbuf *tail;
	struct sbuf *last_requested; // last file requested
	struct sbuf *add_sigs_here; // server only
	struct sbuf *blks_to_request; // server only
	struct sbuf *blks_to_send; // client only
};

extern struct sbuf *sbuf_alloc(void);
extern void sbuf_free_contents(struct sbuf *sb);
extern void sbuf_free(struct sbuf *sb);

extern struct slist *slist_alloc(void);
extern void slist_free(struct slist *slist);

extern int sbuf_attribs_encode(struct sbuf *sb, struct config *conf);
extern void sbuf_attribs_decode(struct sbuf *sb, struct config *conf);

extern int sbuf_open_file(struct sbuf *sb, struct config *conf);
extern void sbuf_close_file(struct sbuf *sb);
extern ssize_t sbuf_read(struct sbuf *sb, char *buf, size_t bufsize);

extern int cmd_is_link(char cmd);
extern int sbuf_is_link(struct sbuf *sb);
extern int sbuf_to_manifest(struct sbuf *sb, gzFile zp);
extern void sbuf_add_to_list(struct sbuf *sb, struct slist *slist);

extern int sbuf_pathcmp(struct sbuf *a, struct sbuf *b);

extern void sbuf_print_alloc_stats(void);

extern int sbuf_fill(struct sbuf *sb, gzFile zp, struct blk *blk,
	char *datpath, struct config *conf);
extern int sbuf_fill_from_gzfile(struct sbuf *sb, gzFile zp, struct blk *blk,
	char *datpath, struct config *conf);
extern int sbuf_fill_from_net(struct sbuf *sb, struct blk *blk,
	struct config *conf);

#endif
