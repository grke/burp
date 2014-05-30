#ifndef _SBUF_H
#define _SBUF_H

#include <sys/stat.h>
#include <zlib.h>

#include "bfile.h"
#include "burp1/sbuf_burp1.h"
#include "burp2/sbuf_burp2.h"

// Bits in sbuf flags.
// Keep track of what has been sent.
#define SBUF_SENT_STAT			0x01
#define SBUF_SENT_PATH			0x02
#define SBUF_SENT_LINK			0x04
// Keep track of what needs to be received.
#define SBUF_NEED_LINK			0x10
#define SBUF_NEED_DATA			0x20
#define SBUF_HEADER_WRITTEN_TO_MANIFEST	0x40

typedef struct sbuf sbuf_t;

struct sbuf
{
	struct iobuf path; // File data.
	struct iobuf link; // Link data.
	struct iobuf attr; // Attribute data.

	struct stat statp;
	uint64_t winattr;
	int32_t compression;

	uint8_t flags;

	// These maybe should be a single pointer that is casted.
	struct burp1 *burp1;
	struct burp2 *burp2;

	struct sbuf *next;
};

extern struct sbuf *sbuf_alloc(struct conf *conf);
extern void sbuf_free_content(struct sbuf *sb);
extern void sbuf_free(struct sbuf **sb);

extern int sbuf_open_file(struct sbuf *sb,
	struct asfd *asfd, struct conf *conf);
extern void sbuf_close_file(struct sbuf *sb, struct asfd *asfd);
extern ssize_t sbuf_read(struct sbuf *sb, char *buf, size_t bufsize);

extern int sbuf_is_filedata(struct sbuf *sb);
extern int sbuf_is_link(struct sbuf *sb);
extern int sbuf_to_manifest(struct sbuf *sb, gzFile zp);

extern int sbuf_pathcmp(struct sbuf *a, struct sbuf *b);

extern void sbuf_print_alloc_stats(void);

extern int sbuf_fill(struct sbuf *sb, struct asfd *asfd,
	gzFile zp, struct blk *blk,
	char *datpath, struct conf *conf);
extern int sbuf_fill_from_gzfile(struct sbuf *sb, struct asfd *asfd,
	gzFile zp, struct blk *blk, char *datpath, struct conf *conf);
extern int sbuf_fill_from_net(struct sbuf *sb, struct asfd *asfd,
	struct blk *blk, struct conf *conf);

#endif
